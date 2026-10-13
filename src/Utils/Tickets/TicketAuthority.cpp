#include "TicketAuthority.h"

#include "Hook/Hooks_Decryption.h"
#include "OSTPlatform/include/SteamCredentialStore.h"
#include "Steam/Enums.h"
#include "Steam/Structs.h"
#include "Utils/Config/Config.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Logging/Log.h"
#include "Utils/Tickets/AppTicket.h"
#include "Utils/Tickets/EticketClient.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace TicketAuthority {
namespace {

    // The Steam client's own app id. A logged-in account always keeps a cached
    // ticket for it, which makes it the last-resort base - never the first one.
    constexpr AppId_t kClientAppId = 7;

    enum class BaseKind : uint8
    {
        ConfigStore,      // Local ConfigStore key apptickets\<appid>
        CredentialStore,  // HKCU\Software\Valve\Steam\Apps\<appid>\AppTicket
        Vault,            // our own copy of signed material that worked before
    };

    struct BaseRef
    {
        BaseKind kind = BaseKind::ConfigStore;
        AppId_t  appId = 0;
    };

    // Session notes about ticket material handed over by the config/redeem
    // paths. Lua re-runs on every Steam start, so in-memory is enough - and it
    // lets the authority warn about incomplete imports before any launch.
    struct ImportNote
    {
        bool   hasAppTicket = false;
        uint64 appTicketSteamId = 0;
        uint32 appTicketEmbeddedApp = 0;  // 0 when the blob is too short to say
        bool   hasETicket = false;
    };

    struct Entry
    {
        Decision   decision;
        Identity   identity;
        bool       hasETicket = false;   // pool eticket present for this app
    };

    std::mutex g_mutex;
    std::unordered_map<AppId_t, Entry> g_entries;
    std::unordered_map<AppId_t, ImportNote> g_imports;
    std::optional<BaseRef> g_lastGoodBase;   // base that already worked this session

    // -- helpers --------------------------------------------------------------

    // -- private ticket vault -------------------------------------------------
    // Our own copy of signed material that once worked, under
    // <Steam>/opensteamtool/vault. Steam clearing its caches, an update wiping
    // ConfigStore, or a reinstall cannot empty the machine while this exists -
    // it is what makes the "no material left" case recoverable, and it is a
    // mechanism no other tool in this family has.

    std::filesystem::path VaultDir()
    {
        const std::string dir = Config::GetLogDir();
        if (dir.empty()) return {};
        return std::filesystem::path(dir) / "vault";
    }

    bool VaultLoad(AppId_t appId, std::vector<uint8_t>& out)
    {
        out.clear();
        const std::filesystem::path dir = VaultDir();
        if (dir.empty()) return false;
        std::ifstream in(dir / (std::to_string(appId) + ".bin"), std::ios::binary);
        if (!in) return false;
        out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        return !out.empty();
    }

    void VaultSave(AppId_t appId, const std::vector<uint8_t>& blob, uint64 owner, const char* kind)
    {
        if (appId == 0 || !AppTicket::IsUsableForgeSourceTicket(blob)) return;
        const std::filesystem::path dir = VaultDir();
        if (dir.empty()) return;

        std::error_code ec;
        std::filesystem::create_directories(dir, ec);

        std::ofstream out(dir / (std::to_string(appId) + ".bin"), std::ios::binary | std::ios::trunc);
        if (!out) return;
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
        out.close();

        // Sidecar for humans and support: which account the blob belongs to and
        // where it came from (the blob itself still carries the SteamID).
        std::ofstream meta(dir / (std::to_string(appId) + ".txt"), std::ios::trunc);
        if (meta) meta << "owner=" << owner << "\nkind=" << (kind ? kind : "") << "\n";
    }

    void VaultList(std::vector<AppId_t>& out)
    {
        const std::filesystem::path dir = VaultDir();
        if (dir.empty()) return;

        std::error_code ec;
        for (std::filesystem::directory_iterator it(dir, ec), end; it != end && !ec; it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            const std::string name = it->path().filename().string();
            if (name.size() < 5 || name.compare(name.size() - 4, 4, ".bin") != 0) continue;

            AppId_t appId = 0;
            bool valid = true;
            for (size_t i = 0; i + 4 < name.size(); ++i) {
                const char c = name[i];
                if (!std::isdigit(static_cast<unsigned char>(c))) { valid = false; break; }
                appId = appId * 10 + static_cast<AppId_t>(c - '0');
            }
            if (valid && appId != 0) out.push_back(appId);
        }
    }

    // -- helpers --------------------------------------------------------------

    bool ReadBase(BaseKind kind, AppId_t appId, std::vector<uint8_t>& out)
    {
        if (kind == BaseKind::ConfigStore) {
            out = Hooks_Decryption::GetCacheAppOwnershipTicket(appId);
        } else if (kind == BaseKind::Vault) {
            VaultLoad(appId, out);
        } else {
            out.clear();
            if (OSTPlatform::SteamCredentialStore::GetAppTicket(appId, out)
                != OSTPlatform::SteamCredentialStore::Status::Ok) {
                out.clear();
            }
        }
        return !out.empty();
    }

    uint32 EmbeddedAppId(const std::vector<uint8_t>& blob)
    {
        if (blob.size() < AppTicket::kAppTicketAppIdOffset + sizeof(uint32)) return 0;
        return *reinterpret_cast<const uint32*>(blob.data() + AppTicket::kAppTicketAppIdOffset);
    }

    // VDF strings escape backslashes; undo that for path values.
    std::string UnescapeVdfPath(const std::string& in)
    {
        std::string out;
        out.reserve(in.size());
        for (size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '\\' && i + 1 < in.size()) out += in[++i];
            else                                     out += in[i];
        }
        return out;
    }

    // App ids this machine actually has installed: steamapps/appmanifest_<id>.acf
    // for the Steam root and every library folder listed in libraryfolders.vdf.
    // These are the user's own (normally owned) apps, so their cached tickets
    // are the most natural forge bases - which is why they are discovered here
    // instead of a fixed app id list being compiled into the DLL.
    void CollectInstalledAppIds(const std::filesystem::path& steamRoot, std::vector<AppId_t>& out)
    {
        namespace fs = std::filesystem;
        std::error_code ec;

        std::vector<fs::path> libraries;
        auto addLibrary = [&](const fs::path& root) {
            if (root.empty()) return;
            for (const fs::path& existing : libraries) if (existing == root) return;
            libraries.push_back(root);
        };
        addLibrary(steamRoot);

        if (std::ifstream vdf(steamRoot / "steamapps" / "libraryfolders.vdf"); vdf) {
            std::string line;
            while (std::getline(vdf, line)) {
                const size_t key = line.find("\"path\"");
                if (key == std::string::npos) continue;
                const size_t first = line.find('"', key + 6);
                if (first == std::string::npos) continue;
                const size_t second = line.find('"', first + 1);
                if (second == std::string::npos || second <= first + 1) continue;
                addLibrary(UnescapeVdfPath(line.substr(first + 1, second - first - 1)));
            }
        }

        constexpr const char* kManifestPrefix = "appmanifest_";
        constexpr size_t kManifestPrefixLen = 12;  // strlen(kManifestPrefix)
        for (const fs::path& library : libraries) {
            const fs::path steamapps = library / "steamapps";
            if (!fs::exists(steamapps, ec)) continue;

            for (fs::directory_iterator it(steamapps, ec), end; it != end && !ec; it.increment(ec)) {
                if (!it->is_regular_file(ec)) continue;
                const std::string name = it->path().filename().string();
                if (name.rfind(kManifestPrefix, 0) != 0) continue;
                if (it->path().extension() != ".acf") continue;

                const std::string digits =
                    name.substr(kManifestPrefixLen, name.size() - kManifestPrefixLen - 4);
                if (digits.empty()) continue;

                AppId_t appId = 0;
                bool valid = true;
                for (char c : digits) {
                    if (!std::isdigit(static_cast<unsigned char>(c))) { valid = false; break; }
                    appId = appId * 10 + static_cast<AppId_t>(c - '0');
                }
                if (valid && appId != 0) out.push_back(appId);
            }
        }
    }

    // SteamID64 of the signed-in account, or 0 when it cannot be determined.
    uint64 ActiveAccountSteamId()
    {
        uint32 accountId = 0;
        std::wstring universeName;
        if (OSTPlatform::SteamCredentialStore::GetActiveUser(accountId, universeName)
            != OSTPlatform::SteamCredentialStore::Status::Ok || accountId == 0) {
            return 0;
        }

        EUniverse universe = k_EUniverseInvalid;
        if (universeName == L"Public")        universe = k_EUniversePublic;
        else if (universeName == L"Beta")     universe = k_EUniverseBeta;
        else if (universeName == L"Internal") universe = k_EUniverseInternal;
        else if (universeName == L"Dev")      universe = k_EUniverseDev;
        if (universe == k_EUniverseInvalid) return 0;

        CSteamID steamId;
        steamId.Set(accountId, universe, k_EAccountTypeIndividual);
        return steamId.ConvertToUint64();
    }

    bool StoreHasETicket(AppId_t appId)
    {
        return !AppTicket::GetEncryptedTicketFromCredentialStore(appId).empty();
    }

    // The account the DRM will check everything against, derived from local
    // material in priority order: validated stored ticket -> stored SteamID
    // credential -> this session's import notes -> ETicket (account unknown).
    Identity DeriveIdentityLocked(AppId_t appId)
    {
        Identity identity;
        const uint64 local = ActiveAccountSteamId();

        std::vector<uint8_t> stored = AppTicket::GetAppOwnershipTicketFromCredentialStore(appId);
        if (!stored.empty() && AppTicket::IsUsableForgeSourceTicket(stored)) {
            const uint64 id = AppTicket::ExtractSteamIdFromTicketBytes(stored);
            if (id != 0) {
                identity.known   = true;
                identity.steamId = id;
                identity.foreign = (local == 0 || id != local);
                identity.source  = "stored_appticket";
                return identity;
            }
        }

        uint64 storedSteamId = 0;
        if (OSTPlatform::SteamCredentialStore::GetSteamId(appId, storedSteamId)
                == OSTPlatform::SteamCredentialStore::Status::Ok && storedSteamId != 0) {
            identity.known   = true;
            identity.steamId = storedSteamId;
            identity.foreign = (local == 0 || storedSteamId != local);
            identity.source  = "stored_steamid";
            return identity;
        }

        if (auto it = g_imports.find(appId); it != g_imports.end()) {
            const ImportNote& note = it->second;
            if (note.hasAppTicket && note.appTicketSteamId != 0) {
                identity.known   = true;
                identity.steamId = note.appTicketSteamId;
                identity.foreign = (local == 0 || note.appTicketSteamId != local);
                identity.source  = "imported_appticket";
                return identity;
            }
            if (note.hasETicket) {
                identity.foreign = true;
                identity.known   = false;
                identity.source  = "imported_eticket";
                return identity;
            }
        }

        if (StoreHasETicket(appId)) {
            identity.foreign = true;
            identity.known   = false;
            identity.source  = "stored_eticket";
            return identity;
        }

        identity.known   = (local != 0);
        identity.steamId = local;
        identity.source  = "signed_in_account";
        return identity;
    }

    // -- report helpers -------------------------------------------------------

    std::string JsonEscape(const std::string& in)
    {
        std::string out;
        out.reserve(in.size() + 8);
        for (char c : in) {
            switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += c;
                }
            }
        }
        return out;
    }

    std::string TimestampUtc()
    {
        const std::time_t now = std::time(nullptr);
        std::tm tm{};
        gmtime_s(&tm, &now);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buf;
    }

    // User-provided base hints ([tickets].sources). Empty in normal setups:
    // forge bases are discovered, not configured.
    void AppendSourceList(std::ostringstream& os, const Config::TicketPolicy& policy)
    {
        os << '[';
        for (size_t i = 0; i < policy.sources.size(); ++i) {
            if (i) os << ',';
            os << policy.sources[i];
        }
        os << ']';
    }

    std::string BuildReportLocked(const Config::TicketPolicy& policy)
    {
        std::ostringstream os;
        os << "{\n";
        os << "  \"generated\": \"" << TimestampUtc() << "\",\n";

        os << "  \"policy\": {\n";
        os << "    \"prefer_stored\": "        << (policy.preferStored ? "true" : "false") << ",\n";
        os << "    \"allow_forge\": "          << (policy.allowForge ? "true" : "false") << ",\n";
        os << "    \"require_appid_match\": "  << (policy.requireAppIdMatch ? "true" : "false") << ",\n";
        os << "    \"require_account_match\": " << (policy.requireAccountMatch ? "true" : "false") << ",\n";
        os << "    \"scan_credential_store\": " << (policy.scanCredentialStore ? "true" : "false") << ",\n";
        os << "    \"identity_mode\": \"" << (policy.allowMixedIdentity ? "best_effort" : "strict") << "\",\n";
        os << "    \"vault\": "               << (policy.vault ? "true" : "false") << ",\n";
        os << "    \"allow_backend\": "        << (policy.allowBackend ? "true" : "false") << ",\n";
        os << "    \"sources\": ";
        AppendSourceList(os, policy);
        os << ",\n    \"base_discovery\": true\n  },\n";

        uint32 evaluated = 0, stored = 0, forged = 0, unserved = 0;
        for (const auto& [appId, entry] : g_entries) {
            (void)appId;
            ++evaluated;
            if (!entry.decision.servable) ++unserved;
            else if (entry.decision.provenance == Provenance::Stored) ++stored;
            else ++forged;
        }
        os << "  \"summary\": { \"evaluated\": " << evaluated
           << ", \"served_stored\": " << stored
           << ", \"served_forge\": " << forged
           << ", \"unserved\": " << unserved << " },\n";

        os << "  \"apps\": [\n";
        size_t index = 0;
        for (const auto& [appId, entry] : g_entries) {
            const Decision& d = entry.decision;
            os << "    { \"appid\": " << appId
               << ", \"servable\": " << (d.servable ? "true" : "false")
               << ", \"provenance\": \"" << ToString(d.provenance) << "\""
               << ", \"identity_pool\": " << (entry.identity.foreign ? "true" : "false")
               << ", \"identity_known\": " << (entry.identity.known ? "true" : "false")
               << ", \"identity_steamid\": " << entry.identity.steamId
               << ", \"identity_source\": \"" << JsonEscape(entry.identity.source) << "\""
               << ", \"mixed_identity\": " << (d.mixedIdentity ? "true" : "false")
               << ", \"source_app\": " << d.sourceApp
               << ", \"owner_steamid\": " << d.ownerSteamId
               << ", \"has_eticket\": " << (entry.hasETicket ? "true" : "false")
               << ", \"bytes\": " << d.bytes.size()
               << ", \"reason\": \"" << JsonEscape(d.reason) << "\" }";
            if (++index < g_entries.size()) os << ',';
            os << "\n";
        }
        os << "  ]\n}\n";
        return os.str();
    }

    void FlushReport(const std::string& json)
    {
        const std::string dir = Config::GetLogDir();
        if (dir.empty()) return;

        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        std::ofstream out(std::filesystem::path(dir) / "tickets.json", std::ios::trunc);
        if (!out) return;
        out << json;
    }

    // -- the evaluation itself ------------------------------------------------

    Entry EvaluateLocked(AppId_t appId, const Config::TicketPolicy& policy)
    {
        Entry entry;
        Decision& d = entry.decision;
        d.appIdOffset   = AppTicket::kAppTicketAppIdOffset;
        d.steamIdOffset = AppTicket::kAppTicketSteamIdOffset;
        d.signatureSize = AppTicket::kAppTicketSignatureSize;

        entry.identity   = DeriveIdentityLocked(appId);
        entry.hasETicket = StoreHasETicket(appId)
                           || (g_imports.count(appId) && g_imports[appId].hasETicket);
        d.identity = entry.identity;

        if (!LuaConfig::HasDepot(appId)) {
            d.reason = "app id is not managed by Lua (addappid)";
            return entry;
        }

        // 1) Stored bytes. This is the only source that carries an account's
        //    identity directly, so it is preferred whenever it validates. Our
        //    own vault is consulted too - it survives Steam cache clears.
        std::vector<uint8_t> storedRaw;   // validation failures kept for a last-resort rung
        if (policy.preferStored) {
            bool fromVault = false;
            std::vector<uint8_t> stored = AppTicket::GetAppOwnershipTicketFromCredentialStore(appId);
            if (stored.empty()) {
                fromVault = VaultLoad(appId, stored);
            }
            if (!stored.empty()) {
                const uint32 embedded = EmbeddedAppId(stored);
                if (!AppTicket::IsUsableForgeSourceTicket(stored)) {
                    LOG_TICKET_WARN("AppId {}: stored ticket is malformed ({} bytes); it will only be served if nothing else exists",
                                    appId, stored.size());
                    storedRaw = std::move(stored);
                } else if (policy.requireAppIdMatch && embedded != appId) {
                    LOG_TICKET_WARN("AppId {}: stored ticket embeds AppId {} (stale/foreign); it will only be served if nothing else exists",
                                    appId, embedded);
                    storedRaw = std::move(stored);
                } else {
                    d.servable         = true;
                    d.provenance       = fromVault ? Provenance::StoredVault : Provenance::Stored;
                    d.ownerSteamId     = AppTicket::ExtractSteamIdFromTicketBytes(stored);
                    d.totalSize        = static_cast<uint32>(stored.size());
                    d.signatureOffset  = *reinterpret_cast<const uint32*>(stored.data());
                    d.bytes            = std::move(stored);
                    d.reason           = fromVault ? "validated stored ticket (private vault)"
                                                   : "validated stored ticket";
                    if (policy.vault) VaultSave(appId, d.bytes, d.ownerSteamId, "stored");
                    return entry;
                }
            }
        }

        if (!policy.allowForge) {
            d.reason = "no validated stored ticket and forging is disabled ([tickets].allow_forge)";
            return entry;
        }

        // Identity policy: "strict" refuses answers whose bytes describe a
        // different account than the expected identity. "best-effort" (default)
        // prefers matching bases but still serves the best available bytes,
        // recording the mixing - an empty answer guarantees the launch failure
        // while a mixed one may still pass, so falling back can only help.
        const bool strict = policy.requireAccountMatch && !policy.allowMixedIdentity;
        const uint64 localSteamId = strict ? ActiveAccountSteamId() : 0;

        if (strict && entry.identity.foreign && !entry.identity.known) {
            d.reason = "pool ticket material present but its account is unknown; import "
                       "setAppTicket from the same source (extract_tickets on the owning "
                       "account) or re-redeem (or set [tickets] identity_mode = \"best_effort\")";
            return entry;
        }

        auto baseMatchesIdentity = [&](uint64 baseSteamId) -> bool {
            if (entry.identity.foreign) {
                return entry.identity.steamId != 0 && baseSteamId == entry.identity.steamId;
            }
            // Local identity: an unknown-account base is acceptable as before,
            // a known one must be the signed-in account.
            return baseSteamId == 0 || localSteamId == 0 || baseSteamId == localSteamId;
        };

        auto tryBase = [&](BaseKind kind, AppId_t baseApp, Provenance fromProvider, bool requireMatch) -> bool {
            if (baseApp == 0 || baseApp == appId) return false;   // a blob cannot forge itself

            std::vector<uint8_t> base;
            if (!ReadBase(kind, baseApp, base)) return false;
            if (!AppTicket::IsUsableForgeSourceTicket(base)) return false;

            const uint64 baseSteamId = AppTicket::ExtractSteamIdFromTicketBytes(base);
            if (requireMatch && !baseMatchesIdentity(baseSteamId)) {
                LOG_TICKET_DEBUG("AppId {}: base AppId {} (account {}) does not match the expected identity, skipping",
                                 appId, baseApp, baseSteamId);
                return false;
            }

            std::vector<uint8_t> forged = AppTicket::ForgeFromSource(appId, base);
            if (forged.empty()) return false;

            d.servable        = true;
            d.provenance      = fromProvider;
            d.sourceApp       = baseApp;
            d.ownerSteamId    = baseSteamId;
            d.bytes           = std::move(forged);
            d.totalSize       = static_cast<uint32>(d.bytes.size() - sizeof(AppId_t));
            d.appIdOffset     = d.totalSize - AppTicket::kAppTicketSignatureSize;
            d.steamIdOffset   = AppTicket::kAppTicketSteamIdOffset;
            d.signatureOffset = d.appIdOffset + sizeof(AppId_t);
            d.signatureSize   = AppTicket::kAppTicketSignatureSize;

            const bool matchesExpected = entry.identity.known && entry.identity.steamId != 0 &&
                                         baseSteamId == entry.identity.steamId;
            d.mixedIdentity = entry.identity.foreign && !matchesExpected;

            if (policy.vault) VaultSave(baseApp, base, baseSteamId, "base");
            return true;
        };

        // 2a) The base that already worked earlier in this session.
        if (g_lastGoodBase.has_value()
            && tryBase(g_lastGoodBase->kind, g_lastGoodBase->appId, Provenance::ForgeFromCache, false)) {
            d.reason = "forged from base that already worked this session";
            return entry;
        }

        // 2b) Base providers, in preference order. There is deliberately no
        //     fixed app id list in the DLL - candidates are discovered:
        //     vault -> hints -> Lua-managed -> installed apps -> per-app
        //     credentials (both storage kinds) -> the Steam client's own
        //     ticket (last local).
        struct Candidate {
            BaseKind    kind;
            AppId_t     appId;
            int         rank;
            Provenance  provider;
            const char* providerName;
        };
        std::vector<Candidate> candidates;
        auto addCandidate = [&](BaseKind kind, AppId_t app, int rank,
                                Provenance provider, const char* providerName) {
            if (app == 0 || app == appId) return;
            for (const Candidate& existing : candidates)
                if (existing.kind == kind && existing.appId == app) return;
            candidates.push_back(Candidate{ kind, app, rank, provider, providerName });
        };

        {
            std::vector<AppId_t> vaultIds;
            VaultList(vaultIds);
            for (AppId_t app : vaultIds)
                addCandidate(BaseKind::Vault, app, 0, Provenance::ForgeFromVault, "vault");
        }

        for (AppId_t hint : policy.sources)
            addCandidate(BaseKind::ConfigStore, hint, 1, Provenance::ForgeFromHint, "hint");

        {
            // App ids this Lua setup manages: the games actually played here,
            // so their cached tickets are strong candidates. Bounded so a huge
            // depot list cannot stall the decision.
            constexpr size_t kMaxLuaCandidates = 128;
            const std::vector<AppId_t> managed = LuaConfig::GetAllDepotIds();
            size_t added = 0;
            for (AppId_t app : managed) {
                if (added >= kMaxLuaCandidates) break;
                addCandidate(BaseKind::ConfigStore, app, 2, Provenance::ForgeFromLua, "lua");
                ++added;
            }
        }

        const std::string logDir = Config::GetLogDir();
        if (!logDir.empty()) {
            std::vector<AppId_t> installed;
            CollectInstalledAppIds(std::filesystem::path(logDir).parent_path(), installed);
            for (AppId_t app : installed)
                addCandidate(BaseKind::ConfigStore, app, 3, Provenance::ForgeFromInstalled, "installed");
        }

        if (policy.scanCredentialStore) {
            std::vector<uint32_t> credentials;
            if (OSTPlatform::SteamCredentialStore::EnumerateAppIds(credentials)
                == OSTPlatform::SteamCredentialStore::Status::Ok) {
                for (uint32_t credential : credentials) {
                    const AppId_t app = static_cast<AppId_t>(credential);
                    // Union probing: an id discovered here is tried in BOTH
                    // storage locations, so a ConfigStore-only blob (Steam's
                    // own cache) is found even without a registry credential.
                    addCandidate(BaseKind::CredentialStore, app, 4, Provenance::ForgeFromRegistry, "credential");
                    addCandidate(BaseKind::ConfigStore, app, 4, Provenance::ForgeFromRegistry, "credential");
                }
            }
        }

        addCandidate(BaseKind::ConfigStore, kClientAppId, 5, Provenance::ForgeFromClient, "client");
        addCandidate(BaseKind::CredentialStore, kClientAppId, 5, Provenance::ForgeFromClient, "client");
        addCandidate(BaseKind::Vault, kClientAppId, 5, Provenance::ForgeFromClient, "client");

        std::stable_sort(candidates.begin(), candidates.end(),
                         [](const Candidate& a, const Candidate& b) {
                             if (a.rank != b.rank) return a.rank < b.rank;
                             return a.appId < b.appId;   // deterministic tie-break
                         });

        auto runCandidates = [&](bool requireMatch) -> bool {
            for (const Candidate& candidate : candidates) {
                if (tryBase(candidate.kind, candidate.appId, candidate.provider, requireMatch)) {
                    g_lastGoodBase = BaseRef{ candidate.kind, candidate.appId };
                    d.reason = std::string("forged from ") + candidate.providerName + " base";
                    return true;
                }
            }
            return false;
        };

        bool served = false;
        const bool matchingFirst = entry.identity.known && entry.identity.steamId != 0;
        if (matchingFirst) {
            served = runCandidates(true);
        }
        if (!served && !strict) {
            // Best-effort pass: accept any usable base and record the mixing.
            served = runCandidates(false);
        }
        if (!served && strict && !matchingFirst) {
            // Strict mode with an unidentifiable expected account (e.g. the
            // active-user key is unavailable): mirror the historical behavior.
            served = runCandidates(true);
        }
        if (served) return entry;

        // 2c) Ticket backend (only when this build/user configured one). The
        //     mint returns the ownership ticket AND the pool account it was
        //     minted for, so the served bytes and the reported identity stay on
        //     that one account. This is the last resort: it is the only path
        //     that can answer when this machine holds no signed material at all.
        if (policy.allowBackend) {
            const uint64 existingSteamId = entry.identity.known ? entry.identity.steamId : 0;
            if (auto fetched = EticketClient::FetchTickets(appId, {}, existingSteamId);
                fetched && AppTicket::IsUsableForgeSourceTicket(fetched->ownership)) {
                d.servable        = true;
                d.provenance      = Provenance::FetchedFromBackend;
                d.ownerSteamId    = fetched->steamId;
                d.bytes           = std::move(fetched->ownership);
                d.totalSize       = static_cast<uint32>(d.bytes.size());
                d.appIdOffset     = AppTicket::kAppTicketAppIdOffset;
                d.steamIdOffset   = AppTicket::kAppTicketSteamIdOffset;
                d.signatureOffset = *reinterpret_cast<const uint32*>(d.bytes.data());
                d.signatureSize   = AppTicket::kAppTicketSignatureSize;

                if (fetched->steamId != 0) {
                    entry.identity.foreign = true;
                    entry.identity.known   = true;
                    entry.identity.steamId = fetched->steamId;
                    entry.identity.source  = "backend";
                }
                d.identity = entry.identity;
                d.reason   = "fetched from the configured ticket backend";
                if (policy.vault) VaultSave(appId, d.bytes, fetched->steamId, "backend");
                return entry;
            }
        }

        // Closing rung: the requested app's own stored bytes failed validation,
        // but an empty answer guarantees the launch failure while a served one
        // may still pass. Best-effort mode serves them and records the mixing;
        // strict mode stops here.
        if (!storedRaw.empty() && !strict) {
            d.servable        = true;
            d.provenance      = Provenance::StoredRaw;
            d.ownerSteamId    = AppTicket::ExtractSteamIdFromTicketBytes(storedRaw);
            d.bytes           = std::move(storedRaw);
            d.totalSize       = static_cast<uint32>(d.bytes.size());
            d.appIdOffset     = AppTicket::kAppTicketAppIdOffset;
            d.steamIdOffset   = AppTicket::kAppTicketSteamIdOffset;
            d.signatureOffset = d.bytes.size() >= sizeof(uint32)
                                    ? *reinterpret_cast<const uint32*>(d.bytes.data())
                                    : 0;
            d.signatureSize   = AppTicket::kAppTicketSignatureSize;
            d.mixedIdentity   = true;
            d.reason = "stored ticket failed validation and nothing else exists; "
                       "served anyway (best-effort)";
            return entry;
        }

        if (entry.identity.foreign) {
            d.reason = entry.identity.known
                ? "pool identity expected (account " + std::to_string(entry.identity.steamId) +
                  ") but no signed base for that account exists locally; import setAppTicket "
                  "from the same source (extract_tickets on the owning account) or re-redeem"
                : "no validated stored ticket and no usable forge base";
        } else {
            d.reason = "no validated stored ticket and no usable forge base "
                       "(this is the launch-failure class reported as error 54)";
        }
        return entry;
    }

    void LogDecision(AppId_t appId, const Entry& entry)
    {
        const Decision& d = entry.decision;
        if (!d.servable) {
            LOG_TICKET_WARN("AppId {}: no ownership ticket to serve - {}", appId, d.reason);
            return;
        }
        LOG_TICKET_INFO("AppId {}: serving {} (base AppId {}, owner {}, {} bytes, eticket={}, "
                        "identity={}{}{}) - {}",
                        appId, ToString(d.provenance), d.sourceApp, d.ownerSteamId,
                        d.bytes.size(), entry.hasETicket,
                        entry.identity.foreign ? "pool/" : "local/",
                        entry.identity.known ? std::to_string(entry.identity.steamId)
                                             : std::string("unknown"),
                        d.mixedIdentity ? ", mixed" : "",
                        d.reason);
    }

} // namespace

const char* ToString(Provenance provenance)
{
    switch (provenance) {
    case Provenance::None:               return "none";
    case Provenance::Stored:             return "stored";
    case Provenance::StoredVault:        return "stored_vault";
    case Provenance::StoredRaw:          return "stored_raw";
    case Provenance::ForgeFromHint:      return "forge_hint";
    case Provenance::ForgeFromLua:       return "forge_lua";
    case Provenance::ForgeFromInstalled: return "forge_installed";
    case Provenance::ForgeFromVault:     return "forge_vault";
    case Provenance::ForgeFromRegistry:  return "forge_credential";
    case Provenance::ForgeFromClient:    return "forge_client";
    case Provenance::ForgeFromCache:     return "forge_cached";
    case Provenance::FetchedFromBackend: return "fetch_backend";
    }
    return "?";
}

const char* ToString(ImportKind kind)
{
    switch (kind) {
    case ImportKind::AppTicket: return "appticket";
    case ImportKind::ETicket:   return "eticket";
    }
    return "?";
}

Decision Resolve(AppId_t appId)
{
    // Policy and paths are read before taking our lock: config reloads call
    // Reset() after dropping their own lock, so this order can never deadlock.
    const Config::TicketPolicy policy = Config::GetTicketPolicy();

    std::string report;
    Decision result;
    {
        std::lock_guard lock(g_mutex);
        if (auto it = g_entries.find(appId); it != g_entries.end()) {
            return it->second.decision;
        }

        Entry entry = EvaluateLocked(appId, policy);
        result = entry.decision;
        LogDecision(appId, entry);
        g_entries.emplace(appId, std::move(entry));

        if (policy.report) {
            report = BuildReportLocked(policy);
        }
    }

    if (!report.empty()) FlushReport(report);
    return result;
}

void NoteImport(AppId_t appId, ImportKind kind, const std::vector<uint8_t>& blob)
{
    const uint64 local = ActiveAccountSteamId();
    const Config::TicketPolicy policy = Config::GetTicketPolicy();

    {
        std::lock_guard lock(g_mutex);
        ImportNote& note = g_imports[appId];

        if (kind == ImportKind::AppTicket) {
            note.hasAppTicket = true;
            note.appTicketSteamId = AppTicket::ExtractSteamIdFromTicketBytes(blob);
            note.appTicketEmbeddedApp = EmbeddedAppId(blob);

            // Imported material joins the vault immediately: it survives Steam
            // cache clears and is available as a forge base or stored ticket.
            if (policy.vault) VaultSave(appId, blob, note.appTicketSteamId, "imported");

            if (note.appTicketEmbeddedApp != 0 && note.appTicketEmbeddedApp != appId) {
                LOG_TICKET_WARN("setAppTicket({}): blob embeds AppId {} - it will be ignored for this app",
                                appId, note.appTicketEmbeddedApp);
            }
            if (local != 0 && note.appTicketSteamId != 0 && note.appTicketSteamId != local) {
                LOG_TICKET_INFO("setAppTicket({}): ticket belongs to account {} (foreign/pool import)",
                                appId, note.appTicketSteamId);
            }
        } else {
            note.hasETicket = true;
        }

        // Material changed for this app: re-evaluate on the next request.
        g_entries.erase(appId);
    }

    // The checks below read the store through AppTicket (no authority lock
    // needed) so importing a lone ETicket is flagged immediately.
    if (kind == ImportKind::ETicket) {
        std::vector<uint8_t> stored = AppTicket::GetAppOwnershipTicketFromCredentialStore(appId);
        const bool haveApp = !stored.empty() && AppTicket::IsUsableForgeSourceTicket(stored);
        if (!haveApp) {
            LOG_TICKET_WARN("setETicket({}): no AppTicket imported for this app; a pool ETicket "
                            "cannot be paired with a locally forged ticket - import setAppTicket "
                            "from the same source or re-redeem", appId);
        }
    } else {
        std::vector<uint8_t> storedEt = AppTicket::GetEncryptedTicketFromCredentialStore(appId);
        if (storedEt.empty()) {
            LOG_TICKET_INFO("setAppTicket({}): Denuvo titles also need setETicket from the same "
                            "account; once an ETicket exists, changing the AppTicket would leave "
                            "the pair inconsistent", appId);
        }
    }
}

uint64 IdentityToReport(AppId_t appId)
{
    (void)Resolve(appId);   // ensure the entry exists and is current

    Entry entry;
    {
        std::lock_guard lock(g_mutex);
        auto it = g_entries.find(appId);
        if (it == g_entries.end()) return 0;
        entry = it->second;
    }

    uint64 report = 0;
    if (entry.decision.servable) {
        report = (entry.decision.provenance == Provenance::Stored)
                     ? (entry.identity.known ? entry.identity.steamId : entry.decision.ownerSteamId)
                     : entry.decision.ownerSteamId;
    } else if (entry.identity.foreign) {
        report = entry.identity.steamId;   // 0 when the foreign account is unknown
    }

    // Reporting the signed-in account as a "spoof" would be a no-op; keep the
    // real identity in that case so the DRM's checks compare like with like.
    const uint64 local = ActiveAccountSteamId();
    if (report != 0 && local != 0 && report == local) return 0;
    return report;
}

void Reset()
{
    std::lock_guard lock(g_mutex);
    g_entries.clear();
    g_lastGoodBase.reset();
    g_imports.clear();
}

void WriteReport()
{
    const Config::TicketPolicy policy = Config::GetTicketPolicy();
    std::string report;
    {
        std::lock_guard lock(g_mutex);
        report = BuildReportLocked(policy);
    }
    FlushReport(report);
}

} // namespace TicketAuthority
