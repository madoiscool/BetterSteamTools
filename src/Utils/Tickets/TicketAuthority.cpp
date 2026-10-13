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
#include <filesystem>
#include <mutex>
#include <optional>
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

    // A forge base candidate: which storage holds the blob and which provider
    // discovered it (only used for the log line).
    struct Candidate
    {
        BaseKind    kind;
        AppId_t     appId;
        int         rank;
        const char* providerName;
    };

    std::mutex g_mutex;
    std::unordered_map<AppId_t, Entry> g_entries;
    std::unordered_map<AppId_t, ImportNote> g_imports;
    std::optional<BaseRef> g_lastGoodBase;   // base that already worked this session

    // -- helpers --------------------------------------------------------------

    bool ReadBase(BaseKind kind, AppId_t appId, std::vector<uint8_t>& out)
    {
        if (kind == BaseKind::ConfigStore) {
            out = Hooks_Decryption::GetCacheAppOwnershipTicket(appId);
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

    // 1) Stored bytes. This is the only source that carries an account's
    //    identity directly, so it is preferred whenever it validates; a blob
    //    that fails validation is kept in storedRaw as a last resort.
    bool TryStoredLocked(AppId_t appId, Entry& entry, std::vector<uint8_t>& storedRaw)
    {
        std::vector<uint8_t> stored = AppTicket::GetAppOwnershipTicketFromCredentialStore(appId);
        if (stored.empty()) return false;

        const uint32 embedded = EmbeddedAppId(stored);
        if (!AppTicket::IsUsableForgeSourceTicket(stored)) {
            LOG_TICKET_WARN("AppId {}: stored ticket is malformed ({} bytes); it will only be served if nothing else exists",
                            appId, stored.size());
            storedRaw = std::move(stored);
            return false;
        }
        if (embedded != appId) {
            LOG_TICKET_WARN("AppId {}: stored ticket embeds AppId {} (stale/foreign); it will only be served if nothing else exists",
                            appId, embedded);
            storedRaw = std::move(stored);
            return false;
        }

        Decision& d = entry.decision;
        d.servable        = true;
        d.provenance      = Provenance::Stored;
        d.ownerSteamId    = AppTicket::ExtractSteamIdFromTicketBytes(stored);
        d.totalSize       = static_cast<uint32>(stored.size());
        d.signatureOffset = *reinterpret_cast<const uint32*>(stored.data());
        d.bytes           = std::move(stored);
        return true;
    }

    // 2) Forge-base candidates, in preference order. There is deliberately no
    //    fixed app id list in the DLL - ids are discovered:
    //    Lua-managed apps -> per-app credentials (probed in BOTH storage
    //    locations) -> the Steam client's own ticket (last local resort).
    std::vector<Candidate> CollectCandidatesLocked(AppId_t appId)
    {
        std::vector<Candidate> candidates;
        auto add = [&](BaseKind kind, AppId_t app, int rank, const char* name) {
            if (app == 0 || app == appId) return;
            for (const Candidate& existing : candidates)
                if (existing.kind == kind && existing.appId == app) return;
            candidates.push_back(Candidate{ kind, app, rank, name });
        };

        {
            // App ids this Lua setup manages: the games actually played here,
            // so their cached tickets are strong candidates. Bounded so a huge
            // depot list cannot stall the decision.
            constexpr size_t kMaxLuaCandidates = 128;
            const std::vector<AppId_t> managed = LuaConfig::GetAllDepotIds();
            size_t added = 0;
            for (AppId_t app : managed) {
                if (added >= kMaxLuaCandidates) break;
                add(BaseKind::ConfigStore, app, 0, "lua");
                ++added;
            }
        }

        {
            // Every id the credential store knows about is probed in both
            // storage locations, so a cache-only blob cannot hide just because
            // no registry credential exists for it.
            std::vector<uint32_t> credentials;
            if (OSTPlatform::SteamCredentialStore::EnumerateAppIds(credentials)
                == OSTPlatform::SteamCredentialStore::Status::Ok) {
                for (uint32_t credential : credentials) {
                    const AppId_t app = static_cast<AppId_t>(credential);
                    add(BaseKind::CredentialStore, app, 1, "credential");
                    add(BaseKind::ConfigStore, app, 1, "credential");
                }
            }
        }

        add(BaseKind::ConfigStore, kClientAppId, 2, "client");
        add(BaseKind::CredentialStore, kClientAppId, 2, "client");

        std::stable_sort(candidates.begin(), candidates.end(),
                         [](const Candidate& a, const Candidate& b) {
                             if (a.rank != b.rank) return a.rank < b.rank;
                             return a.appId < b.appId;   // deterministic tie-break
                         });
        return candidates;
    }

    bool BaseMatchesIdentity(const Entry& entry, uint64 baseSteamId, uint64 localSteamId)
    {
        if (entry.identity.foreign) {
            return entry.identity.steamId != 0 && baseSteamId == entry.identity.steamId;
        }
        // Local identity: an unknown-account base is acceptable, a known one
        // must be the signed-in account.
        return baseSteamId == 0 || localSteamId == 0 || baseSteamId == localSteamId;
    }

    bool TryBaseLocked(AppId_t appId, Entry& entry, const Candidate& candidate,
                       bool requireMatch, uint64 localSteamId)
    {
        std::vector<uint8_t> base;
        if (!ReadBase(candidate.kind, candidate.appId, base)) return false;
        if (!AppTicket::IsUsableForgeSourceTicket(base)) return false;

        const uint64 baseSteamId = AppTicket::ExtractSteamIdFromTicketBytes(base);
        if (requireMatch && !BaseMatchesIdentity(entry, baseSteamId, localSteamId)) {
            LOG_TICKET_DEBUG("AppId {}: base AppId {} (account {}) does not match the expected identity, skipping",
                             appId, candidate.appId, baseSteamId);
            return false;
        }

        std::vector<uint8_t> forged = AppTicket::ForgeFromSource(appId, base);
        if (forged.empty()) return false;

        Decision& d = entry.decision;
        d.servable        = true;
        d.provenance      = Provenance::Forged;
        d.sourceApp       = candidate.appId;
        d.ownerSteamId    = baseSteamId;
        d.bytes           = std::move(forged);
        d.totalSize       = static_cast<uint32>(d.bytes.size() - sizeof(AppId_t));
        d.appIdOffset     = d.totalSize - AppTicket::kAppTicketSignatureSize;
        d.steamIdOffset   = AppTicket::kAppTicketSteamIdOffset;
        d.signatureOffset = d.appIdOffset + sizeof(AppId_t);
        d.signatureSize   = AppTicket::kAppTicketSignatureSize;

        const bool matchesExpected = entry.identity.known && entry.identity.steamId != 0 &&
                                     baseSteamId == entry.identity.steamId;
        d.mixedIdentity = !matchesExpected && baseSteamId != 0;
        return true;
    }

    bool ForgeLocked(AppId_t appId, Entry& entry, const std::vector<Candidate>& candidates,
                     bool requireMatch, uint64 localSteamId)
    {
        for (const Candidate& candidate : candidates) {
            if (TryBaseLocked(appId, entry, candidate, requireMatch, localSteamId)) {
                g_lastGoodBase = BaseRef{ candidate.kind, candidate.appId };
                entry.decision.reason = std::string("forged from ") + candidate.providerName + " base";
                return true;
            }
        }
        return false;
    }

    // 3) Ticket backend (only when this build/user configured one). The mint
    //    returns the ownership ticket AND the pool account it was minted for,
    //    so the served bytes and the reported identity stay on that one account.
    bool TryBackendLocked(AppId_t appId, Entry& entry)
    {
        const uint64 existingSteamId = entry.identity.known ? entry.identity.steamId : 0;
        auto fetched = EticketClient::FetchTickets(appId, {}, existingSteamId);
        if (!fetched || !AppTicket::IsUsableForgeSourceTicket(fetched->ownership)) return false;

        Decision& d = entry.decision;
        d.servable        = true;
        d.provenance      = Provenance::Forged;
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
        return true;
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

        std::vector<uint8_t> storedRaw;   // validation failures kept for a last-resort rung
        if (TryStoredLocked(appId, entry, storedRaw)) {
            d.reason = "validated stored ticket";
            return entry;
        }

        // Identity policy: "strict" refuses answers whose bytes describe a
        // different account than the expected identity. "best-effort" (default)
        // prefers matching bases but still serves the best available bytes,
        // recording the mixing - an empty answer guarantees the launch failure
        // while a mixed one may still pass, so falling back can only help.
        const bool strict = !policy.allowMixedIdentity;
        const uint64 localSteamId = ActiveAccountSteamId();

        if (strict && entry.identity.foreign && !entry.identity.known) {
            d.reason = "pool ticket material present but its account is unknown; import "
                       "setAppTicket from the same source (extract_tickets on the owning "
                       "account) or re-redeem (or set [tickets] identity_mode = \"best_effort\")";
            return entry;
        }

        bool served = false;

        // The base that already worked earlier in this session is tried first.
        if (g_lastGoodBase.has_value()) {
            const Candidate cached{ g_lastGoodBase->kind, g_lastGoodBase->appId, 0, "cached" };
            served = TryBaseLocked(appId, entry, cached, false, localSteamId);
            if (served) d.reason = "forged from base that already worked this session";
        }

        if (!served) {
            const std::vector<Candidate> candidates = CollectCandidatesLocked(appId);
            const bool matchingFirst = entry.identity.known && entry.identity.steamId != 0;
            if (matchingFirst) {
                served = ForgeLocked(appId, entry, candidates, true, localSteamId);
            }
            if (!served && !strict) {
                // Best-effort pass: accept any usable base and record the mixing.
                served = ForgeLocked(appId, entry, candidates, false, localSteamId);
            }
            if (!served && strict && !matchingFirst) {
                // Strict mode with an unidentifiable expected account (e.g. the
                // active-user key is unavailable): mirror the historical behavior.
                served = ForgeLocked(appId, entry, candidates, true, localSteamId);
            }
            if (served) return entry;
        } else {
            return entry;
        }

        if (TryBackendLocked(appId, entry)) return entry;

        // Closing rung: the requested app's own stored bytes failed validation,
        // but an empty answer guarantees the launch failure while a served one
        // may still pass. Best-effort mode serves them and records the mixing;
        // strict mode stops here.
        if (!storedRaw.empty() && !strict) {
            d.servable        = true;
            d.provenance      = Provenance::Stored;
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
    case Provenance::None:   return "none";
    case Provenance::Stored: return "stored";
    case Provenance::Forged: return "forged";
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
    // Policy is read before taking our lock: config reloads call Reset() after
    // dropping their own lock, so this order can never deadlock.
    const Config::TicketPolicy policy = Config::GetTicketPolicy();

    std::lock_guard lock(g_mutex);
    if (auto it = g_entries.find(appId); it != g_entries.end()) {
        return it->second.decision;
    }

    Entry entry = EvaluateLocked(appId, policy);
    LogDecision(appId, entry);
    const Decision result = entry.decision;
    g_entries.emplace(appId, std::move(entry));
    return result;
}

void NoteImport(AppId_t appId, ImportKind kind, const std::vector<uint8_t>& blob)
{
    const uint64 local = ActiveAccountSteamId();

    {
        std::lock_guard lock(g_mutex);
        ImportNote& note = g_imports[appId];

        if (kind == ImportKind::AppTicket) {
            note.hasAppTicket = true;
            note.appTicketSteamId = AppTicket::ExtractSteamIdFromTicketBytes(blob);
            note.appTicketEmbeddedApp = EmbeddedAppId(blob);

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

    // The spoof must describe the bytes actually served: the account baked into
    // them. When nothing is served but a foreign identity is known, report that
    // identity so the DRM's checks compare like with like.
    uint64 report = 0;
    if (entry.decision.servable) {
        report = entry.decision.ownerSteamId;
    } else if (entry.identity.foreign) {
        report = entry.identity.steamId;
    }

    // Reporting the signed-in account as a "spoof" would be a no-op; keep the
    // real identity in that case.
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

} // namespace TicketAuthority
