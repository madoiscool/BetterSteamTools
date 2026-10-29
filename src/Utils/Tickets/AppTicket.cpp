#include "AppTicket.h"
#include "Hook/Hooks_Decryption.h"
#include "OSTPlatform/include/SteamCredentialStore.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Logging/Log.h"
#include "dllmain.h"

#include <cctype>
#include <fstream>
#include <string>

namespace AppTicket {
    // Preference order for the ticket spliced into as the forge source: the
    // appid-7 ticket first, then appid 228980, then (if both are unavailable)
    // any other appticket observed in the local ConfigStore. A source only needs
    // to be a real signed ticket long enough to carry the trailing signature.
    constexpr AppId_t kPrimaryAppTicketSourceAppId = 7;
    constexpr AppId_t kFallbackAppTicketSourceAppId = 228980;
    constexpr size_t kSteamIdTicketMinimumSize = 16;

    static uint64_t GetSteamIDFromCredentialStore(AppId_t appId) {
        uint64_t steamId = 0;
        const auto status = OSTPlatform::SteamCredentialStore::GetSteamId(appId, steamId);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_TRACE("GetSpoofSteamID for AppId {}: SteamID unavailable in credential store ({})",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return 0;
        }

        LOG_DEBUG("GetSpoofSteamID for AppId {}: SteamID credential -> 0x{:X}({})", appId, steamId, steamId);
        return steamId;
    }

    std::vector<uint8_t> GetAppOwnershipTicketFromCredentialStore(AppId_t appId) {
        // exclude those appids that are not in addappid
        if (!LuaConfig::HasDepot(appId)) {
            LOG_DEBUG("GetAppOwnershipTicketFromCredentialStore for AppId {}: not in addappid, skip", appId);
            return {};
        }
        std::vector<uint8_t> ticket;
        const auto status = OSTPlatform::SteamCredentialStore::GetAppTicket(appId, ticket);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_TRACE("Read App Ownership Ticket for AppId {}: cached credential unavailable ({})",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return {};
        }

        LOG_INFO("Successfully retrieved App Ownership Ticket from credential store, AppId: {}, Ticket Size: {}", appId, ticket.size());
        return ticket;
    }

    // Exploit steamdrmp's off-by-four ticket parsing vulnerability:
    // splice the requested AppId into a cached, signed source ticket just
    // before its trailing signature. The source may belong to any app — it
    // only needs to be a real signed ticket long enough to carry a signature.
    struct SourceTicket {
        AppId_t appId = 0;
        std::vector<uint8_t> data;
    };

    static bool IsValidSourceTicket(const std::vector<uint8_t>& ticket) {
        return !ticket.empty() && ticket.size() > kAppTicketSignatureSize;
    }

    // Read the active account's localconfig.vdf and return the FIRST cached
    // app-ownership ticket big enough to splice into. These are the user's OWN
    // tickets (Steam writes them here; OST never does), so they carry the user's
    // SteamID and need no spoofing — and the appid of the base is irrelevant, so
    // the first valid one works for every game. apptickets is a flat text-VDF
    // block of "<appid>" "<hexticket>" pairs.
    static SourceTicket ReadLocalConfigSourceTicket() {
        SourceTicket pick;
        if (!SteamInstallPath[0]) return pick;

        uint32_t accountId = 0;
        std::wstring universe;
        if (OSTPlatform::SteamCredentialStore::GetActiveUser(accountId, universe)
                != OSTPlatform::SteamCredentialStore::Status::Ok || accountId == 0) {
            LOG_DEBUG("ReadLocalConfigSourceTicket: no active user");
            return pick;
        }

        const std::string path = std::string(SteamInstallPath) + "\\userdata\\" +
                                 std::to_string(accountId) + "\\config\\localconfig.vdf";
        std::ifstream f(path, std::ios::binary);
        if (!f) { LOG_DEBUG("ReadLocalConfigSourceTicket: cannot open {}", path); return pick; }
        const std::string data((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());

        const size_t sec = data.find("\"apptickets\"");
        if (sec == std::string::npos) { LOG_DEBUG("ReadLocalConfigSourceTicket: no apptickets section"); return pick; }
        const size_t open = data.find('{', sec);
        if (open == std::string::npos) return pick;
        size_t close = data.find('}', open);           // apptickets is flat — no nested braces
        if (close == std::string::npos) close = data.size();

        // Walk "<appid>" "<hex>" pairs; stop at the first valid base.
        size_t pos = open;
        const auto nextQuoted = [&](std::string& out) -> bool {
            const size_t a = data.find('"', pos);
            if (a == std::string::npos || a >= close) return false;
            const size_t b = data.find('"', a + 1);
            if (b == std::string::npos || b >= close) return false;
            out.assign(data, a + 1, b - a - 1);
            pos = b + 1;
            return true;
        };
        const auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return c - 'A' + 10;
        };

        std::string key, val;
        while (nextQuoted(key) && nextQuoted(val)) {
            if (key.empty() || key.find_first_not_of("0123456789") != std::string::npos) continue;
            if (val.size() < 2 || (val.size() % 2) != 0) continue;
            bool isHex = true;
            for (char c : val) if (!std::isxdigit(static_cast<unsigned char>(c))) { isHex = false; break; }
            if (!isHex || val.size() / 2 <= kAppTicketSignatureSize) continue;  // need > signature

            std::vector<uint8_t> bytes;
            bytes.reserve(val.size() / 2);
            for (size_t i = 0; i + 1 < val.size(); i += 2)
                bytes.push_back(static_cast<uint8_t>((hexVal(val[i]) << 4) | hexVal(val[i + 1])));

            // The forged ticket inherits this base's SteamID, and Denuvo
            // cross-checks it against GetSteamID. Skip any ticket not issued to
            // the logged-in account (e.g. a family-shared game, whose ticket
            // carries the lender's SteamID) — using it would guarantee error 54.
            const uint64_t ticketSteamId = ExtractSteamIdFromTicketBytes(bytes);
            if (static_cast<uint32_t>(ticketSteamId & 0xFFFFFFFFull) != accountId) {
                LOG_DEBUG("ReadLocalConfigSourceTicket: skip appid {} base (SteamID account {} != active {})",
                          strtoul(key.c_str(), nullptr, 10),
                          static_cast<uint32_t>(ticketSteamId & 0xFFFFFFFFull), accountId);
                continue;
            }

            pick.appId = static_cast<AppId_t>(strtoul(key.c_str(), nullptr, 10));
            pick.data = std::move(bytes);
            LOG_INFO("ReadLocalConfigSourceTicket: using appid {} ticket ({} bytes) as forge base",
                     pick.appId, pick.data.size());
            return pick;
        }
        LOG_DEBUG("ReadLocalConfigSourceTicket: no valid base ticket in apptickets");
        return pick;
    }

    // Pick the source ticket to splice into:
    //   1. any valid ticket from the active account's localconfig (cached once —
    //      appId 7 is no longer universally present, but one base forges all)
    //   2. fallback probes: appid 7, appid 228980, then any appticket the
    //      decryption hook has observed this session
    // Returns an empty source (appId == 0) when nothing is available.
    static SourceTicket PickForgeSourceTicket() {
        // One valid base forges every appid, so resolve localconfig once and
        // keep it for the session. Cache only on success (retry until ready).
        static SourceTicket cached;
        if (cached.appId != 0) return cached;
        if (SourceTicket lc = ReadLocalConfigSourceTicket(); lc.appId != 0) {
            cached = std::move(lc);
            return cached;
        }

        SourceTicket pick;
        const auto tryAppId = [&](AppId_t id) -> bool {
            if (id == 0) return false;
            std::vector<uint8_t> ticket = Hooks_Decryption::GetCacheAppOwnershipTicket(id);
            if (IsValidSourceTicket(ticket)) {
                pick.appId = id;
                pick.data = std::move(ticket);
                return true;
            }
            return false;
        };

        if (tryAppId(kPrimaryAppTicketSourceAppId)) return pick;
        if (tryAppId(kFallbackAppTicketSourceAppId)) return pick;
        for (AppId_t id : Hooks_Decryption::GetSeenAppTicketIds()) {
            if (id == kPrimaryAppTicketSourceAppId || id == kFallbackAppTicketSourceAppId) continue;
            if (tryAppId(id)) return pick;
        }
        LOG_DEBUG("PickForgeSourceTicket: no available source appticket found");
        return pick;
    }

    static std::vector<uint8_t> ForgeLocalAppOwnershipTicket(AppId_t appId) {
        SourceTicket source = PickForgeSourceTicket();
        if (source.appId == 0) {
            LOG_DEBUG("ForgeLocalAppOwnershipTicket for AppId {}: no source appticket", appId);
            return {};
        }

        const size_t signedSize = source.data.size() - kAppTicketSignatureSize;
        std::vector<uint8_t> ticket;
        ticket.reserve(source.data.size() + sizeof(AppId_t));
        ticket.insert(ticket.end(), source.data.begin(), source.data.begin() + signedSize);

        const uint8_t* appIdBytes = reinterpret_cast<const uint8_t*>(&appId);
        ticket.insert(ticket.end(), appIdBytes, appIdBytes + sizeof(AppId_t));
        ticket.insert(ticket.end(), source.data.begin() + signedSize, source.data.end());

        LOG_INFO("Forged App Ownership Ticket, AppId: {}, SourceAppId: {}, Physical Size: {}, Total Size: {}",
                 appId, source.appId, ticket.size(), source.data.size());
        return ticket;
    }

    bool GetAppOwnershipTicket(AppId_t appId, AppOwnershipTicket& ticket, AppTicketSource source) {
        ticket = {};
        
        if (source == AppTicketSource::CredentialStoreOnly || source == AppTicketSource::CredentialStoreThenForge) {
            ticket.data = GetAppOwnershipTicketFromCredentialStore(appId);
            if (!ticket.data.empty() && ticket.data.size() >= sizeof(uint32)) {
                ticket.totalSize = static_cast<uint32>(ticket.data.size());
                ticket.appIdOffset = kAppTicketAppIdOffset;
                ticket.steamIdOffset = kAppTicketSteamIdOffset;
                ticket.signatureOffset = *reinterpret_cast<const uint32*>(ticket.data.data());
                ticket.signatureSize = kAppTicketSignatureSize;
                return true;
            }
        }

        if (source == AppTicketSource::CredentialStoreOnly) return false;

        ticket.data = ForgeLocalAppOwnershipTicket(appId);
        if (ticket.data.empty()) return false;

        ticket.totalSize = static_cast<uint32>(ticket.data.size() - sizeof(AppId_t));
        ticket.appIdOffset = ticket.totalSize - kAppTicketSignatureSize;
        ticket.steamIdOffset = kAppTicketSteamIdOffset;
        ticket.signatureOffset = ticket.appIdOffset + sizeof(AppId_t);
        ticket.signatureSize = kAppTicketSignatureSize;
        return true;
    }

    std::vector<uint8_t> GetEncryptedTicketFromCredentialStore(AppId_t appId) {
        LOG_DEBUG("appid={}", appId);    
        // exclude those appids that are not in addappid
        if (!LuaConfig::HasDepot(appId)) {
            LOG_DEBUG("GetEncryptedTicketFromCredentialStore for AppId {}: not in addappid, skip", appId);
            return {};
        }
        std::vector<uint8_t> ticket;
        const auto status = OSTPlatform::SteamCredentialStore::GetETicket(appId, ticket);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_TRACE("Read Encrypted App Ticket for AppId {}: cached credential unavailable ({})",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return {};
        }

        LOG_INFO("Successfully retrieved Encrypted App Ticket from credential store, AppId: {}, Ticket Size: {}", appId, ticket.size());
        return ticket;
    }

    bool WriteAppOwnershipTicket(AppId_t appId, const std::vector<uint8_t>& data) {
        // we can't execlude appids here 
        const auto status = OSTPlatform::SteamCredentialStore::WriteAppTicket(appId, data);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_ERROR("Failed to write AppTicket for AppId {} to credential store: {}",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return false;
        }

        LOG_INFO("Wrote AppTicket for AppId {} ({} bytes)", appId, data.size());
        return true;
    }

    bool WriteEncryptedTicket(AppId_t appId, const std::vector<uint8_t>& data) {
        // we can't execlude appids here 
        const auto status = OSTPlatform::SteamCredentialStore::WriteETicket(appId, data);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_ERROR("Failed to write ETicket for AppId {} to credential store: {}",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return false;
        }

        LOG_INFO("Wrote ETicket for AppId {} ({} bytes)", appId, data.size());
        return true;
    }

    bool WriteSteamID(AppId_t appId, uint64_t steamId) {
        const auto status = OSTPlatform::SteamCredentialStore::WriteSteamId(appId, steamId);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_ERROR("Failed to write SteamID for AppId {} to credential store: {}",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return false;
        }

        LOG_INFO("Wrote SteamID for AppId {} ({})", appId, steamId);
        return true;
    }

    uint64_t ExtractSteamIdFromTicketBytes(const std::vector<uint8_t>& ticket) {
        // Layout: ticket bytes start with [uint32 Size][uint32 Version][uint64 SteamID][...].
        if (ticket.size() < kSteamIdTicketMinimumSize) return 0;
        return reinterpret_cast<const uint64_t*>(ticket.data())[1];
    }

    uint64_t GetSpoofSteamID(AppId_t appId) {
        // exclude those appids that are not in addappid
        if (!LuaConfig::HasDepot(appId)) {
            LOG_DEBUG("GetSpoofSteamID for AppId {}: not in addappid, skip spoofing", appId);
            return 0;
        }
        const uint64_t credentialSteamID = GetSteamIDFromCredentialStore(appId);
        if (credentialSteamID != 0) {
            return credentialSteamID;
        }

        // The SteamID baked into the cached AppOwnershipTicket is the same
        // one Steam itself uses for this app — pull it straight out of the
        // ticket so spoofed responses match what the DRM layer expects.
        const uint64_t steamID = ExtractSteamIdFromTicketBytes(GetAppOwnershipTicketFromCredentialStore(appId));
        if (steamID) {
            LOG_DEBUG("GetSpoofSteamID for AppId {}: -> 0x{:X}({})", appId, steamID, steamID);
        }
        return steamID;
    }
}
