#include "AppTicket.h"

#include "OSTPlatform/include/SteamCredentialStore.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Logging/Log.h"
#include "Utils/Tickets/TicketAuthority.h"

namespace AppTicket {
namespace {

    constexpr size_t kUsableBlobMinBytes = kAppTicketSignatureSize + 1;  // longer than the signature
    constexpr size_t kUsableBlobMaxBytes = 0x10000;                      // 64 KiB sanity bound
    constexpr size_t kSteamIdTicketMinimumSize = 16;

} // namespace

    bool IsUsableForgeSourceTicket(const std::vector<uint8_t>& data)
    {
        if (data.size() < kUsableBlobMinBytes) return false;
        if (data.size() > kUsableBlobMaxBytes) return false;
        // The first word is the signature offset the DRM layer reads; a
        // placeholder blob has none, so it cannot be served or forged from.
        return *reinterpret_cast<const uint32*>(data.data()) != 0;
    }

    std::vector<uint8_t> GetAppOwnershipTicketFromCredentialStore(AppId_t appId)
    {
        // Exclude app ids that are not managed by Lua.
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

        LOG_DEBUG("Read App Ownership Ticket for AppId {}: {} bytes", appId, ticket.size());
        return ticket;
    }

    std::vector<uint8_t> GetValidatedAppOwnershipTicketFromCredentialStore(AppId_t appId)
    {
        std::vector<uint8_t> ticket = GetAppOwnershipTicketFromCredentialStore(appId);
        if (ticket.empty()) return ticket;

        // A stored blob that does not embed this app id (stale write, or a
        // ticket meant for another app) must not be served: DRM-wrapped titles
        // reject the launch on the mismatch, which surfaces as the "error 54"
        // class. Callers fall back to the forge path instead.
        if (ticket.size() < kAppTicketAppIdOffset + sizeof(uint32)) {
            LOG_WARN("GetValidatedAppOwnershipTicket: AppId {} cached ticket too small ({} bytes), ignoring",
                     appId, ticket.size());
            return {};
        }
        const uint32 embeddedAppId = *reinterpret_cast<const uint32*>(ticket.data() + kAppTicketAppIdOffset);
        if (embeddedAppId != appId) {
            LOG_WARN("GetValidatedAppOwnershipTicket: AppId {} cached ticket embeds AppId {} - stale, ignoring",
                     appId, embeddedAppId);
            return {};
        }
        return ticket;
    }

    std::vector<uint8_t> GetEncryptedTicketFromCredentialStore(AppId_t appId)
    {
        // Exclude app ids that are not managed by Lua.
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

        LOG_DEBUG("Read Encrypted App Ticket for AppId {}: {} bytes", appId, ticket.size());
        return ticket;
    }

    std::vector<uint8_t> ForgeFromSource(AppId_t appId, const std::vector<uint8_t>& source)
    {
        // The DRM reads the app id from the word right before the signature,
        // which the signature does not cover - so splicing the requested app id
        // there keeps the source's signature valid for the new bytes.
        if (source.size() <= kAppTicketSignatureSize) return {};

        const size_t signedSize = source.size() - kAppTicketSignatureSize;
        std::vector<uint8_t> ticket;
        ticket.reserve(source.size() + sizeof(AppId_t));
        ticket.insert(ticket.end(), source.begin(), source.begin() + signedSize);

        const uint8_t* appIdBytes = reinterpret_cast<const uint8_t*>(&appId);
        ticket.insert(ticket.end(), appIdBytes, appIdBytes + sizeof(AppId_t));
        ticket.insert(ticket.end(), source.begin() + signedSize, source.end());
        return ticket;
    }

    uint64_t GetSpoofSteamID(AppId_t appId)
    {
        // Exclude app ids that are not managed by Lua.
        if (!LuaConfig::HasDepot(appId)) {
            LOG_DEBUG("GetSpoofSteamID for AppId {}: not in addappid, skip spoofing", appId);
            return 0;
        }

        // The identity to report is derived by the ticket authority from the
        // same material that decides which bytes are served, so the two can
        // never disagree. 0 means "keep the real signed-in account".
        const uint64_t identity = TicketAuthority::IdentityToReport(appId);
        if (identity == 0) {
            LOG_DEBUG("GetSpoofSteamID for AppId {}: no foreign identity to report", appId);
            return 0;
        }
        LOG_DEBUG("GetSpoofSteamID for AppId {}: -> 0x{:X}({})", appId, identity, identity);
        return identity;
    }

    uint64_t ExtractSteamIdFromTicketBytes(const std::vector<uint8_t>& ticket)
    {
        // Layout: ticket bytes start with [uint32 Size][uint32 Version][uint64 SteamID][...].
        if (ticket.size() < kSteamIdTicketMinimumSize) return 0;
        return reinterpret_cast<const uint64_t*>(ticket.data())[1];
    }

    bool WriteAppOwnershipTicket(AppId_t appId, const std::vector<uint8_t>& data)
    {
        const auto status = OSTPlatform::SteamCredentialStore::WriteAppTicket(appId, data);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_ERROR("Failed to write AppTicket for AppId {} to credential store: {}",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return false;
        }

        LOG_INFO("Wrote AppTicket for AppId {} ({} bytes)", appId, data.size());
        return true;
    }

    bool WriteEncryptedTicket(AppId_t appId, const std::vector<uint8_t>& data)
    {
        const auto status = OSTPlatform::SteamCredentialStore::WriteETicket(appId, data);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_ERROR("Failed to write ETicket for AppId {} to credential store: {}",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return false;
        }

        LOG_INFO("Wrote ETicket for AppId {} ({} bytes)", appId, data.size());
        return true;
    }

    bool WriteSteamID(AppId_t appId, uint64_t steamId)
    {
        const auto status = OSTPlatform::SteamCredentialStore::WriteSteamId(appId, steamId);
        if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
            LOG_ERROR("Failed to write SteamID for AppId {} to credential store: {}",
                      appId, OSTPlatform::SteamCredentialStore::ToString(status));
            return false;
        }

        LOG_INFO("Wrote SteamID for AppId {} ({})", appId, steamId);
        return true;
    }

} // namespace AppTicket
