#pragma once

#include "Steam/Types.h"

#include <cstdint>
#include <vector>

namespace AppTicket {
    inline constexpr uint32 kAppTicketSteamIdOffset = 8;
    inline constexpr uint32 kAppTicketAppIdOffset = 16;
    inline constexpr uint32 kAppTicketSignatureSize = 128;

    // Raw read of the credential-store ticket for appId (gated by the Lua
    // addappid list). Returns an empty vector when no credential exists.
    std::vector<uint8_t> GetAppOwnershipTicketFromCredentialStore(AppId_t appId);

    // Same read, additionally requiring the blob to embed appId at
    // kAppTicketAppIdOffset. Stale entries written for another app are ignored.
    std::vector<uint8_t> GetValidatedAppOwnershipTicketFromCredentialStore(AppId_t appId);

    // Encrypted app ticket (strict Denuvo) from the credential store.
    std::vector<uint8_t> GetEncryptedTicketFromCredentialStore(AppId_t appId);

    // True when a raw blob is a plausible signed ticket: longer than the
    // 128-byte signature it carries, within a sane size, with a non-zero
    // signature-offset word. Placeholder blobs fail this.
    bool IsUsableForgeSourceTicket(const std::vector<uint8_t>& data);

    // Builds a ticket for appId from any signed source blob by splicing appId
    // ahead of the trailing signature - the spot SteamDRMP's parser reads as
    // the app id, which the signature does not cover. Returns empty when the
    // source is too small to carry a signature.
    std::vector<uint8_t> ForgeFromSource(AppId_t appId, const std::vector<uint8_t>& source);

    // SteamID to report for appId: the stored credential identity while the
    // ticket authority answers from the store, otherwise 0 so the real account
    // identity stays consistent with the bytes actually served.
    uint64_t GetSpoofSteamID(AppId_t appId);

    // Parses the SteamID baked into ticket bytes (kAppTicketSteamIdOffset).
    // Returns 0 when the blob is too short to contain one.
    uint64_t ExtractSteamIdFromTicketBytes(const std::vector<uint8_t>& ticket);

    // Write AppTicket / ETicket / SteamID binary data to Steam's local
    // credential store.
    bool WriteAppOwnershipTicket(AppId_t appId, const std::vector<uint8_t>& data);
    bool WriteEncryptedTicket(AppId_t appId, const std::vector<uint8_t>& data);
    bool WriteSteamID(AppId_t appId, uint64_t steamId);

} // namespace AppTicket
