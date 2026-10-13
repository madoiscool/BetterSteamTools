#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace OSTPlatform::SteamCredentialStore {

    enum class Status {
        Ok,
        NotFound,
        Unsupported,
        Failed,
    };

    const char* ToString(Status status);

    // Read/write Steam per-app credentials. Each Get* reader writes its
    // out-parameter only on Status::Ok; on any other status the out-parameter is
    // left untouched. The signatures mirror their Write* counterparts so a value
    // travels through the same shape going in and coming out.
    Status GetAppTicket(uint32_t appId, std::vector<uint8_t>& ticket);
    Status WriteAppTicket(uint32_t appId, const std::vector<uint8_t>& data);

    Status GetETicket(uint32_t appId, std::vector<uint8_t>& ticket);
    Status WriteETicket(uint32_t appId, const std::vector<uint8_t>& data);

    Status GetSteamId(uint32_t appId, uint64_t& steamId);
    Status WriteSteamId(uint32_t appId, uint64_t steamId);

    Status GetActiveUser(uint32_t& accountId, std::wstring& universe);

    // Enumerate the app ids that have a per-app credential key in the store.
    // Windows backend: subkeys of HKCU\Software\Valve\Steam\Apps whose names
    // parse as decimal app ids (anything else is skipped). Returns Ok with an
    // empty vector when the root key exists but holds no app keys, and
    // NotFound when the root key is missing. Used to find a signed ticket to
    // forge a target app's ownership ticket from when the usual sources are
    // absent.
    Status EnumerateAppIds(std::vector<uint32_t>& appIds);

} // namespace OSTPlatform::SteamCredentialStore
