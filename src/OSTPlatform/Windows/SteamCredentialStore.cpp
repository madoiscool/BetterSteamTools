#include "include/SteamCredentialStore.h"

#include "include/Log.h"
#include "include/Numbers.h"
#include "include/Encoding.h"
#include "Windows/Handles.h"

#include <windows.h>

#include <utility>

namespace OSTPlatform::SteamCredentialStore {
namespace {

constexpr const wchar_t* kValueSteamId = L"SteamID";
constexpr const wchar_t* kValueAppTicket = L"AppTicket";
constexpr const wchar_t* kValueEncryptedTicket = L"ETicket";
constexpr const wchar_t* kAppsRootKeyPath = L"Software\\Valve\\Steam\\Apps";
constexpr const wchar_t* kActiveProcessKeyPath = L"Software\\Valve\\Steam\\ActiveProcess";
constexpr const wchar_t* kValueActiveUser = L"ActiveUser";
constexpr const wchar_t* kValueUniverse = L"Universe";

std::wstring SteamAppKeyPath(uint32_t appId) {
    return L"Software\\Valve\\Steam\\Apps\\" + std::to_wstring(appId);
}

const char* ValueNameForLog(PCWSTR valueName) {
    if (valueName == kValueSteamId) return "SteamID";
    if (valueName == kValueAppTicket) return "AppTicket";
    if (valueName == kValueEncryptedTicket) return "ETicket";
    if (valueName == kValueActiveUser) return "ActiveUser";
    if (valueName == kValueUniverse) return "Universe";
    return "?";
}

Status FromLStatus(LSTATUS status) {
    switch (status) {
    case ERROR_SUCCESS:
        return Status::Ok;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_NOT_FOUND:
        return Status::NotFound;
    default:
        return Status::Failed;
    }
}

// RegGetValueW does the size-dance for us: first call (pvData == nullptr)
// reports the byte count, second fills the buffer. `out` is overwritten only on
// success; left untouched on any failure.
LSTATUS ReadBinaryValue(uint32_t appId, PCWSTR valueName, std::vector<uint8_t>& out) {
    const std::wstring keyPath = SteamAppKeyPath(appId);

    DWORD bytes = 0;
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), valueName,
                                  RRF_RT_REG_BINARY, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: {} missing for appid={} status={}",
                           ValueNameForLog(valueName), appId, status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to query {} size for appid={} status={}",
                          ValueNameForLog(valueName), appId, status);
        }
        return status;
    }
    if (bytes == 0) {
        OSTP_LOG_DEBUG("SteamCredentialStore: {} empty for appid={}", ValueNameForLog(valueName), appId);
        out.clear();
        return ERROR_SUCCESS;
    }

    std::vector<uint8_t> buffer(bytes);
    status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), valueName,
                          RRF_RT_REG_BINARY, nullptr, buffer.data(), &bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to read {} for appid={} status={}",
                      ValueNameForLog(valueName), appId, status);
        return status;
    }

    buffer.resize(bytes);
    out = std::move(buffer);
    OSTP_LOG_DEBUG("SteamCredentialStore: read {} for appid={} bytes={}",
                   ValueNameForLog(valueName), appId, out.size());
    return ERROR_SUCCESS;
}

// Create-or-open the per-app key and set a single value. REG_OPTION_NON_VOLATILE
// + KEY_SET_VALUE mirrors what Steam itself uses for these credential entries.
LSTATUS WriteValue(uint32_t appId, PCWSTR valueName, DWORD type, const BYTE* data, DWORD bytes) {
    Windows::UniqueRegKey key;
    LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, SteamAppKeyPath(appId).c_str(), 0, nullptr,
                                     REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, key.put(), nullptr);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to create/open app key appid={} status={}", appId, status);
        return status;
    }

    status = RegSetValueExW(key.get(), valueName, 0, type, data, bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to write {} for appid={} bytes={} status={}",
                      ValueNameForLog(valueName), appId, bytes, status);
        return status;
    }

    OSTP_LOG_INFO("SteamCredentialStore: wrote {} for appid={} bytes={}",
                  ValueNameForLog(valueName), appId, bytes);
    return ERROR_SUCCESS;
}

} // namespace

const char* ToString(Status status) {
    switch (status) {
    case Status::Ok: return "Ok";
    case Status::NotFound: return "NotFound";
    case Status::Unsupported: return "Unsupported";
    case Status::Failed: return "Failed";
    }
    return "Unknown";
}

Status GetAppTicket(uint32_t appId, std::vector<uint8_t>& ticket) {
    return FromLStatus(ReadBinaryValue(appId, kValueAppTicket, ticket));
}

Status WriteAppTicket(uint32_t appId, const std::vector<uint8_t>& data) {
    return FromLStatus(WriteValue(appId, kValueAppTicket, REG_BINARY,
                                  reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size())));
}

Status GetETicket(uint32_t appId, std::vector<uint8_t>& ticket) {
    return FromLStatus(ReadBinaryValue(appId, kValueEncryptedTicket, ticket));
}

Status WriteETicket(uint32_t appId, const std::vector<uint8_t>& data) {
    return FromLStatus(WriteValue(appId, kValueEncryptedTicket, REG_BINARY,
                                  reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size())));
}

Status GetSteamId(uint32_t appId, uint64_t& steamId) {
    const std::wstring keyPath = SteamAppKeyPath(appId);

    DWORD bytes = 0;
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), kValueSteamId,
                                  RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: SteamID missing for appid={} status={}", appId, status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to query SteamID size for appid={} status={}", appId, status);
        }
        return mapped;
    }
    if (bytes < sizeof(wchar_t)) {
        OSTP_LOG_WARN("SteamCredentialStore: SteamID value too short for appid={} bytes={}", appId, bytes);
        return Status::NotFound;
    }

    std::wstring raw(bytes / sizeof(wchar_t), L'\0');
    status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), kValueSteamId,
                          RRF_RT_REG_SZ, nullptr, raw.data(), &bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to read SteamID for appid={} status={}", appId, status);
        return FromLStatus(status);
    }

    // RegGetValueW guarantees a single null terminator and counts it in `bytes`;
    // drop it so the parser sees only digits.
    const size_t chars = bytes / sizeof(wchar_t);
    raw.resize(chars > 0 ? chars - 1 : 0);

    // A present-but-empty/zero/unparseable value is treated as "no credential".
    const auto parsed = Numbers::ParseUInt64(raw);
    if (!parsed || *parsed == 0) {
        OSTP_LOG_WARN("SteamCredentialStore: SteamID value invalid for appid={}", appId);
        return Status::NotFound;
    }

    steamId = *parsed;
    OSTP_LOG_DEBUG("SteamCredentialStore: read SteamID for appid={} steamid={}", appId, steamId);
    return Status::Ok;
}

Status WriteSteamId(uint32_t appId, uint64_t steamId) {
    const std::wstring value = std::to_wstring(steamId);
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return FromLStatus(WriteValue(appId, kValueSteamId, REG_SZ,
                                  reinterpret_cast<const BYTE*>(value.c_str()), bytes));
}

// Subkey scan of HKCU\Software\Valve\Steam\Apps. Steam itself writes one key
// per app that has credentials (tickets / SteamID), so this doubles as "apps
// this account has locally usable ticket material for". Bounded in both entry
// count and name length so a corrupted hive cannot stall the caller.
Status EnumerateAppIds(std::vector<uint32_t>& appIds) {
    appIds.clear();

    Windows::UniqueRegKey key;
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, kAppsRootKeyPath, 0,
                                   KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, key.put());
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: Apps key missing status={}", status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to open Apps key status={}", status);
        }
        return mapped;
    }

    constexpr DWORD kMaxEntries = 4096;
    constexpr DWORD kMaxNameChars = 64;
    for (DWORD index = 0; index < kMaxEntries; ++index) {
        wchar_t name[kMaxNameChars];
        DWORD nameChars = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
        status = RegEnumKeyExW(key.get(), index, name, &nameChars,
                               nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) {
            OSTP_LOG_WARN("SteamCredentialStore: Apps enumeration stopped at index={} status={}", index, status);
            break;
        }

        const auto parsed = Numbers::ParseUInt32(std::wstring_view(name, nameChars));
        if (!parsed || *parsed == 0) continue;
        appIds.push_back(*parsed);
    }

    OSTP_LOG_DEBUG("SteamCredentialStore: enumerated {} app credential keys", appIds.size());
    return Status::Ok;
}

Status GetActiveUser(uint32_t& accountId, std::wstring& universe) {
    DWORD activeUser = 0;
    DWORD bytes = sizeof(activeUser);
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, kActiveProcessKeyPath, kValueActiveUser,
                                  RRF_RT_REG_DWORD, nullptr, &activeUser, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: ActiveUser missing status={}", status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to read ActiveUser status={}", status);
        }
        return mapped;
    }
    if (bytes != sizeof(activeUser)) {
        OSTP_LOG_WARN("SteamCredentialStore: ActiveUser has unexpected size bytes={}", bytes);
        return Status::NotFound;
    }
    if (activeUser == 0) {
        OSTP_LOG_DEBUG("SteamCredentialStore: ActiveUser is zero");
        return Status::NotFound;
    }

    bytes = 0;
    status = RegGetValueW(HKEY_CURRENT_USER, kActiveProcessKeyPath, kValueUniverse,
                          RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: ActiveProcess Universe missing status={}", status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to query ActiveProcess Universe size status={}", status);
        }
        return mapped;
    }
    if (bytes < sizeof(wchar_t)) {
        OSTP_LOG_WARN("SteamCredentialStore: ActiveProcess Universe value too short bytes={}", bytes);
        return Status::NotFound;
    }

    std::wstring rawUniverse(bytes / sizeof(wchar_t), L'\0');
    status = RegGetValueW(HKEY_CURRENT_USER, kActiveProcessKeyPath, kValueUniverse,
                          RRF_RT_REG_SZ, nullptr, rawUniverse.data(), &bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to read ActiveProcess Universe status={}", status);
        return FromLStatus(status);
    }

    const size_t chars = bytes / sizeof(wchar_t);
    rawUniverse.resize(chars > 0 ? chars - 1 : 0);
    if (rawUniverse.empty()) {
        OSTP_LOG_WARN("SteamCredentialStore: ActiveProcess Universe is empty");
        return Status::NotFound;
    }

    accountId = activeUser;
    universe = std::move(rawUniverse);
    OSTP_LOG_DEBUG("SteamCredentialStore: read ActiveUser accountid={} universe={}({} chars)",
                   accountId, Encoding::WideToUtf8(universe), universe.size());
    return Status::Ok;
}

} // namespace OSTPlatform::SteamCredentialStore
