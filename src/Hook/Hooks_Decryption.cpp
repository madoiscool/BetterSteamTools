#include "Hooks_Decryption.h"
#include "HookMacros.h"
#include "dllmain.h"
#include <string>

namespace {

    void* g_pConfigStoreLocal = nullptr;

    // AppIds of apptickets observed being read from the local user ConfigStore.
    // Populated by the ConfigStoreGetBinary hook; used by the forge fallback to
    // search for any available source ticket when appid 7 / 228980 are missing.
    std::unordered_set<AppId_t> g_seenAppTicketIds;

    HOOK_FUNC(ConfigStoreGetBinary, int32, void* pObject, EConfigStore eConfigStore, const char* KeyName, char* Key, uint32 KeySize) {
        if (eConfigStore == k_EConfigStoreUserLocal && pObject && !g_pConfigStoreLocal) {
            g_pConfigStoreLocal = pObject;
            LOG_DECRYPTIONKEY_DEBUG("ConfigStoreGetBinary: captured local ConfigStore at {}", g_pConfigStoreLocal);

        }
        std::string name(KeyName);
        LOG_DECRYPTIONKEY_DEBUG("ConfigStore::GetBinary called for pObject={}, eConfigStore={}, KeyName='{}'",
                                    pObject, static_cast<uint32>(eConfigStore), name);
        // Record any appticket key Steam reads from the local store so the forge
        // fallback can later search for any available source ticket.
        if (eConfigStore == k_EConfigStoreUserLocal) {
            const std::string kAppticketPrefix = "apptickets\\";
            if (name.rfind(kAppticketPrefix, 0) == 0) {
                const std::string rest = name.substr(kAppticketPrefix.size());
                if (!rest.empty() && rest.find_first_not_of("0123456789") == std::string::npos) {
                    g_seenAppTicketIds.insert(static_cast<AppId_t>(std::stoul(rest)));
                }
            }
        }
        // Expected shape: ".../<DepotId>\DecryptionKey"
        if (size_t last = name.find("\\DecryptionKey"); last != std::string::npos) {
            if (size_t start = name.find_last_of("\\", last - 1); start != std::string::npos) {
                AppId_t depotId = std::stoul(name.substr(start + 1, last - start - 1));
                if (const auto& key = LuaConfig::GetDecryptionKey(depotId); !key.empty()) {
                    if (KeySize >= key.size()) {
                        LOG_DECRYPTIONKEY_INFO("Providing decryption key for depot {}: {}", depotId,
                                               spdlog::to_hex(key.data(), key.data() + key.size()));
                        memcpy(Key, key.data(), key.size());
                        return static_cast<int32>(key.size());
                    }
                    LOG_DECRYPTIONKEY_WARN("Decryption key for depot {} is too large ({} bytes) for buffer ({} bytes)",
                                            depotId, key.size(), KeySize);
                }
            }
        }
        return oConfigStoreGetBinary(pObject, eConfigStore, KeyName, Key, KeySize);
    }

    std::vector<uint8_t> ReadConfigStoreLocalBinary(const std::string& keyName) {
        if (!g_pConfigStoreLocal || !oConfigStoreGetBinary) {
            LOG_DECRYPTIONKEY_WARN("GetConfigStoreLocalBinary: ConfigStoreGetBinary not ready, cannot get binary value");
            return {};
        }

        std::vector<uint8_t> value(1024);
        int32 result = oConfigStoreGetBinary(g_pConfigStoreLocal, k_EConfigStoreUserLocal,
                                             keyName.c_str(),
                                             reinterpret_cast<char*>(value.data()),
                                             static_cast<uint32>(value.size()));
        if (result <= 0) {
            LOG_DECRYPTIONKEY_DEBUG("GetConfigStoreLocalBinary: failed to read KeyName='{}'", keyName);
            return {};
        }

        value.resize(result);
        LOG_DECRYPTIONKEY_DEBUG("GetConfigStoreLocalBinary: got value for KeyName='{}' ({} bytes)",
                                keyName, value.size());
        return value;
    }
}

namespace Hooks_Decryption {
    void Install() {
        HOOK_BEGIN();
        INSTALL_HOOK_C(ConfigStoreGetBinary);
        HOOK_END();
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK_C(ConfigStoreGetBinary);
        UNHOOK_END();
    }

    std::vector<uint8_t> GetCacheAppOwnershipTicket(AppId_t appId) {
        std::vector<uint8_t> ticket = ReadConfigStoreLocalBinary(std::format("apptickets\\{}", appId));
        if (ticket.empty()) {
            LOG_DECRYPTIONKEY_DEBUG("no cached ticket for AppId {}", appId);
            return ticket;
        }
        LOG_DECRYPTIONKEY_DEBUG("got cached ticket for AppId {} ({} bytes)", appId, ticket.size());
        return ticket;
    }

    const std::unordered_set<AppId_t>& GetSeenAppTicketIds() {
        return g_seenAppTicketIds;
    }
}
