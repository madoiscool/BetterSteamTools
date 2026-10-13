#ifndef DLLMAIN_H
#define DLLMAIN_H

#include "OSTPlatform/include/DynamicLibrary.h"

#include <string>
#include <fstream>
#include <filesystem>
#include <array>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <regex>
#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include <format>

#include "Steam/Types.h"
#include "Steam/Enums.h"
#include "Steam/Structs.h"
#include "Steam/Callback.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Logging/Log.h"
#include "Utils/Config/Config.h"


inline OSTPlatform::DynamicLibrary::ModuleHandle client_hModule = nullptr;
inline OSTPlatform::DynamicLibrary::ModuleHandle ui_hModule = nullptr;

// Diversion/startup synchronization: g_HooksInstalled is
// set when hook installation has completed (or failed); the SteamUI
// LoadModuleWithPath hook waits on it. g_IsDiversionActive is true while the
// cloned steamclient64.dll (bin\diversion64.dll) is the loaded client module.
inline std::atomic<bool> g_HooksInstalled{false};
inline std::atomic<bool> g_IsDiversionActive{false};

inline constexpr size_t kRuntimePathCapacity = 260;

inline char SteamInstallPath[kRuntimePathCapacity] = {};
inline char SteamclientPath[kRuntimePathCapacity]  = {};
inline char SteamUIPath[kRuntimePathCapacity]      = {};
inline char DiversionPath[kRuntimePathCapacity]    = {};
inline char LuaDir[kRuntimePathCapacity]           = {};
inline char ConfigPath[kRuntimePathCapacity]       = {};
inline char DllDir[kRuntimePathCapacity]           = {};

// The fake AppId used by -onlinefix (SpaceWar).
constexpr AppId_t kOnlineFixAppId = 480;

#endif // DLLMAIN_H
