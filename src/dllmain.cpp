#include "dllmain.h"
#include "Hook/HookManager.h"
#include "Utils/Config/Config.h"
#include "Utils/Config/ConfigFileWatcher.h"
#include "Utils/Config/LuaFileWatcher.h"
#include "Utils/CloudRedirect/CloudRedirectHost.h"
#include "Utils/SteamMetadata/IPCLoader.h"
#include "Utils/SteamMetadata/ManifestDonor.h"
#include "Utils/SteamMetadata/PatternLoader.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"
#include "Utils/Tokeer/TokeerBridge.h"
#ifdef OST_ENABLE_UPDATER
#include "Utils/Update/AppUpdater.h"
#endif
#include "OSTPlatform/include/Dialog.h"
#include "OSTPlatform/include/DynamicLibrary.h"
#include "OSTPlatform/include/Encoding.h"
#include "OSTPlatform/include/Thread.h"

#include <string>
#include <windows.h>

// prepare key runtime paths.
//
// Diversion shadow module: steamclient64.dll is copied to <Steam>\bin\diversion64.dll
// and the COPY is loaded and hooked, so the original module stays untouched in
// memory. Callers that ask for "steamclient64.dll" are redirected to the copy
// (see Hooks_SteamUI.cpp). If the copy or load fails, the original is loaded
// unchanged ("Diversion inactive") - the process must always end up with a
// working client module.
bool InitializeSteamComponents(OSTPlatform::DynamicLibrary::ModuleHandle selfModule)
{
    auto steamExeDir = OSTPlatform::DynamicLibrary::GetModuleDirectory(nullptr);
    std::string steamInstallPath = OSTPlatform::Encoding::WideToUtf8(steamExeDir.wstring());
    if (steamInstallPath.empty()) {
        steamInstallPath = OSTPlatform::DynamicLibrary::GetCurrentDirectoryPath();
    }
    if (steamInstallPath.empty()) {
        return false;
    }
    sprintf_s(SteamInstallPath, kRuntimePathCapacity, "%s", steamInstallPath.c_str());
    sprintf_s(SteamclientPath, kRuntimePathCapacity, "%s\\steamclient64.dll",    SteamInstallPath);
    sprintf_s(SteamUIPath,     kRuntimePathCapacity, "%s\\steamui.dll",          SteamInstallPath);
    sprintf_s(DiversionPath,   kRuntimePathCapacity, "%s\\bin\\diversion64.dll", SteamInstallPath);
    sprintf_s(LuaDir,          kRuntimePathCapacity, "%s\\config\\stplug-in",    SteamInstallPath);
    sprintf_s(ConfigPath,      kRuntimePathCapacity, "%s\\opensteamtool.toml",   SteamInstallPath);

    auto dllDir = OSTPlatform::DynamicLibrary::GetModuleDirectory(selfModule);
    std::string dllPath = OSTPlatform::Encoding::WideToUtf8(dllDir.wstring());
    if (dllPath.empty()) {
        dllPath = steamInstallPath;
    }
    sprintf_s(DllDir, kRuntimePathCapacity, "%s", dllPath.c_str());

    // Diversion shadow module cloning & loading:
    // Clone steamclient64.dll into bin\diversion64.dll so all hooks and patches
    // are isolated to the diversion module while original steamclient64.dll stays 100% clean.
    WIN32_FILE_ATTRIBUTE_DATA origAttr{}, divAttr{};
    const std::wstring wideSteamclientPath = OSTPlatform::Encoding::Utf8ToWide(SteamclientPath);
    const std::wstring wideDiversionPath   = OSTPlatform::Encoding::Utf8ToWide(DiversionPath);
    const std::wstring wideSteamUIPath     = OSTPlatform::Encoding::Utf8ToWide(SteamUIPath);

    const bool origExists = GetFileAttributesExW(wideSteamclientPath.c_str(), GetFileExInfoStandard, &origAttr) != 0;
    const bool divExists  = GetFileAttributesExW(wideDiversionPath.c_str(), GetFileExInfoStandard, &divAttr) != 0;

    bool isUpToDate = false;
    if (origExists && divExists) {
        if (origAttr.nFileSizeHigh == divAttr.nFileSizeHigh &&
            origAttr.nFileSizeLow  == divAttr.nFileSizeLow &&
            origAttr.ftLastWriteTime.dwLowDateTime  == divAttr.ftLastWriteTime.dwLowDateTime &&
            origAttr.ftLastWriteTime.dwHighDateTime == divAttr.ftLastWriteTime.dwHighDateTime)
        {
            isUpToDate = true;
        }
    }

    bool copyOk = isUpToDate;
    if (isUpToDate) {
        LOG_DEBUG("Diversion module is already up to date ({}), skipping copy", DiversionPath);
    } else {
        std::filesystem::path diversionFsPath(wideDiversionPath);
        std::error_code ec;
        std::filesystem::create_directories(diversionFsPath.parent_path(), ec);
        if (divExists && (divAttr.dwFileAttributes & FILE_ATTRIBUTE_READONLY)) {
            SetFileAttributesW(wideDiversionPath.c_str(), FILE_ATTRIBUTE_NORMAL);
        }

        // Retry up to 3 times in case the old Steam process is still releasing the file handle
        constexpr int kMaxCopyRetries = 3;
        DWORD gle = ERROR_SUCCESS;
        for (int attempt = 1; attempt <= kMaxCopyRetries; ++attempt) {
            if (CopyFileW(wideSteamclientPath.c_str(), wideDiversionPath.c_str(), FALSE)) {
                copyOk = true;
                LOG_INFO("Cloned steamclient64.dll -> {}", DiversionPath);
                break;
            }
            gle = GetLastError();
            if (gle != ERROR_SHARING_VIOLATION && gle != ERROR_ACCESS_DENIED) {
                break;
            }
            if (attempt < kMaxCopyRetries) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }

        if (!copyOk) {
            LOG_WARN("CopyFileW to diversion64.dll failed after {} attempts (err={})", kMaxCopyRetries, gle);
        }
    }

    if (copyOk) {
        client_hModule = OSTPlatform::DynamicLibrary::Load(std::filesystem::path(wideDiversionPath));
        if (client_hModule) {
            g_IsDiversionActive.store(true, std::memory_order_release);
            LOG_INFO("Loaded diversion module from {}", DiversionPath);
        } else {
            LOG_WARN("Load diversion module failed (path={}, err={}), falling back to real steamclient64.dll",
                     DiversionPath, OSTPlatform::DynamicLibrary::GetLastErrorCode());
        }
    }

    if (!client_hModule) {
        g_IsDiversionActive.store(false, std::memory_order_release);
        client_hModule = OSTPlatform::DynamicLibrary::Load(std::filesystem::path(wideSteamclientPath));
        if (!client_hModule) {
            LOG_ERROR("Load steamclient64.dll failed: {} (err={})",
                      SteamclientPath, OSTPlatform::DynamicLibrary::GetLastErrorCode());
            return false;
        }
        LOG_INFO("Loaded fallback steamclient64.dll from {} (Diversion inactive)", SteamclientPath);
    }

    ui_hModule = OSTPlatform::DynamicLibrary::Load(std::filesystem::path(wideSteamUIPath));
    if(!ui_hModule) {
        LOG_ERROR("Load failed for steamui.dll: err={}", OSTPlatform::DynamicLibrary::GetLastErrorCode());
        return false;
    }
    return true;
}

// All initialisation that touches the filesystem, loads modules, scans
// memory, or installs detours runs here on a worker thread — we MUST NOT do
// any of that from inside DllMain (loader lock).
static uint32_t InitThread(OSTPlatform::DynamicLibrary::ModuleHandle selfModule) {
    Log::Init(selfModule);
    LOG_INFO("OpenSteamTool init thread started");

    if (!InitializeSteamComponents(selfModule)) {
        LOG_ERROR("InitializeSteamComponents failed");
        // Release the SteamUI LoadModuleWithPath waiters; nothing else will.
        g_HooksInstalled.store(true, std::memory_order_release);
        return 1;
    }

    Config::Load(ConfigPath);
    Log::InitModules();
    Log::InstallPlatformLogSink();
    SteamDiagnostics::Initialize(SteamclientPath, SteamUIPath);

    // Load pattern files for steamclient64.dll and steamui.dll.
    // Each call computes the SHA-256 of the DLL on disk, checks the local
    // cache, and downloads from GitHub if needed.  Both calls are synchronous
    // but run on this worker thread, never under the loader lock.
    PatternLoader::Load(ui_hModule, SteamUIPath, "steamui");
    PatternLoader::Load(client_hModule, SteamclientPath, "steamclient");

    // Install SteamUI hooks early so LoadModuleWithPath can intercept
    // and synchronize with client hook installation.
    SteamUI::CoreHook();

    // IPC method metadata (funcHash, fencepost, argc, ...)
    IPCLoader::Load(SteamclientPath);

    std::vector<std::string> watchDirs =
        LuaConfig::MergeWatchDirs(Config::GetLuaPaths(), std::string(LuaDir));
    for (const auto& dir : watchDirs)
        LuaConfig::ParseDirectory(dir);

    LuaFileWatcher::Start(watchDirs);
    ConfigFileWatcher::Start(ConfigPath, LuaDir);

    SteamClient::CoreHook();

    // Surface any functions that FindPattern() could not locate.
    PatternLoader::ReportMissingFunctions();

    // Optional Steam Cloud save redirection (CloudRedirect). No-op unless
    // [cloud].enabled is set and cloud_redirect.dll is present.
    CloudRedirectHost::Initialize(SteamInstallPath);

    // Contributes manifest request codes for depots this account owns, on
    // request. Started after the hooks are in place because it needs the
    // netpacket send path; it idles until the license list resolves anyway.
    ManifestDonor::Start();

    // Register the bst:// URI scheme so the website can drive code redemption via this
    // DLL (rundll32 handler). HKCU, no admin; idempotent.
    TokeerBridge::RegisterUriScheme(std::string(SteamInstallPath) + "\\OpenSteamTool.dll");

    // Optional self-update check. Runs on its own detached thread so the network
    // round-trip never delays hook installation; a staged DLL applies next launch.
    //
    // Compiled out entirely by -DOST_ENABLE_UPDATER=OFF. That is deliberately a
    // build-time cut rather than a runtime one: a pinned or private build should
    // not be replaceable by flipping [update] in opensteamtool.toml, and with the
    // updater absent the DLL makes no update request at all.
#ifdef OST_ENABLE_UPDATER
    if (Config::GetUpdateEnabled()) {
        OSTPlatform::Thread::StartDetached([] () -> uint32_t {
            const std::string self = std::string(SteamInstallPath) + "\\OpenSteamTool.dll";
            AppUpdater::CleanupStagedBackup(self);

            const AppUpdater::CheckResult upd = AppUpdater::Check();
            if (!upd.updateAvailable) return 0;
            if (!AppUpdater::DownloadAndStage(upd, self)) return 0;

            const bool restart = OSTPlatform::Dialog::ShowConfirm(
                "BetterSteamTools Updated!",
                upd.oldVersion + " -> " + upd.newVersion +
                "\n\nRestart Steam now to apply?");
            if (restart) AppUpdater::RestartSteam();
            return 0;
        });
    }
#else
    LOG_INFO("Self-updater not compiled in (OST_ENABLE_UPDATER=OFF)");
#endif

    g_HooksInstalled.store(true, std::memory_order_release);
    LOG_INFO("OpenSteamTool init complete ({})",
             g_IsDiversionActive.load(std::memory_order_acquire)
                 ? "Diversion active"
                 : "Diversion bypassed, using original steamclient64");
    return 0;
}

// True only when the host process is steam.exe. The proxy DLLs already gate injection to
// Steam, but rundll32 loads this DLL directly to service a bst:// link — there we must NOT
// run the Steam-injection machinery (steamclient load, hooks, watchers); the TokeerUri
// export does its work standalone.
static bool IsSteamHost()
{
    char exePath[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, exePath, MAX_PATH)) return false;
    const char* name = strrchr(exePath, '\\');
    name = name ? name + 1 : exePath;
    return _stricmp(name, "steam.exe") == 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        if (!IsSteamHost())
            return TRUE;   // e.g. rundll32 bst:// handler — no injection here

        // Keep this module pinned so an explicit FreeLibrary cannot unload code
        // while hooks and worker threads may still reference it.
        HMODULE pinnedModule = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCSTR>(&DllMain), &pinnedModule);

        // Hand off all real work to a worker thread to avoid running file I/O,
        // module loading and detour transactions under the loader lock.
        OSTPlatform::Thread::StartDetached([module = reinterpret_cast<OSTPlatform::DynamicLibrary::ModuleHandle>(hModule)] {
            return InitThread(module);
        });
    }
    else if (dwReason == DLL_PROCESS_DETACH && IsSteamHost())
    {
        g_HooksInstalled.store(false, std::memory_order_release);
        g_IsDiversionActive.store(false, std::memory_order_release);

        // When pvReserved != nullptr the process is terminating: all other
        // threads are already gone and detour cleanup / thread joins under the
        // loader lock can deadlock. Skip cleanup; the OS reclaims everything.
        if (pvReserved == nullptr) {
            ConfigFileWatcher::Stop();
            LuaFileWatcher::Stop();
            SteamUI::CoreUnhook();
            SteamClient::CoreUnhook();
            CloudRedirectHost::Shutdown();
        }
    }

    return TRUE;
}
