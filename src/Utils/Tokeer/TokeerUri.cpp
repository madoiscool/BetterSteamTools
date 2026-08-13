// rundll32 entry point for the bst:// URI scheme. Registered by
// TokeerBridge::RegisterUriScheme as:
//   rundll32.exe "<steam>\OpenSteamTool.dll",TokeerUri "%1"
// When a browser opens a bst:// link, Windows launches this in a short-lived rundll32
// process (NOT steam.exe), so the DLL's injection init never runs here — the bridge does
// all its work standalone (registry credential store + HTTP + clipboard).

#include "Utils/Tokeer/TokeerBridge.h"
#include "Utils/Logging/Log.h"
#include "OSTPlatform/include/DynamicLibrary.h"

#include <windows.h>

#include <string>

extern "C" __declspec(dllexport) void CALLBACK TokeerUri(HWND, HINSTANCE, LPSTR lpszCmdLine, int)
{
    // InitThread didn't run in this process, so Log::Main is unset — initialise logging
    // against this DLL's own directory first (a no-op in Release builds).
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&TokeerUri), &self);
    Log::Init(reinterpret_cast<OSTPlatform::DynamicLibrary::ModuleHandle>(self));

    TokeerBridge::HandleUri(lpszCmdLine ? std::string(lpszCmdLine) : std::string());
}
