#include "TokeerBridge.h"

#include "OSTPlatform/include/Dialog.h"
#include "OSTPlatform/include/Http.h"
#include "OSTPlatform/include/Numbers.h"
#include "OSTPlatform/include/SteamCredentialStore.h"
#include "Utils/Logging/Log.h"
#include "OSTPlatform/include/DynamicLibrary.h"

#include <windows.h>
#include <shellapi.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>

// Code-server base URL, baked in at build time. Empty by default so a public tree ships
// no deployment's backend; point a build at yours with:
//   cmake -B build -DOST_TOKEER_URL="https://luastools.xyz"
#ifndef OST_TOKEER_URL
#define OST_TOKEER_URL "https://luastools.xyz"
#endif

namespace TokeerBridge {

namespace {

    constexpr const char* kUriScheme = "bst";

    int HexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    std::optional<std::vector<uint8_t>> HexToBytes(std::string_view hex) {
        if (hex.empty() || (hex.size() % 2) != 0) return std::nullopt;
        std::vector<uint8_t> out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            const int hi = HexNibble(hex[i]);
            const int lo = HexNibble(hex[i + 1]);
            if (hi < 0 || lo < 0) return std::nullopt;
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        return out;
    }

    // Minimal "key":"value" string extraction from the server's flat JSON reply.
    bool JsonString(std::string_view body, std::string_view key, std::string& out) {
        const std::string needle = "\"" + std::string(key) + "\"";
        size_t k = body.find(needle);
        if (k == std::string_view::npos) return false;
        size_t colon = body.find(':', k + needle.size());
        if (colon == std::string_view::npos) return false;
        size_t q1 = body.find('"', colon + 1);
        if (q1 == std::string_view::npos) return false;
        size_t delim = body.find_first_of(",}", colon + 1);
        if (delim != std::string_view::npos && q1 > delim) return false;  // value was null/number
        size_t q2 = body.find('"', q1 + 1);
        if (q2 == std::string_view::npos) return false;
        out = std::string(body.substr(q1 + 1, q2 - q1 - 1));
        return true;
    }

    bool JsonTrue(std::string_view body, std::string_view key) {
        const std::string needle = "\"" + std::string(key) + "\"";
        size_t k = body.find(needle);
        if (k == std::string_view::npos) return false;
        size_t colon = body.find(':', k + needle.size());
        if (colon == std::string_view::npos) return false;
        return body.find("true", colon + 1) == body.find_first_not_of(" \t", colon + 1);
    }

    std::string TokeerBaseUrl() {
        std::string url = OST_TOKEER_URL;
        while (!url.empty() && url.back() == '/') url.pop_back();
        return url;
    }

    void Warn(const std::string& title, const std::string& msg) {
        OSTPlatform::Dialog::ShowWarning(title, msg);
    }

    // This DLL lives in the Steam root, so its own directory is the Steam dir.
    // (The rundll32 URI context never runs InitializeSteamComponents, so the
    // SteamInstallPath global is not set here — resolve from the module.)
    std::filesystem::path SteamDirFromSelf() {
        HMODULE self = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&SteamDirFromSelf), &self);
        if (!self) return {};
        return OSTPlatform::DynamicLibrary::GetModuleDirectory(
            reinterpret_cast<OSTPlatform::DynamicLibrary::ModuleHandle>(self));
    }

    // Delete a game's cached achievement schema so Steam re-fetches the current
    // one (picking up newly-added achievements and the sets/groups layout). arg
    // is an appid, or "all". The next stat request / achievement-page view pulls
    // a fresh copy; user unlock state (UserGameStats_*, a separate file) is never
    // touched.
    void RefreshAchievements(const std::string& arg) {
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path statsDir = SteamDirFromSelf() / "appcache" / "stats";
        if (statsDir.empty() || !fs::exists(statsDir, ec)) {
            Warn("BetterSteamTools", "Could not locate Steam's stats cache.");
            return;
        }

        size_t removed = 0;
        if (arg == "all") {
            for (fs::directory_iterator it(statsDir, ec), end; it != end && !ec; it.increment(ec)) {
                const std::string name = it->path().filename().string();
                if (name.rfind("UserGameStatsSchema_", 0) == 0 &&
                    it->path().extension() == ".bin" && fs::remove(it->path(), ec))
                    ++removed;
            }
        } else {
            const fs::path f = statsDir / ("UserGameStatsSchema_" + arg + ".bin");
            if (fs::remove(f, ec)) ++removed;
        }

        LOG_INFO("TokeerBridge: RefreshAchievements('{}') removed {} schema file(s)", arg, removed);
        OSTPlatform::Dialog::ShowInfo(
            "Achievements Refreshed",
            std::to_string(removed) + " achievement schema(s) cleared.\n\n"
            "Reopen the game's achievement page in Steam to pull the latest "
            "(including sets/groups). Your unlocks are untouched.");
    }

} // namespace

void Redeem(const std::string& code) {
    namespace CS = OSTPlatform::SteamCredentialStore;

    const std::string url = TokeerBaseUrl() + "/drm/redeem";
    const std::string reqBody = "{\"code\":\"" + code + "\"}";

    OSTPlatform::Http::Result r = OSTPlatform::Http::Execute(
        L"POST", url.c_str(), reqBody.data(), static_cast<uint32_t>(reqBody.size()),
        L"Content-Type: application/json\r\n",
        5000, 5000, 10000, 20000, 4u * 1024 * 1024);

    if (!r.ok || r.status != 200 || !JsonTrue(r.body, "success")) {
        std::string reason;
        if (!JsonString(r.body, "reason", reason) && !JsonString(r.body, "error", reason))
            reason = "Server error " + std::to_string(r.status);
        LOG_WARN("TokeerBridge: redeem failed (HTTP {}): {}", r.status, reason);
        Warn("BetterSteamTools", "Redeem failed:\n\n" + reason);
        return;
    }

    std::string appIdStr, appHex, etHex;
    JsonString(r.body, "app_id", appIdStr);
    JsonString(r.body, "appticket", appHex);
    JsonString(r.body, "eticket", etHex);

    const auto appId = OSTPlatform::Numbers::ParseUInt32(appIdStr);
    const auto appBytes = HexToBytes(appHex);
    const auto etBytes = HexToBytes(etHex);
    if (!appId || !appBytes || appBytes->empty() || !etBytes || etBytes->empty()) {
        LOG_WARN("TokeerBridge: redeem returned an incomplete/invalid ticket");
        Warn("BetterSteamTools", "The server returned an incomplete ticket.");
        return;
    }

    if (CS::WriteAppTicket(*appId, *appBytes) != CS::Status::Ok ||
        CS::WriteETicket(*appId, *etBytes) != CS::Status::Ok) {
        LOG_ERROR("TokeerBridge: failed to write tickets for app {}", *appId);
        Warn("BetterSteamTools", "Could not write the ticket to Steam.");
        return;
    }

    LOG_INFO("TokeerBridge: redeemed code for app {} ({} + {} bytes)",
             *appId, appBytes->size(), etBytes->size());

    const bool launchNow = OSTPlatform::Dialog::ShowConfirm(
        "Code Redeemed!",
        "Added app " + std::to_string(*appId) + " to your library.\n\nLaunch it now?");
    if (launchNow) {
        const std::string steamUrl = "steam://rungameid/" + std::to_string(*appId);
        ShellExecuteA(nullptr, "open", steamUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        LOG_INFO("TokeerBridge: launching app {} via {}", *appId, steamUrl);
    }
}

void HandleUri(const std::string& rawUrl) {
    LOG_INFO("TokeerBridge: HandleUri raw='{}'", rawUrl);

    // rundll32 does its own lightweight command-line parsing and does NOT strip quotes
    // from the trailing argument the way a normal EXE's argv would — since the registry
    // command wraps %1 in quotes ("...",TokeerUri "%1"), the literal quote characters
    // land inside lpszCmdLine. Strip a single wrapping pair (either quote style) plus
    // incidental whitespace before parsing.
    std::string url = rawUrl;
    size_t begin = url.find_first_not_of(" \t\r\n");
    size_t end = url.find_last_not_of(" \t\r\n");
    url = (begin == std::string::npos) ? "" : url.substr(begin, end - begin + 1);
    if (url.size() >= 2 &&
        ((url.front() == '"' && url.back() == '"') ||
         (url.front() == '\'' && url.back() == '\'')))
        url = url.substr(1, url.size() - 2);

    // Accept "bst://action/arg" (and a stray trailing slash). Strip the scheme.
    const std::string prefix = std::string(kUriScheme) + "://";
    if (url.rfind(prefix, 0) != 0) {
        LOG_WARN("TokeerBridge: ignoring non-{} URL (cleaned='{}')", kUriScheme, url);
        return;
    }
    std::string rest = url.substr(prefix.size());
    while (!rest.empty() && (rest.back() == '/' || rest.back() == '\r' ||
                             rest.back() == '\n' || rest.back() == ' '))
        rest.pop_back();

    const size_t slash = rest.find('/');
    const std::string action = rest.substr(0, slash);
    const std::string arg = (slash == std::string::npos) ? "" : rest.substr(slash + 1);

    if (action == "redeem") {
        if (!arg.empty()) Redeem(arg);
        else Warn("BetterSteamTools", "Missing code in link.");
    } else if (action == "refreshachievements") {
        RefreshAchievements(arg.empty() ? "all" : arg);
    } else {
        LOG_WARN("TokeerBridge: unknown action '{}'", action);
    }
}

void RegisterUriScheme(const std::string& dllPath) {
    // HKCU\Software\Classes\bst  (URL Protocol) ; \shell\open\command -> rundll32 handler.
    const std::string command =
        "rundll32.exe \"" + dllPath + "\",TokeerUri \"%1\"";

    auto writeKey = [](const char* sub, const char* valueName, const std::string& value) -> bool {
        HKEY key{};
        if (RegCreateKeyExA(HKEY_CURRENT_USER, sub, 0, nullptr, 0,
                            KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
            return false;
        const LSTATUS s = RegSetValueExA(key, valueName, 0, REG_SZ,
                                         reinterpret_cast<const BYTE*>(value.c_str()),
                                         static_cast<DWORD>(value.size() + 1));
        RegCloseKey(key);
        return s == ERROR_SUCCESS;
    };

    const bool ok =
        writeKey("Software\\Classes\\bst", nullptr, "URL:BetterSteamTools") &&
        writeKey("Software\\Classes\\bst", "URL Protocol", "") &&
        writeKey("Software\\Classes\\bst\\shell\\open\\command", nullptr, command);

    if (ok) LOG_INFO("TokeerBridge: registered bst:// scheme -> {}", command);
    else    LOG_WARN("TokeerBridge: failed to register bst:// scheme");
}

} // namespace TokeerBridge
