#include "Hook/Hooks_NetPacket.h"
#include "Hook/Hooks_Package.h"
#include "Utils/Config/Config.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Config/LuaFileWatcher.h"
#include "Utils/Config/ConfigFileWatcher.h"
#include "Utils/Logging/Log.h"
#include "Utils/Tickets/TicketAuthority.h"
#include "OSTPlatform/include/DirectoryWatch.h"

#include <atomic>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ConfigFileWatcher {
namespace {

std::atomic<bool> g_running{false};
std::thread g_watcherThread;
std::string g_configPath;
std::string g_defaultLuaDir;

constexpr uint32_t kDebounceMs = 500;

bool SameFileName(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(lhs[i])) !=
            std::tolower(static_cast<unsigned char>(rhs[i]))) {
            return false;
        }
    }
    return true;
}

bool ContainsConfigChange(
    const std::vector<OSTPlatform::DirectoryWatch::Change>& changes,
    std::string_view targetFileName) {
    for (const auto& change : changes) {
        if (SameFileName(change.relativePath, targetFileName)) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> BuildLuaWatchDirs() {
    return LuaConfig::MergeWatchDirs(Config::GetLuaPaths(), g_defaultLuaDir);
}

void RestartLuaWatcher() {
    std::vector<std::string> watchDirs = BuildLuaWatchDirs();

    LuaFileWatcher::Stop();
    LuaConfig::ReloadDirectories(watchDirs);
    LuaFileWatcher::Start(watchDirs);

    // The managed app set changed: cached ticket decisions may no longer apply.
    TicketAuthority::Reset();

    Hooks_Package::NotifyLicenseChanged();
    LOG_INFO("Lua directories refreshed after config reload: {}", static_cast<uint32_t>(watchDirs.size()));
}

// ── manifest probe request file ──────────────────────────────────────────────
// Diagnostic only. Drop depot ids, one per line, into manifest_probe.txt beside
// opensteamtool.toml and each is turned into an originated
// GetManifestRequestCode; results land in manifest.log.
//
// It shares this watcher rather than starting its own because the file sits in
// the directory already being watched, so it costs one filename comparison.
// Being file-driven means probes can be re-run without restarting Steam, which
// matters because a restart truncates every log.
constexpr std::string_view kProbeFileName = "manifest_probe.txt";

void ProcessProbeFile() {
    const std::filesystem::path path =
        std::filesystem::path(g_configPath).parent_path() / kProbeFileName;

    std::ifstream in(path);
    if (!in) return;

    uint32_t requested = 0, accepted = 0;
    std::string line;
    while (std::getline(in, line)) {
        // Tolerate comments, blank lines and stray whitespace/CR.
        const size_t hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        const size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        const size_t last = line.find_last_not_of(" \t\r\n");
        line = line.substr(first, last - first + 1);

        uint32_t depotId = 0;
        if (std::from_chars(line.data(), line.data() + line.size(), depotId).ec != std::errc{} ||
            depotId == 0) {
            LOG_WARN("manifest_probe: ignoring unparseable line \"{}\"", line);
            continue;
        }

        ++requested;
        if (Hooks_NetPacket::ProbeManifest(depotId)) ++accepted;
    }

    LOG_INFO("manifest_probe: {} depot(s) read, {} request(s) sent", requested, accepted);
}

void ReloadConfig() {
    LOG_INFO("Reloading config: {}", g_configPath);

    const Config::LoadResult result = Config::Load(g_configPath);
    if (!result.applied) {
        LOG_WARN("Config reload skipped; keeping previous valid config");
        return;
    }

    Log::ApplyConfigLevel();

    if (result.luaPathsChanged) {
        RestartLuaWatcher();
    }
}

void WatcherThread() {
    const std::filesystem::path configPath(g_configPath);
    const std::filesystem::path dirPath = configPath.parent_path();
    const std::string targetFileName = configPath.filename().string();

    OSTPlatform::DirectoryWatch::Watch watch;
    if (!watch.Open(dirPath.string(), 4096)) {
        LOG_WARN("Failed to open config watch directory: {}", dirPath.string());
        return;
    }
    if (!watch.IssueRead()) {
        return;
    }

    LOG_INFO("Watching config file: {}", g_configPath);

    OSTPlatform::DirectoryWatch::Watch* watchPtr = &watch;
    std::vector<OSTPlatform::DirectoryWatch::Watch*> watches{watchPtr};

    // Two files are watched in this directory now, so a drain reports which of
    // them moved rather than a single bool.
    struct Touched { bool config = false; bool probe = false; };

    auto drainEvent = [&]() {
        const auto changes = watch.Drain();
        Touched touched;
        touched.config = ContainsConfigChange(changes, targetFileName);
        touched.probe  = ContainsConfigChange(changes, kProbeFileName);
        watch.IssueRead();
        return touched;
    };

    while (g_running) {
        auto waitResult = OSTPlatform::DirectoryWatch::WaitAny(watches, 1000);

        if (!g_running) break;
        if (waitResult.status == OSTPlatform::DirectoryWatch::WaitStatus::Timeout) continue;
        if (waitResult.status != OSTPlatform::DirectoryWatch::WaitStatus::Signaled) continue;

        Touched touched = drainEvent();
        while (g_running) {
            auto debounceResult = OSTPlatform::DirectoryWatch::WaitAny(watches, kDebounceMs);
            if (!g_running) break;
            if (debounceResult.status == OSTPlatform::DirectoryWatch::WaitStatus::Timeout) break;
            if (debounceResult.status != OSTPlatform::DirectoryWatch::WaitStatus::Signaled) break;
            const Touched more = drainEvent();
            touched.config = touched.config || more.config;
            touched.probe  = touched.probe  || more.probe;
        }

        if (touched.config) {
            ReloadConfig();
        }
        if (touched.probe) {
            ProcessProbeFile();
        }
    }

    watch.Cancel();
    LOG_INFO("Config watcher stopped");
}

} // namespace

void Start(const std::string& configPath, const std::string& defaultLuaDir) {
    if (g_running.exchange(true)) {
        LOG_WARN("Config watcher already running");
        return;
    }

    g_configPath = configPath;
    g_defaultLuaDir = defaultLuaDir;
    g_watcherThread = std::thread(WatcherThread);
}

void Stop() {
    if (!g_running) return;
    g_running = false;
    if (g_watcherThread.joinable()) {
        g_watcherThread.join();
    }
}

} // namespace ConfigFileWatcher
