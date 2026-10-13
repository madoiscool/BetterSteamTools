#include "Hook/Hooks_Package.h"
#include "Utils/Config/LuaFileWatcher.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/CloudRedirect/CloudRedirectHost.h"
#include "Utils/Logging/Log.h"
#include "Utils/Tickets/TicketAuthority.h"
#include "OSTPlatform/include/DirectoryWatch.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <thread>
#include <unordered_map>

namespace LuaFileWatcher {
namespace {

enum class ChangeAction {
    Added,
    Modified,
    Removed,
};

struct FileChange {
    std::string path;
    ChangeAction action = ChangeAction::Modified;
};

std::atomic<bool> g_running{false};
std::thread g_watcherThread;
std::vector<std::string> g_watchDirs;

constexpr uint32_t kDebounceMs = 500;

bool IsLuaFile(const std::string& path) {
    if (path.size() < 4) return false;
    return std::equal(path.end() - 4, path.end(), ".lua", [](char lhs, char rhs) {
        return std::tolower(static_cast<unsigned char>(lhs)) == std::tolower(static_cast<unsigned char>(rhs));
    });
}

ChangeAction FromPlatformAction(OSTPlatform::DirectoryWatch::ChangeAction action) {
    switch (action) {
    case OSTPlatform::DirectoryWatch::ChangeAction::Added:
    case OSTPlatform::DirectoryWatch::ChangeAction::RenamedNewName:
        return ChangeAction::Added;
    case OSTPlatform::DirectoryWatch::ChangeAction::Removed:
    case OSTPlatform::DirectoryWatch::ChangeAction::RenamedOldName:
        return ChangeAction::Removed;
    case OSTPlatform::DirectoryWatch::ChangeAction::Modified:
        return ChangeAction::Modified;
    }
    return ChangeAction::Modified;
}

const char* ToString(ChangeAction action) {
    switch (action) {
    case ChangeAction::Added: return "added";
    case ChangeAction::Modified: return "modified";
    case ChangeAction::Removed: return "removed";
    }
    return "modified";
}

void MergeChanges(
    std::unordered_map<std::string, ChangeAction>& accumulated,
    std::vector<std::string>& order,
    const std::vector<FileChange>& newChanges) {
    for (const auto& ch : newChanges) {
        if (!accumulated.contains(ch.path)) {
            order.push_back(ch.path);
        }
        accumulated[ch.path] = ch.action;
    }
}

std::vector<FileChange> FlattenChanges(
    const std::unordered_map<std::string, ChangeAction>& accumulated,
    const std::vector<std::string>& order) {
    std::vector<FileChange> changes;
    changes.reserve(order.size());
    for (const auto& path : order) {
        changes.push_back({path, accumulated.at(path)});
    }
    return changes;
}

std::vector<FileChange> ToFileChanges(
    const std::string& dir,
    const std::vector<OSTPlatform::DirectoryWatch::Change>& changes) {
    std::vector<FileChange> result;
    result.reserve(changes.size());
    for (const auto& change : changes) {
        if (change.relativePath.empty()) continue;
        result.push_back({dir + "\\" + change.relativePath, FromPlatformAction(change.action)});
    }
    return result;
}

void ProcessChanges(const std::vector<FileChange>& changes) {
    std::vector<FileChange> luaChanges;
    for (const auto& change : changes) {
        if (IsLuaFile(change.path)) {
            luaChanges.push_back(change);
        }
    }
    if (luaChanges.empty()) return;

    LOG_PACKAGE_DEBUG("Processing {} Lua file change(s)", luaChanges.size());
    for (const auto& change : luaChanges) {
        LOG_PACKAGE_TRACE("Lua file {}: {}", ToString(change.action), change.path);
        if (change.action == ChangeAction::Removed) {
            LuaConfig::UnloadFile(change.path);
        } else {
            LuaConfig::ParseFile(change.path);
        }
    }

    // App ids may have been added or removed: drop cached ticket decisions.
    TicketAuthority::Reset();

    Hooks_Package::NotifyLicenseChanged();
    CloudRedirectHost::SyncAppSet();
    LOG_PACKAGE_DEBUG("Lua refresh completed");
}

void WatcherThread() {
    const size_t numDirs = g_watchDirs.size();
    std::vector<OSTPlatform::DirectoryWatch::Watch> watches(numDirs);
    std::vector<OSTPlatform::DirectoryWatch::Watch*> watchPtrs(numDirs, nullptr);

    for (size_t i = 0; i < numDirs; ++i) {
        if (!watches[i].Open(g_watchDirs[i], 65536)) {
            LOG_PACKAGE_WARN("Failed to open Lua watch directory: {}", g_watchDirs[i]);
            continue;
        }
        if (!watches[i].IssueRead()) {
            watches[i].Cancel();
            continue;
        }

        watchPtrs[i] = &watches[i];
        LOG_PACKAGE_DEBUG("Watching Lua directory: {}", g_watchDirs[i]);
    }

    bool allFailed = true;
    for (auto* watch : watchPtrs) {
        if (watch && watch->IsOpen()) {
            allFailed = false;
            break;
        }
    }
    if (allFailed) {
        LOG_PACKAGE_WARN("No Lua watch directories could be opened");
        return;
    }

    auto drainEvent = [&](size_t idx,
                          std::unordered_map<std::string, ChangeAction>& accumulated,
                          std::vector<std::string>& order) {
        auto* watch = idx < watchPtrs.size() ? watchPtrs[idx] : nullptr;
        if (!watch || !watch->IsOpen()) return;

        MergeChanges(accumulated, order, ToFileChanges(g_watchDirs[idx], watch->Drain()));
        watch->IssueRead();
    };

    while (g_running) {
        auto waitResult = OSTPlatform::DirectoryWatch::WaitAny(watchPtrs, 1000);

        if (!g_running) break;
        if (waitResult.status == OSTPlatform::DirectoryWatch::WaitStatus::Timeout) continue;
        if (waitResult.status != OSTPlatform::DirectoryWatch::WaitStatus::Signaled ||
            waitResult.index >= numDirs) {
            continue;
        }

        std::unordered_map<std::string, ChangeAction> accumulated;
        std::vector<std::string> order;

        drainEvent(waitResult.index, accumulated, order);

        while (g_running) {
            auto debounceResult = OSTPlatform::DirectoryWatch::WaitAny(watchPtrs, kDebounceMs);
            if (!g_running) break;
            if (debounceResult.status == OSTPlatform::DirectoryWatch::WaitStatus::Timeout) break;
            if (debounceResult.status != OSTPlatform::DirectoryWatch::WaitStatus::Signaled ||
                debounceResult.index >= numDirs) {
                break;
            }
            drainEvent(debounceResult.index, accumulated, order);
        }

        if (!order.empty()) {
            ProcessChanges(FlattenChanges(accumulated, order));
        }
    }

    for (auto& watch : watches) {
        watch.Cancel();
    }
    LOG_PACKAGE_DEBUG("Lua watcher stopped");
}

} // namespace

void Start(const std::vector<std::string>& directories) {
    if (g_running.exchange(true)) {
        LOG_PACKAGE_WARN("Lua watcher already running");
        return;
    }

    g_watchDirs = directories;
    g_watcherThread = std::thread(WatcherThread);
}

void Stop() {
    if (!g_running) return;
    g_running = false;
    if (g_watcherThread.joinable()) {
        g_watcherThread.join();
    }
}

} // namespace LuaFileWatcher
