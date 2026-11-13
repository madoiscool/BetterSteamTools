#include "RemoteToml.h"
#include "OSTPlatform/include/Http.h"
#include "Utils/Config/Config.h"
#include "Utils/Logging/Log.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string_view>
#include <thread>
#include <vector>

namespace RemoteToml {

namespace {
    // Built-in mirror chain, tried in order. Used when [remote] url_template is unset.
    // Mirrors are independent repos/hosts (not just CDN copies of one repo).
    // jsDelivr is first on purpose: raw.githubusercontent.com is unreachable on a
    // lot of networks (returns HTTP=0 and only times out after several seconds),
    // which used to stall startup ~8s per component before falling through — long
    // enough that Steam built depot configs before our hooks installed. Lead with
    // the CDN that actually answers and keep GitHub raw as a last resort.
    constexpr const char* kDefaultTemplates[] = {
        "https://cdn.jsdelivr.net/gh/madoiscool/steam-monitor@{channel}/{component}/{sha256}.toml",
        "https://git.lua.tools/luatools/steam-monitor/raw/branch/{channel}/{component}/{sha256}.toml",
        "https://raw.githubusercontent.com/madoiscool/steam-monitor/{channel}/{component}/{sha256}.toml",
    };

    static bool HasPlaceholder(std::string_view text, std::string_view placeholder)
    {
        return text.find(placeholder) != std::string_view::npos;
    }

    static bool IsValidTemplate(std::string_view urlTemplate)
    {
        return HasPlaceholder(urlTemplate, "{channel}") &&
               HasPlaceholder(urlTemplate, "{component}") &&
               HasPlaceholder(urlTemplate, "{sha256}");
    }

    static void ReplaceAll(std::string& text,
                           std::string_view from,
                           std::string_view to)
    {
        size_t pos = 0;
        while ((pos = text.find(from, pos)) != std::string::npos) {
            text.replace(pos, from.size(), to);
            pos += to.size();
        }
    }

    static std::string ExpandTemplate(std::string urlTemplate,
                                      const Request& request,
                                      std::string_view sha256)
    {
        ReplaceAll(urlTemplate, "{channel}", request.channel);
        ReplaceAll(urlTemplate, "{component}", request.component);
        ReplaceAll(urlTemplate, "{sha256}", sha256);
        return urlTemplate;
    }

    static std::vector<std::string> BuildUrlTemplates()
    {
        const std::vector<std::string> configured = Config::GetRemoteUrlTemplates();
        if (configured.empty())
            return { std::begin(kDefaultTemplates), std::end(kDefaultTemplates) };

        // A configured list REPLACES the built-ins; keep only valid entries.
        std::vector<std::string> out;
        for (const std::string& tmpl : configured) {
            if (IsValidTemplate(tmpl))
                out.push_back(tmpl);
            else
                LOG_WARN("RemoteToml: remote.url_template entry missing "
                         "{{channel}}/{{component}}/{{sha256}}, skipping: {}", tmpl);
        }
        if (out.empty())
            LOG_WARN("RemoteToml: no valid remote.url_template entries; remote fetch disabled");
        return out;
    }

    // Runs the mirror chain for one component and writes the on-disk cache on a
    // 200. Returns the HTTP result of the last attempt. Used both for the
    // synchronous (no-cache) fetch and the detached background refresh.
    static OSTPlatform::Http::Result TryMirrors(Request request,
                                                std::string sha256,
                                                std::filesystem::path cachePath)
    {
        const std::vector<std::string> urlTemplates = BuildUrlTemplates();
        OSTPlatform::Http::Result http;
        std::string lastUrl;

        for (size_t i = 0; i < urlTemplates.size(); ++i) {
            lastUrl = ExpandTemplate(urlTemplates[i], request, sha256);
            LOG_INFO("RemoteToml({}/{}): downloading {}",
                     request.channel, request.component, lastUrl);

            // Short resolve/connect timeouts so a dead mirror (e.g. GitHub raw on a
            // blocked network) fails in a couple of seconds instead of the long
            // WinHTTP default, letting the chain reach a working mirror quickly.
            http = OSTPlatform::Http::Execute(L"GET", lastUrl.c_str(),
                                              nullptr, 0, nullptr,
                                              /*timeoutResolve*/ 2500,
                                              /*timeoutConnect*/ 2500,
                                              /*timeoutSend*/    5000,
                                              /*timeoutRecv*/    5000);

            if (http.ok && http.status == 200) break;

            if (i + 1 < urlTemplates.size()) {
                LOG_WARN("RemoteToml({}/{}): mirror failed ({} ok={} HTTP={}), trying next",
                         request.channel, request.component, lastUrl, http.ok, http.status);
            } else {
                LOG_WARN("RemoteToml({}/{}): mirror failed ({} ok={} HTTP={}), no more mirrors",
                         request.channel, request.component, lastUrl, http.ok, http.status);
            }
        }

        if (http.ok && http.status == 200 && !http.body.empty()) {
            std::ofstream ofs(cachePath, std::ios::binary);
            if (ofs) {
                ofs.write(http.body.data(),
                          static_cast<std::streamsize>(http.body.size()));
                LOG_INFO("RemoteToml({}/{}): cached to {}",
                         request.channel, request.component, cachePath.string());
            } else {
                LOG_WARN("RemoteToml({}/{}): could not open {} for writing",
                         request.channel, request.component, cachePath.string());
            }
        }
        return http;
    }
} // namespace

Result Fetch(const Request& request)
{
    namespace fs = std::filesystem;
    Result out;

    // 1. SHA-256 of the DLL.
    const auto hashStart = std::chrono::steady_clock::now();
    out.sha256 = SteamDiagnostics::Sha256Of(request.dllPath);
    const auto hashMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - hashStart).count();

    if (out.sha256.empty()) {
        LOG_WARN("RemoteToml({}/{}): Sha256OfFile failed for {} ({} ms)",
                 request.channel, request.component, request.dllPath, hashMs);
        return out;
    }
    LOG_INFO("RemoteToml({}/{}): sha256 = {} ({} ms)",
             request.channel, request.component, out.sha256, hashMs);

    // 2. Cache path & dir.
    fs::path steamRoot = fs::path(request.dllPath).parent_path();
    fs::path cacheDir  = steamRoot / "opensteamtool" / request.channel / request.component;
    fs::path cachePath = cacheDir / (out.sha256 + ".toml");
    const std::string cachePathText = cachePath.string();

    std::error_code mkdirEc;
    fs::create_directories(cacheDir, mkdirEc);
    if (mkdirEc) {
        LOG_WARN("RemoteToml({}/{}): could not create cache dir {} ({})",
                 request.channel, request.component, cacheDir.string(), mkdirEc.message());
    }

    // 3. Cache-first. If a TOML for this exact DLL sha is already on disk, use it
    //    immediately so hooks install without waiting on the network, then refresh
    //    the cache in the background for next launch. The cache key IS the sha, so a
    //    cached file is always valid for the running client; a pattern re-published
    //    for the same sha reaches the user one launch later, which is acceptable.
    //    (This window used to cost ~8s/component on networks that can't reach the
    //    first mirror, long enough for Steam to build depot configs unhooked.)
    {
        std::error_code ec;
        if (fs::exists(cachePath, ec) && fs::file_size(cachePath, ec) > 0) {
            std::ifstream ifs(cachePath, std::ios::binary);
            std::string buf((std::istreambuf_iterator<char>(ifs)),
                             std::istreambuf_iterator<char>());
            if (ifs && !buf.empty()) {
                out.body = std::move(buf);
                out.ok = true;
                out.fromCache = true;
                LOG_INFO("RemoteToml({}/{}): served from cache {}, refreshing in background",
                         request.channel, request.component, cachePathText);
                // Detached refresh — args copied by value; the thread only does an
                // HTTP GET and a file write, so it is safe past init scope.
                std::thread(TryMirrors, request, out.sha256, cachePath).detach();
                return out;
            }
            LOG_WARN("RemoteToml({}/{}): cache file unreadable/empty, fetching: {}",
                     request.channel, request.component, cachePathText);
        }
    }

    // 4. No usable cache → fetch synchronously (also writes the cache on success).
    OSTPlatform::Http::Result http = TryMirrors(request, out.sha256, cachePath);
    if (http.ok && http.status == 200 && !http.body.empty()) {
        out.body = std::move(http.body);
        out.ok = true;
        return out;
    }

    // 5. No cache and the fetch failed → degraded; caller handles popup.
    LOG_WARN("RemoteToml({}/{}): no source available (HTTP {})",
             request.channel, request.component, http.status);
    return out;
}

} // namespace RemoteToml
