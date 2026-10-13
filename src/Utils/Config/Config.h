#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "Steam/Types.h"

namespace Config {

    enum class LogLevel { Trace, Debug, Info, Warn, Error };

    struct ManifestTimeouts {
        uint32_t resolve = 5000;
        uint32_t connect = 5000;
        uint32_t send    = 10000;
        uint32_t recv    = 10000;
    };

    // [[inject]] entry: a DLL loaded into a matching game process at the IPC handshake.
    struct InjectDll {
        std::string                 path;        // resolved absolute path
        std::string                 whenCmdline; // substring required in the game command line
        std::unordered_set<AppId_t> whenAppids;  // appids this entry applies to
        bool                        allGames = false;  // false: only Lua-unlocked games
    };

    // [tickets] - how the ownership-ticket reply is decided (TicketAuthority).
    struct TicketPolicy {
        bool                 preferStored        = true;  // answer with a validated stored ticket when one exists
        bool                 allowForge          = true;  // fall back to forging from a locally cached blob
        bool                 requireAppIdMatch   = true;  // stored tickets must embed the requested app id
        bool                 requireAccountMatch = true;  // forge bases must belong to the signed-in account
        bool                 scanCredentialStore = true;  // last resort: scan per-app credential keys
        bool                 allowMixedIdentity  = true;  // best-effort: serve the best available bytes even when the
                                                          // expected identity is another account (identity_mode="strict" refuses)
        bool                 vault               = true;  // keep a private copy of signed material under <Steam>/opensteamtool/vault
        bool                 allowBackend        = true;  // ask a configured ticket backend as the last resort
        bool                 report              = true;  // write opensteamtool/tickets.json
        std::vector<AppId_t> sources;                     // extra forge bases; empty = built-in defaults
    };

    struct CloudSettings {
        bool enabled = false;
        std::string library;
    };

    struct LoadResult {
        bool applied = false;
        bool luaPathsChanged = false;
    };

    LoadResult Load(const std::string& configPath);

    ManifestTimeouts GetManifestTimeouts();
    LogLevel GetLogLevel();
    std::string GetLogDir();
    std::vector<std::string> GetLuaPaths();
    std::vector<std::string> GetRemoteUrlTemplates();
    CloudSettings GetCloudSettings();
    bool GetStatsEnableApi();
    bool GetUpdateEnabled();
    TicketPolicy GetTicketPolicy();

    // [donate] — contribute manifest request codes for depots this account owns.
    struct DonateSettings {
        bool        enabled  = true;
        std::string url;                       // base; empty = built-in default
        uint32_t    intervalSecs        = 30;
        uint32_t    maxMintsPerCycle    = 25;
        uint32_t    minMintIntervalMs   = 2000;
        uint32_t    maxMintsPerSession  = 0;     // 0 = unlimited (mint all session)
        uint32_t    wantedRefreshSecs   = 300;   // re-pull the (large) wanted list only this often; minting still runs every intervalSecs
    };
    DonateSettings GetDonateSettings();

    // [manifest] — provider selection lives in ManifestClient (table-driven).
    inline uint32_t manifestTimeoutResolve = 5000;
    inline uint32_t manifestTimeoutConnect = 5000;
    inline uint32_t manifestTimeoutSend    = 10000;
    inline uint32_t manifestTimeoutRecv    = 10000;

    // [log]
    inline LogLevel logLevel = LogLevel::Debug;

    // derived from configPath: <steam>/opensteamtool/
    inline std::string logDir;

    // [lua]
    inline std::vector<std::string> luaPaths;

    // [remote] — one or more mirror templates, tried in order. Empty = built-in defaults.
    inline std::vector<std::string> remoteUrlTemplates;

    // [stats]
    inline bool statsEnableApi = true;

    // [update] - self-update check on startup (staged for next Steam launch).
    inline bool updateEnabled = true;

    // [tickets] - ownership-ticket answer policy (see TicketAuthority).
    inline TicketPolicy ticketPolicy;

    // [donate] - mint manifest request codes on request for depots this account
    // owns. Codes are bound to (depot, manifest) and rotate within minutes, so
    // they are minted on demand and sent straight on, never stored. The caps
    // exist because this calls Steam as the signed-in user.
    inline DonateSettings donate;

    // [[inject]] - optional DLL injection into matching game processes.
    inline std::vector<InjectDll> injectDlls;

    // [cloud] - optional Steam Cloud save redirection via CloudRedirect.
    inline bool cloudEnabled = false;
    inline std::string cloudLibrary;

}
