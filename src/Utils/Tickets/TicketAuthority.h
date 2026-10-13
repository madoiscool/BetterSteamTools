#pragma once

#include "Steam/Types.h"

#include <cstdint>
#include <string>
#include <vector>

// Decides what to answer when Steam asks for an app's ownership ticket.
//
// The authority is the single owner of that decision. It also derives the
// "expected identity" for an app - the account the DRM will check everything
// against - from whatever ticket material exists locally (a stored AppTicket,
// a stored SteamID credential, or ticket material imported this session via
// setAppTicket / setETicket / the redeem flow). The reply, the SteamID spoof
// and the Denuvo identity checks all read the same result, so the bytes handed
// to the DRM and the identity reported alongside them cannot disagree.
//
// A decision is evaluated once per app and cached for the session; config or
// Lua reloads, account switches and new imports reset the cached entry.
namespace TicketAuthority {

    // Where the bytes we serve came from, for logs and the readiness report.
    enum class Provenance
    {
        None,                 // nothing servable for this app
        Stored,               // validated per-app ticket from the credential store
        StoredVault,          // validated per-app ticket from our private vault
        StoredRaw,            // per-app ticket served despite failing validation (best-effort)
        ForgeFromHint,        // forged from a base the user listed in [tickets].sources
        ForgeFromLua,         // forged from the base of an app the Lua setup manages
        ForgeFromInstalled,   // forged from the base of an app installed on this machine
        ForgeFromVault,       // forged from a base kept in our private vault
        ForgeFromRegistry,    // forged from another app's per-app credential
        ForgeFromClient,      // forged from the Steam client's own cached ticket
        ForgeFromCache,       // forged from a base that already worked this session
        FetchedFromBackend,   // signed ticket fetched from a configured ticket backend
    };

    const char* ToString(Provenance provenance);

    // Kind of ticket material handed to us by the config/redeem paths.
    enum class ImportKind
    {
        AppTicket,
        ETicket,
    };

    const char* ToString(ImportKind kind);

    // The identity the DRM is expected to see for an app.
    struct Identity
    {
        bool        foreign = false;   // true: expected account is NOT the signed-in one
        bool        known   = false;   // steamId below is valid
        uint64      steamId = 0;
        std::string source;            // where the expectation was derived from
    };

    struct Decision
    {
        bool         servable = false;
        bool         mixedIdentity = false; // served bytes describe a different account than the expected identity
        Provenance   provenance = Provenance::None;
        Identity     identity;          // expected identity for the app
        AppId_t      sourceApp = 0;     // app the base blob belongs to (forge only)
        uint64       ownerSteamId = 0;  // account baked into the served bytes (0 unknown)
        std::vector<uint8_t> bytes;     // exact bytes to hand the DRM
        uint32       totalSize = 0;     // reply fields, mirroring the ticket layout
        uint32       appIdOffset = 0;
        uint32       steamIdOffset = 0;
        uint32       signatureOffset = 0;
        uint32       signatureSize = 0;
        std::string  reason;            // one-line explanation for logs/report
    };

    // Evaluate (or return the cached) decision for appId.
    Decision Resolve(AppId_t appId);

    // Called by the Lua setters and the redeem flow when ticket material is
    // imported. Validates the pair early (wrong app id, foreign account, or an
    // ETicket without its AppTicket) and drops the cached decision for the app.
    void NoteImport(AppId_t appId, ImportKind kind, const std::vector<uint8_t>& blob);

    // SteamID that must be reported for appId so the DRM sees a single identity
    // across all its checks. Returns 0 to keep the real signed-in account (no
    // spoof) - the default whenever the expected identity IS the signed-in
    // account, and the only option when a foreign identity cannot be identified.
    uint64 IdentityToReport(AppId_t appId);

    // Forget every cached decision and import note. Call after config/Lua
    // reloads and account switches; the next Resolve() re-evaluates.
    void Reset();

    // Write opensteamtool/tickets.json (respects [tickets].report). Safe to
    // call at any time; no-op when the log directory is unavailable.
    void WriteReport();

} // namespace TicketAuthority
