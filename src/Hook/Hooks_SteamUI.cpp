#include "Hooks_SteamUI.h"
#include "HookManager.h"
#include "HookMacros.h"
#include "dllmain.h"
#include "steam_messages.pb.h"
#include "Utils/HookSupport/VehCommon.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"
#include <mutex>
#include <unordered_set>
#include <vector>

namespace
{
    RESOLVE_FUNC(RepeatedFieldUint32_Add, void, void* field, const uint32* value);

    CAPTURE_THIS_FUNC(GetAppByID, CSteamApp*, g_pController,void* pThis, AppId_t appId, bool bCreate);
    CAPTURE_THIS_FUNC(MarkAppChange,void*,g_pAppChangeSource,void* pThis,AppId_t appId, EAppChangeFlags changeFlags);

    // Apps currently downloading/updating (AppStateFlags UpdateRunning/Started).
    // Maintained here on the UI thread; read from other threads under the lock.
    std::mutex g_activeDlMutex;
    std::unordered_set<AppId_t> g_activeDl;

    HOOK_FUNC(FillInAppOverview, void *, void *pThis, void *pAppOverview, CSteamApp *pApp)
    {
        if (pApp)
        {
            // Track whether this app is actively downloading, so the manifest
            // path can tell a real user download from a background scheduled
            // update. UpdateRunning|UpdateStarted = a download is actually going.
            const bool active = (pApp->AppStateFlags &
                (k_EAppStateUpdateRunning | k_EAppStateUpdateStarted)) != 0;
            {
                std::lock_guard<std::mutex> lock(g_activeDlMutex);
                if (active) g_activeDl.insert(pApp->nAppID);
                else        g_activeDl.erase(pApp->nAppID);
            }

            if (LuaConfig::HasDepot(pApp->nAppID, false))
            {
                uint32_t t = LuaConfig::GetPurchaseTime(pApp->nAppID);
                if (t)
                {
                    pApp->PurchasedTime = t;
                    LOG_STEAMUI_TRACE("FillInAppOverview: set PurchasedTime={} for appId={}",
                                      pApp->PurchasedTime, pApp->nAppID);
                }
            }
        }
        return oFillInAppOverview(pThis, pAppOverview, pApp);
    }

    // Apps to drop from the library: queued off-thread, marked on the UI thread.
    std::mutex g_removalMutex;
    std::vector<AppId_t> g_pendingRemovals;
    std::unordered_set<AppId_t> g_removedAppIds;

    // A full rebuild never lists removed_appid for apps still in the map
    // so re-assert our set after the snapshot is built.
    HOOK_FUNC(BuildCompleteAppOverviewChange, void, void *pController,
              CAppOverview_Change *pChange, void *optionalCallbackSlot)
    {
        oBuildCompleteAppOverviewChange(pController, pChange, optionalCallbackSlot);
        std::lock_guard<std::mutex> lock(g_removalMutex);
        if (pChange && !g_removedAppIds.empty() && oRepeatedFieldUint32_Add)
        {
            auto* field = pChange->mutable_removed_appid();
            for (AppId_t appId : g_removedAppIds){
                oRepeatedFieldUint32_Add(field, &appId);
            }
            LOG_STEAMUI_DEBUG("BuildCompleteAppOverviewChange: appended {} removed_appid entries",
                              g_removedAppIds.size());
        }
    }


    // Clearing ownership makes ShouldShowAppInLibrary() false (delta drops it,
    // the full snapshot skips it); MarkAppChange triggers the flush.
    HOOK_FUNC(CSteamUIAppControllerRunFrame, void *, void *pController)
    {
        if (CAPTURE_READY(GetAppByID) && CAPTURE_READY(MarkAppChange))
        {
            std::vector<AppId_t> draining;
            {
                std::lock_guard<std::mutex> lock(g_removalMutex);
                draining.swap(g_pendingRemovals);
            }
            for (AppId_t appId : draining)
            {
                if (LuaConfig::IsOwned(appId))
                {
                    LOG_STEAMUI_DEBUG("RunFrame: appId {} is owned again, skipping removal", appId);
                    continue;
                }
                if (CSteamApp *pApp = oGetAppByID(g_pController, appId, false))
                {
                    // Only remove from the library if it's not already uninstalled
                    pApp->OwnershipFlags = k_EAppOwnershipFlags_None;
                    if(pApp->AppStateFlags == k_EAppStateUninstalled){
                        std::lock_guard<std::mutex> lock(g_removalMutex);
                        g_removedAppIds.insert(appId);
                    }
                }
                
                oMarkAppChange(g_pAppChangeSource, appId, EAppChangeFlags::AppInfoOrConfig);
            }
        }
        return oCSteamUIAppControllerRunFrame(pController);
    }
}

namespace Hooks_SteamUI
{
    void Install()
    {
        ARM_CAPTURE_U(GetAppByID);
        ARM_CAPTURE_U(MarkAppChange);

        RESOLVE_U(RepeatedFieldUint32_Add);

        // These functions have different signatures and must never share a hook
        // target. Bad metadata has mapped FillInAppOverview to the full-snapshot
        // builder, which passes a different third argument (not a CSteamApp).
        void* fillOverview = PatternLoader::FindPattern(ui_hModule, "FillInAppOverview");
        void* buildOverview = PatternLoader::FindPattern(ui_hModule, "BuildCompleteAppOverviewChange");
        const bool conflictingOverviewHooks = fillOverview && fillOverview == buildOverview;
        if (conflictingOverviewHooks) {
            LOG_WARN("SteamUI: FillInAppOverview and BuildCompleteAppOverviewChange resolve to the same address; skipping the date-added hook");
            SteamDiagnostics::ShowWarning(
                "OpenSteamTool - Conflicting SteamUI Patterns",
                "FillInAppOverview and BuildCompleteAppOverviewChange resolve to the same address.\n\n"
                "The date-added hook is disabled for this session. Update the steamui patterns and restart Steam.\n\n"
                "Please report this at:\nhttps://github.com/madoiscool/BetterSteamTools/issues");
        }

        HOOK_BEGIN();
        if (!conflictingOverviewHooks) {
            INSTALL_HOOK_U(FillInAppOverview);
        }
        INSTALL_HOOK_U(BuildCompleteAppOverviewChange);
        INSTALL_HOOK_U(CSteamUIAppControllerRunFrame);
        HOOK_END();
    }

    void Uninstall()
    {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK(FillInAppOverview);
        UNINSTALL_HOOK(BuildCompleteAppOverviewChange);
        UNINSTALL_HOOK(CSteamUIAppControllerRunFrame);
        UNHOOK_END();
    }

    void QueueRemoval(AppId_t appId)
    {
        std::lock_guard<std::mutex> lock(g_removalMutex);
        g_pendingRemovals.push_back(appId);
    }

    void CancelRemoval(AppId_t appId)
    {
        std::lock_guard<std::mutex> lock(g_removalMutex);
        std::erase(g_pendingRemovals, appId);
        g_removedAppIds.erase(appId);
    }

    size_t ActiveDownloadCount()
    {
        std::lock_guard<std::mutex> lock(g_activeDlMutex);
        return g_activeDl.size();
    }
}
