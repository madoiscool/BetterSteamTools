#include "Hooks_Package.h"
#include "HookMacros.h"
#include "Hooks_SteamUI.h"
#include "dllmain.h"
#include "Utils/HookSupport/VehCommon.h"
#include <algorithm>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
    RESOLVE_FUNC(CUtlMemoryGrow,               void*, CUtlVector<AppId_t>*, int);
    RESOLVE_FUNC(MarkLicenseAsChanged,         int64, void*, uint32, bool);
    RESOLVE_FUNC(ProcessPendingLicenseUpdates, bool,  void*);

    CAPTURE_THIS_FUNC(GetPackageInfo, PackageInfo*,g_pCPackageInfo,void* pThis, uint32 packageId, uint64 accessToken);
    
    void* g_pCUser = nullptr;
    PackageInfo* g_pInjectedPackageInfo = nullptr;
    bool  g_licenseInitialized = false;
    bool  g_licenseRefreshPending = false;

    constexpr PackageId_t kInjectedPackageId = 0;
    constexpr uint64_t kInjectedPkgAccessToken = 10660652434190618804ull;

    bool MarkLicenseAsChangedAndProcessUpdates() {
        if (!g_pCUser || !oMarkLicenseAsChanged || !oProcessPendingLicenseUpdates) {
            LOG_PACKAGE_WARN("MarkLicenseAsChangedAndProcessUpdates: dependencies not ready, skipping");
            return false;
        }
        oMarkLicenseAsChanged(g_pCUser, kInjectedPackageId, true);
        oProcessPendingLicenseUpdates(g_pCUser);
        LOG_PACKAGE_DEBUG("MarkLicenseAsChangedAndProcessUpdates: marked package {} as changed and processed updates", kInjectedPackageId);
        return true;
    }

    void TryProcessPendingLicenseRefresh() {
        if (!g_licenseRefreshPending)
            return;
        if (MarkLicenseAsChangedAndProcessUpdates())
            g_licenseRefreshPending = false;
    }

    bool CUtlMemoryGrowWrap(CUtlVector<AppId_t>* pVec, int grow_size) {
        if (!oCUtlMemoryGrow) {
            LOG_PACKAGE_WARN("CUtlMemoryGrow: oCUtlMemoryGrow not ready, cannot grow");
            return false;
        }
        return oCUtlMemoryGrow(pVec, grow_size);
    }

    bool InitFakeLicenseOnce(PackageInfo* pPkg) {
        // check package status before injecting
        if (pPkg->Status != EPackageStatus::Available) {
            LOG_PACKAGE_WARN("InitFakeLicenseOnce: package status is not Available ({}), skipping injection", static_cast<int>(pPkg->Status));
            return false;
        }

        // Inject all depots from config into the fake license. 
        std::vector<AppId_t> appIds = LuaConfig::GetAllDepotIds();
        if (!appIds.empty()) {
            uint32 oldSize = pPkg->AppIdVec.m_Size;
            uint32 numToAdd = static_cast<uint32>(appIds.size());
            LOG_PACKAGE_INFO("InitFakeLicense(PackageId={}): adding {} apps, oldSize={}", kInjectedPackageId, numToAdd, oldSize);
            if (!CUtlMemoryGrowWrap(&pPkg->AppIdVec, numToAdd)) {
                LOG_PACKAGE_WARN("InitFakeLicense(PackageId={}): failed to grow AppId vector", kInjectedPackageId);
                return false;
            }
            for (uint32 i = 0; i < numToAdd; i++)
                pPkg->AppIdVec.m_Memory.m_pMemory[oldSize + i] = appIds[i];
        }

        g_licenseInitialized = true;
        g_licenseRefreshPending = true;
        TryProcessPendingLicenseRefresh();
        return true;
    }

    bool TryInitFakeLicenseOnce() {
        if (g_licenseInitialized) return true;
        if(CAPTURE_READY(GetPackageInfo)){
            PackageInfo* pPkg = oGetPackageInfo(g_pCPackageInfo, kInjectedPackageId, kInjectedPkgAccessToken);
            if(!pPkg) {
                LOG_PACKAGE_WARN("TryInitFakeLicenseOnce: GetPackageInfo returned null for injected package");
                return false;
            }
            if(!g_pInjectedPackageInfo) g_pInjectedPackageInfo = pPkg;
            return InitFakeLicenseOnce(pPkg);
        }
        return false;
    }


    // ── Owned depot enumeration ──────────────────────────────────────────────
    // The license list arrives once at logon and is the only enumeration of
    // owned packages available; CheckAppOwnership answers one app at a time and
    // only for apps something asks about. Resolving a package to its depots
    // needs GetPackageInfo, whose `this` is captured from Steam's own first
    // call — which normally has not happened by the time the list lands. So the
    // list is parked here and drained on the next CheckAppOwnership.
    std::vector<Hooks_Package::License> g_pendingLicenses;
    bool g_ownedDepotsDumped = false;

    // Filled by the same walk that logs. Read from the donor's worker thread,
    // written from CheckAppOwnership on a Steam thread, hence the mutex.
    std::vector<uint32_t> g_ownedDepots;
    bool                  g_ownedDepotsReady = false;
    std::mutex            g_ownedDepotsMutex;

    // Formats a CUtlVector<AppId_t> as "a, b, c", capped so one enormous package
    // cannot produce an unreadable log line.
    std::string JoinIds(const CUtlVector<AppId_t>& vec, uint32 maxShown = 64) {
        std::string out;
        const uint32 shown = vec.m_Size < maxShown ? vec.m_Size : maxShown;
        for (uint32 i = 0; i < shown; ++i) {
            if (i) out += ", ";
            out += std::to_string(vec.m_Memory.m_pMemory[i]);
        }
        if (vec.m_Size > shown)
            out += " … (+" + std::to_string(vec.m_Size - shown) + " more)";
        return out;
    }

    void DumpOwnedDepots() {
        size_t totalDepots = 0, resolved = 0, unresolved = 0;
        std::vector<uint32_t> owned;

        for (const auto& lic : g_pendingLicenses) {
            PackageInfo* pPkg = oGetPackageInfo(g_pCPackageInfo, lic.packageId, lic.accessToken);
            if (!pPkg) {
                // Usually a package whose info has not been cached yet rather
                // than a real failure; logged at debug so it does not drown the
                // useful lines.
                ++unresolved;
                LOG_PACKAGE_DEBUG("OwnedDepots: package {} did not resolve (token={})",
                                  lic.packageId, lic.accessToken);
                continue;
            }

            ++resolved;
            totalDepots += pPkg->DepotIdVec.m_Size;

            for (uint32 i = 0; i < pPkg->DepotIdVec.m_Size; ++i) {
                const uint32_t depotId = pPkg->DepotIdVec.m_Memory.m_pMemory[i];
                if (depotId) owned.push_back(depotId);
            }

            LOG_PACKAGE_INFO("OwnedDepots: package {} apps={} depots={} | appids=[{}] | depotids=[{}]",
                             lic.packageId,
                             pPkg->AppIdVec.m_Size, pPkg->DepotIdVec.m_Size,
                             JoinIds(pPkg->AppIdVec), JoinIds(pPkg->DepotIdVec));
        }

        // Packages overlap heavily — the same depot arrives via several
        // licenses — so dedupe before anyone intersects against this.
        std::sort(owned.begin(), owned.end());
        owned.erase(std::unique(owned.begin(), owned.end()), owned.end());

        {
            std::lock_guard<std::mutex> lock(g_ownedDepotsMutex);
            g_ownedDepots      = std::move(owned);
            g_ownedDepotsReady = true;
        }

        LOG_PACKAGE_INFO("OwnedDepots: done — {} package(s) resolved, {} unresolved, "
                         "{} depot entr(ies), {} unique",
                         resolved, unresolved, totalDepots, g_ownedDepots.size());

        // The per-package lines above are capped by JoinIds, so for a package
        // with hundreds of depots they show a subset. This set — deduped, after
        // the walk — is the one the donor actually intersects a wanted list
        // against, and deciding what gets disclosed off a list nobody can read
        // back is not something to leave to inference. Chunked so no single
        // line is unusable, and debug-only: it is thousands of ids.
        {
            std::lock_guard<std::mutex> lock(g_ownedDepotsMutex);
            constexpr size_t kPerLine = 64;
            for (size_t i = 0; i < g_ownedDepots.size(); i += kPerLine) {
                const size_t end = (i + kPerLine < g_ownedDepots.size())
                                 ? i + kPerLine : g_ownedDepots.size();
                std::string chunk;
                for (size_t j = i; j < end; ++j) {
                    if (j > i) chunk += ", ";
                    chunk += std::to_string(g_ownedDepots[j]);
                }
                LOG_PACKAGE_DEBUG("OwnedDepots[{}-{}]: {}", i, end - 1, chunk);
            }
        }
    }


    HOOK_FUNC(CheckAppOwnership, bool, void* pObj, AppId_t appId, AppOwnership* pOwn) {
        if (!g_pCUser) {
            g_pCUser = pObj;
            LOG_PACKAGE_DEBUG("CheckAppOwnership: captured CUser {}", g_pCUser);
        }

        bool result = oCheckAppOwnership(pObj, appId, pOwn);
        TryInitFakeLicenseOnce();
        Hooks_Package::TryDumpOwnedDepots();

        if (LuaConfig::HasDepot(appId,false)) {
            // Keep Steam's current family license, including any lock or expiry.
            if (result && pOwn && pOwn->PackageId != kInjectedPackageId &&
                (pOwn->bFamilyShared || pOwn->bBorrowed)) {
                return result;
            }

            if (result && pOwn->ExistInPackageNums > 1) {
                // Actually owned — record so HasDepot excludes it going forward
                LuaConfig::MarkOwned(appId);
                pOwn->ReleaseState = EAppReleaseState::Released;
            } else {
                pOwn->PackageId    = kInjectedPackageId;
                pOwn->ReleaseState = EAppReleaseState::Released;
                pOwn->bOwnsLicense = true; //This forces DLCs on steam family shared games that u dont own when adding their appid via .lua
                // Setting this free flag to false will hide it from the library UI.
                pOwn->bFreeLicense = false;
                return true;
            }
        }
        return result;
    }
}

namespace Hooks_Package {

    void OnLicenseList(std::vector<License> licenses) {
        g_pendingLicenses  = std::move(licenses);
        g_ownedDepotsDumped = false;
    }

    void TryDumpOwnedDepots() {
        if (g_ownedDepotsDumped || g_pendingLicenses.empty()) return;
        if (!CAPTURE_READY(GetPackageInfo)) return;

        // Set before dumping, not after: DumpOwnedDepots calls back into
        // steamclient, and CheckAppOwnership is what drives us — without this
        // a re-entrant call would start a second dump.
        g_ownedDepotsDumped = true;
        DumpOwnedDepots();
    }

    OwnedDepots GetOwnedDepots() {
        std::lock_guard<std::mutex> lock(g_ownedDepotsMutex);
        return {g_ownedDepotsReady, g_ownedDepots};
    }

    void Install() {
        RESOLVE_C(CUtlMemoryGrow);
        RESOLVE_C(MarkLicenseAsChanged);
        RESOLVE_C(ProcessPendingLicenseUpdates);

        ARM_CAPTURE_C(GetPackageInfo);

        HOOK_BEGIN();
        INSTALL_HOOK_C(CheckAppOwnership);
        HOOK_END();
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK_C(CheckAppOwnership);
        UNHOOK_END();
    }

    void NotifyLicenseChanged() {
        PackageInfo* pPkg = g_pInjectedPackageInfo;
        if (!pPkg) {
            LOG_PACKAGE_WARN("NotifyLicenseChanged: injected PackageInfo not ready, cannot notify");
            return;
        }

        // ── Remove depots that were unloaded ──
        std::vector<AppId_t> removals = LuaConfig::TakePendingRemovals();
        LOG_PACKAGE_DEBUG("NotifyLicenseChanged: processing {} removals", removals.size());
        uint32_t removedCount = 0;
        for (AppId_t id : removals) {
            if (pPkg->AppIdVec.FindAndFastRemove(id)) {
                ++removedCount;
                LOG_PACKAGE_DEBUG("NotifyLicenseChanged: removed AppId {}", id);
            }else {
                LOG_PACKAGE_WARN("NotifyLicenseChanged: AppId {} not found in package AppIdVec during removal", id);
            }
        }

        // ── Add depots that are newly loaded ──
        std::vector<AppId_t> additions = LuaConfig::TakePendingAdditions();
        std::unordered_set<AppId_t> addedIds;
        LOG_PACKAGE_DEBUG("NotifyLicenseChanged: processing {} additions", additions.size());
        if (!additions.empty()) {
            uint32_t oldSize = pPkg->AppIdVec.m_Size;
            if (CUtlMemoryGrowWrap(&pPkg->AppIdVec, additions.size())) {
                // An applied addition invalidates any UI removal that has not
                // reached the UI thread yet.
                for (AppId_t id : additions)
                    Hooks_SteamUI::CancelRemoval(id);

                for (size_t i = 0; i < additions.size(); ++i) {
                    pPkg->AppIdVec.m_Memory.m_pMemory[oldSize + i] = additions[i];
                    addedIds.insert(additions[i]);
                    LOG_PACKAGE_DEBUG("NotifyLicenseChanged: inserted AppId {} at [{}]", additions[i], oldSize + i);
                }
            }else {
                LOG_PACKAGE_WARN("NotifyLicenseChanged: failed to grow AppId vector for additions");
            }
        }

        if (addedIds.empty() && removedCount == 0) {
            LOG_PACKAGE_DEBUG("NotifyLicenseChanged: no changes");
            return;
        }

        // Mark package 0 as changed and trigger library refresh.
        if (!MarkLicenseAsChangedAndProcessUpdates()) {
            LOG_PACKAGE_WARN("NotifyLicenseChanged: failed to mark license as changed");
            return;
        }
        LOG_PACKAGE_INFO("NotifyLicenseChanged: {} added, {} removed", addedIds.size(), removedCount);

        // Queue UI removals for the main-thread RunFrame hook to drain.
        // Never touch MarkAppChange from this (FileWatcher) thread.
        size_t queuedRemovalCount = 0;
        for (AppId_t id : removals) {
            // ParseFile unloads the old file before parsing the replacement.
            // Do not queue that transient removal when the id was added again.
            if (!addedIds.contains(id)) {
                Hooks_SteamUI::QueueRemoval(id);
                ++queuedRemovalCount;
            }
        }
        LOG_PACKAGE_DEBUG("NotifyLicenseChanged: queued {} UI removals, skipped {} transient removals",
                          queuedRemovalCount, removals.size() - queuedRemovalCount);
    }
}
