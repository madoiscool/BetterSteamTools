#include "Hooks_NetPacket.h"
#include "Utils/SteamMetadata/ManifestClient.h"
#include "Utils/SteamMetadata/ManifestDonor.h"
#include "Utils/SteamMetadata/ManifestCache.h"
#include "Utils/Config/Config.h"
#include "OSTPlatform/include/Thread.h"
#include "Hooks_Misc.h"
#include "Hooks_Manifest.h"
#include "Hooks_SteamUI.h"
#include "Hooks_Package.h"
#include "HookMacros.h"
#include "dllmain.h"
#include "Utils/Tickets/AppTicket.h"
#include "Utils/Tickets/LegacyCDKey.h"
#include "Utils/Tickets/EticketClient.h"
#include "Utils/Support/FnvHash.h"
#include "Utils/CloudRedirect/CloudRedirectHost.h"
#include "Utils/Stats/LocalStats.h"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "steam_messages.pb.h"

// ════════════════════════════════════════════════════════════════
//  Shared infrastructure
// ════════════════════════════════════════════════════════════════
namespace {

    constexpr uint32 kMaxBodySize   = 65536;
    constexpr uint32 kMaxHdrSize    = 1024;
    constexpr uint32 kMaxPacketSize = 8 + kMaxHdrSize + kMaxBodySize;
    constexpr int    kPacketPoolSize = 8;

    // ── Incoming (RecvPkt) packet pool ─────────────────────
    // NOTE: Steam dispatches network packets on more than one thread. These
    // used to be plain globals, so two concurrent RecvPkt calls overwrote each
    // other's replacement header/body and one depot's manifest code could land
    // in another depot's reply (random 401s / downloads resetting to 0%).
    // thread_local keeps each network thread on its own scratch space; the
    // HandleRecv -> ReplaceRecvPacket use is always same-thread.
    thread_local uint8  g_NewBody[kMaxBodySize];
    thread_local uint32 g_cbNewBody   = 0;
    thread_local uint8  g_NewHdr[kMaxHdrSize];
    thread_local uint32 g_cbNewHdr    = 0;
    thread_local bool   g_NeedReplaceBody = false;
    thread_local bool   g_NeedReplaceHdr  = false;
    thread_local bool   g_ResizedInPlace = false;
    thread_local uint32 g_NewBodySize    = 0;
    thread_local uint8  g_RecvPacketPool[kPacketPoolSize][kMaxPacketSize];
    thread_local int    g_RecvPacketPoolIdx = 0;

    // ── Outgoing (BBuildAndAsyncSendFrame) — same pattern ───────
    thread_local uint8  g_SendNewBody[kMaxBodySize];
    thread_local uint32 g_cbSendNewBody = 0;
    thread_local bool   g_NeedReplaceSend = false;
    thread_local bool   g_SuppressSend    = false;   // drop the outbound frame entirely (cloud RPC answered locally)
    thread_local uint8  g_SendPacketPool[kPacketPoolSize][kMaxPacketSize];
    thread_local int    g_SendPacketPoolIdx = 0;

    // ── EMsg -> name lookup  ─────────────────────────
    RESOLVE_FUNC(PchMsgNameFromEMsg, char*, EMsg eMsg);
    inline const char* MsgName(EMsg eMsg) {
        if (oPchMsgNameFromEMsg) return oPchMsgNameFromEMsg(eMsg);
        return "?";
    }


    // ── Packet layout ──────────────────────────────────────────
    inline bool UnpackRaw(const uint8* data, uint32 size,
                          EMsg& eMsg, const uint8*& pHdr, uint32& cbHdr,
                          const uint8*& pBody, uint32& cbBody)
    {
        if (!data || size < sizeof(MsgHdr)) {
        fail:
            eMsg = static_cast<EMsg>(0);
            cbHdr = 0;
            pHdr = nullptr;
            pBody = nullptr;
            cbBody = 0;
            return false;
        }
        const MsgHdr* hdr = reinterpret_cast<const MsgHdr*>(data);
        if (!(hdr->eMsg & kMsgHdrProtoFlag)) goto fail;

        eMsg  = static_cast<EMsg>(hdr->eMsg & ~kMsgHdrProtoFlag);
        cbHdr = hdr->headerLength;
        uint32 off = sizeof(MsgHdr) + cbHdr;
        if (off > size) goto fail;
        pHdr   = data + sizeof(MsgHdr);
        pBody  = data + off;
        cbBody = size - off;
        return true;
    }

    // ── Incoming: replace header and/or body (ring-buffer pool) ──
    inline void ReplaceRecvPacket(CNetPacket* p,
                                  const uint8* pNewHdr, uint32 cbNewHdr,
                                  const uint8* pNewBody, uint32 cbNewBody)
    {
        uint32 newSize = sizeof(MsgHdr) + cbNewHdr + cbNewBody;
        if (newSize > sizeof(g_RecvPacketPool[0])) return;

        uint8* buf = g_RecvPacketPool[g_RecvPacketPoolIdx];
        const MsgHdr* orig = reinterpret_cast<const MsgHdr*>(p->m_pubData);
        MsgHdr* out = reinterpret_cast<MsgHdr*>(buf);
        out->eMsg         = orig->eMsg;
        out->headerLength = cbNewHdr;
        memcpy(buf + sizeof(MsgHdr), pNewHdr, cbNewHdr);
        if (cbNewBody)
            memcpy(buf + sizeof(MsgHdr) + cbNewHdr, pNewBody, cbNewBody);
        p->m_pubData = buf;
        p->m_cubData = newSize;

        g_RecvPacketPoolIdx = (g_RecvPacketPoolIdx + 1) % kPacketPoolSize;
    }

    // ── Outgoing: assemble modified packet (ring-buffer pool) ────
    inline uint8* ReplaceSendPacket(const uint8* pubData,
                                    uint32 cbHdr, const uint8* pHdr,
                                    const uint8* pNewBody, uint32 cbNewBody,
                                    uint32* pNewSize)
    {
        *pNewSize = sizeof(MsgHdr) + cbHdr + cbNewBody;
        if (*pNewSize > sizeof(g_SendPacketPool[0])) return nullptr;

        uint8* buf = g_SendPacketPool[g_SendPacketPoolIdx];
        const MsgHdr* orig = reinterpret_cast<const MsgHdr*>(pubData);
        MsgHdr* out = reinterpret_cast<MsgHdr*>(buf);
        out->eMsg         = orig->eMsg;
        out->headerLength = cbHdr;
        memcpy(buf + sizeof(MsgHdr), pHdr, cbHdr);
        memcpy(buf + sizeof(MsgHdr) + cbHdr, pNewBody, cbNewBody);
        g_SendPacketPoolIdx = (g_SendPacketPoolIdx + 1) % kPacketPoolSize;
        return buf;
    }

    // ── Hash constants for target_job_name dispatch ─────────────
    constexpr uint32 HASH_JOB_NotifyRunningApps = Fnv1aHash("FamilyGroupsClient.NotifyRunningApps#1");
    constexpr uint32 HASH_JOB_GetUserStats = Fnv1aHash("Player.GetUserStats#1");
    constexpr uint32 HASH_JOB_GetManifestRequestCode = Fnv1aHash("ContentServerDirectory.GetManifestRequestCode#1");

} // anonymous namespace


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_AccessToken
//
//  Outgoing: CMsgClientPICSProductInfoRequest (eMsg 8903)
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_AccessToken {

    bool HandleSend(const uint8* pBody, uint32 cbBody)
    {
        CMsgClientPICSProductInfoRequest req;
        if (!req.ParseFromArray(pBody, cbBody)) {
            LOG_PICS_WARN("Failed to ParseFromArray CMsgClientPICSProductInfoRequest");
            return false;
        }
        LOG_PICS_DEBUG("CMsgClientPICSProductInfoRequest original body:\n{}", req.DebugString());

        bool needsPatch = false;
        for (const auto& app : req.apps()) {
            if (LuaConfig::HasDepot(app.appid()) && LuaConfig::GetAccessToken(app.appid())) {
                needsPatch = true;
                LOG_PICS_DEBUG("CMsgClientPICSProductInfoRequest: found appid {} with access_token, need patching", app.appid());
                break;
            }
        }
        if (!needsPatch) {
            LOG_PICS_TRACE("CMsgClientPICSProductInfoRequest: no apps need token injection, skip");
            return false;
        }

        int injected = 0, noToken = 0, notAddAppId = 0;
        for (auto& app : *req.mutable_apps()) {
            if (LuaConfig::HasDepot(app.appid())) {
                uint64_t token = LuaConfig::GetAccessToken(app.appid());
                if (token) {
                    LOG_PICS_DEBUG("CMsgClientPICSProductInfoRequest: inject appid={}: {} -> {}", app.appid(),
                               app.has_access_token() ? std::to_string(app.access_token()) : "absent",
                               token);
                    app.set_access_token(token);
                    ++injected;
                } else {
                    LOG_PICS_WARN("CMsgClientPICSProductInfoRequest: skip appid={}: in depot, no token configured", app.appid());
                    ++noToken;
                }
            } else {
                ++notAddAppId;
            }
        }
        LOG_PICS_DEBUG("CMsgClientPICSProductInfoRequest: injected={} no_token={} not_in_add_appid={} total={}",
                   injected, noToken, notAddAppId, req.apps_size());

        g_cbSendNewBody = static_cast<uint32>(req.ByteSizeLong());
        if (g_cbSendNewBody > kMaxBodySize) {
            LOG_PICS_WARN("CMsgClientPICSProductInfoRequest: encoded size {} exceeds buffer", g_cbSendNewBody);
            return false;
        }
        if (!req.SerializeToArray(g_SendNewBody, kMaxBodySize)) {
            LOG_PICS_WARN("CMsgClientPICSProductInfoRequest: Failed to encode modified request");
            return false;
        }

        LOG_PICS_DEBUG("CMsgClientPICSProductInfoRequest: modified body: {}", req.DebugString());
        return true;
    }

} // namespace Hooks_NetPacket_AccessToken


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_UserStats
//
//  Outgoing: CPlayer_GetUserStats_Request  (eMsg 151 -> target: Player.GetUserStats#1)
//            CMsgClientGetUserStats        (eMsg 818)
//  Incoming: CPlayer_GetUserStats_Response (eMsg 147 ← target: Player.GetUserStats#1)
//            CMsgClientGetUserStatsResponse(eMsg 819)
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_UserStats {

    // jobid_source -> appid mapping (eMsg 151 request -> eMsg 147 response)
    std::unordered_map<uint64, AppId_t> g_JobIdToAppId;

    // ── Send: CPlayer_GetUserStats_Request (eMsg 151) ──────────
    bool HandleSend_GetUserStats(const uint8* pBody, uint32 cbBody,
                                 const uint8* pHdr, uint32 cbHdr)
    {

        CPlayer_GetUserStats_Request req;
        if (!req.ParseFromArray(pBody, cbBody)) {
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats request: failed to ParseFromArray");
            return false;
        }
        if (!req.has_appid()) {
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats request: missing appid");
            return false;
        }

        LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats request: original body:\n{}", req.DebugString());
        
        AppId_t appId = req.appid();
        bool hasShaSchema = req.has_sha_schema() && !req.sha_schema().empty();

        if (hasShaSchema) {
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats request: sha_schema is present, do not spoof");
            return false;
        }
        if (!LuaConfig::HasDepot(appId)) {
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats request: appid={} is not in addappid", appId);
            return false;
        }

        // Save jobid_source -> appid for the response handler
        CMsgProtoBufHeader hdr;
        if (hdr.ParseFromArray(pHdr, cbHdr) && hdr.has_jobid_source()) {
            uint64 jobId = hdr.jobid_source();
            g_JobIdToAppId[jobId] = appId;
            LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats request: stored jobid={} -> appid={}", jobId, appId);
        }

        uint64_t newSteamId = LuaConfig::GetStatSteamId(appId);
        req.set_steamid(newSteamId);

        g_cbSendNewBody = static_cast<uint32>(req.ByteSizeLong());
        if (!req.SerializeToArray(g_SendNewBody, kMaxBodySize)) {
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats request: failed to encode");
            return false;
        }

        LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats request: modified body:\n{}", req.DebugString());
        return true;
    }

    // ── Recv: CPlayer_GetUserStats_Response (eMsg 147) ─────────
    //     Header: set eresult=OK.  Body: strip stats (field 4).
    void HandleRecv_GetUserStatsResponse(const uint8* pHdr, uint32 cbHdr,
                                    const uint8* pBody, uint32 cbBody)
    {
        // Header: set eresult=OK
        CMsgProtoBufHeader hdrMsg;
        if (!hdrMsg.ParseFromArray(pHdr, cbHdr)){
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats response: failed to ParseFromArray original header");
            return;
        }
        LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats response: original header:\n{}", hdrMsg.DebugString());

        // Look up appid via jobid_target -> jobid_source match
        AppId_t appId = 0;
        bool hasAppId = false;
        if (hdrMsg.has_jobid_target()) {
            uint64 jobId = hdrMsg.jobid_target();
            auto it = g_JobIdToAppId.find(jobId);
            if (it != g_JobIdToAppId.end()) {
                appId = it->second;
                hasAppId = true;
                LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats response: matched jobid={} -> appid={}", jobId, appId);
                g_JobIdToAppId.erase(it);
            }
        }

        hdrMsg.set_eresult(static_cast<int32_t>(k_EResultOK));
        g_cbNewHdr = static_cast<uint32>(hdrMsg.ByteSizeLong());
        if (g_cbNewHdr > kMaxHdrSize || !hdrMsg.SerializeToArray(g_NewHdr, kMaxHdrSize))
            return;
        LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats response: modified header:\n{}", hdrMsg.DebugString());
        g_NeedReplaceHdr = true;

        // Body: strip stats (only if appid was matched and is in our config)
        CPlayer_GetUserStats_Response resp;
        if (!resp.ParseFromArray(pBody, cbBody)){
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats response: failed to ParseFromArray original response");
            return;
        }
        LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats response: original body:\n{}", resp.DebugString());

        if (!hasAppId || !LuaConfig::HasDepot(appId)) {
            LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats response: no appid match, skip body strip");
            return;
        }

        resp.clear_stats();
        g_NewBodySize = static_cast<uint32>(resp.ByteSizeLong());
        if (!resp.SerializeToArray(const_cast<uint8*>(pBody), cbBody)){
            LOG_ACHIEVEMENT_WARN("Player::GetUserStats response: failed to SerializeToArray modified response");
            return;
        }
        g_ResizedInPlace = true;

        LOG_ACHIEVEMENT_DEBUG("Player::GetUserStats response: modified body:\n{}", resp.DebugString());
    }

    // ── Send: CMsgClientGetUserStats (eMsg 818) ────────────────
    bool HandleSend_ClientGetUserStats(const uint8* pBody, uint32 cbBody)
    {
        CMsgClientGetUserStats req;
        if (!req.ParseFromArray(pBody, cbBody)) {
            LOG_ACHIEVEMENT_WARN("ClientGetUserStats request: failed to ParseFromArray");
            return false;
        }
        LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats request: original body:\n{}", req.DebugString());

        if (!req.has_game_id()) {
            LOG_ACHIEVEMENT_WARN("ClientGetUserStats request: missing game_id");
            return false;
        }
        AppId_t appId = static_cast<AppId_t>(req.game_id());
        if (!LuaConfig::HasDepot(appId)) {
            LOG_ACHIEVEMENT_WARN("ClientGetUserStats request: appid={} is not in addappid", appId);
            return false;
        }
        if (req.schema_local_version() != -1) {
            req.set_schema_local_version(-1);
            LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats request: forced schema_local_version to -1");
        }

        uint64_t newSteamId = LuaConfig::GetStatSteamId(appId);
        req.set_steam_id_for_user(newSteamId);

        g_cbSendNewBody = static_cast<uint32>(req.ByteSizeLong());
        if (!req.SerializeToArray(g_SendNewBody, kMaxBodySize)) {
            LOG_ACHIEVEMENT_WARN("ClientGetUserStats request: failed to SerializeToArray");
            return false;
        }

        LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats request: modified body:\n{}", req.DebugString());
        return true;
    }

    // ── Send: CMsgClientStoreUserStats (eMsg 820) / StoreUserStats2 (5466) ──
    //
    //  Local-only stat stores. With [stats] local_only (default), stores for
    //  Lua-unlocked games never reach Valve: the (stat_id, stat_value) pairs
    //  are journaled to LocalStats (achievements travel as stat bits — there
    //  is no separate unlock list on the wire), CloudRedirect is still
    //  notified so its sync keeps working, the outbound frame is suppressed,
    //  and a synthesized 821 success is delivered so the game sees StoreStats
    //  succeed and the client shows the unlock toast. Nothing lands on the
    //  online profile. Owned games are untouched (normal online behavior).
    std::mutex                     g_storeMutex;
    std::deque<std::vector<uint8>> g_storePending;   // ready-to-inject 821 frames

    void QueueStoreResponse(std::vector<uint8>&& pkt) {
        std::lock_guard<std::mutex> lk(g_storeMutex);
        if (g_storePending.size() < 64)
            g_storePending.push_back(std::move(pkt));
    }

    // Deliver queued 821 frames by borrowing the carrier packet for one
    // oRecvPkt call each (same trick as Cloud/LegacyKey). Runs on the network
    // thread from inside the RecvPkt hook.
    void DrainStoreResponses(void* pThis, CNetPacket* pCarrier,
                             bool (*invokeOriginal)(void*, CNetPacket*))
    {
        for (;;) {
            std::vector<uint8> pkt;
            {
                std::lock_guard lk(g_storeMutex);
                if (g_storePending.empty()) return;
                pkt = std::move(g_storePending.front());
                g_storePending.pop_front();
            }

            uint8* origData = pCarrier->m_pubData;
            uint32 origSize = pCarrier->m_cubData;
            pCarrier->m_pubData = pkt.data();
            pCarrier->m_cubData = static_cast<uint32>(pkt.size());
            invokeOriginal(pThis, pCarrier);
            pCarrier->m_pubData = origData;
            pCarrier->m_cubData = origSize;
            LOG_ACHIEVEMENT_DEBUG("StoreUserStats: delivered {}-byte synthesized response", pkt.size());
        }
    }

    // Build + queue an 821 success frame. jobId/steamId come from the request
    // header when present (correlates the reply); protoHdr mirrors the
    // request envelope (raw 820 in, raw 821 out).
    void QueueStoreSuccess(uint64_t gameId, uint32_t crc, uint64_t jobId,
                           uint64_t steamId, bool protoHdr) {
        CMsgClientStoreUserStatsResponse resp;
        if (gameId) resp.set_game_id(gameId);
        resp.set_eresult(static_cast<int32_t>(k_EResultOK));
        resp.set_crc_stats(crc);

        const uint32 cbBody = static_cast<uint32>(resp.ByteSizeLong());

        uint8 hdrBuf[kMaxHdrSize];
        uint32 cbHdr = 0;
        if (protoHdr) {
            CMsgProtoBufHeader respHdr;
            if (jobId)   respHdr.set_jobid_target(jobId);
            if (steamId) respHdr.set_steamid(steamId);
            respHdr.set_eresult(static_cast<int32_t>(k_EResultOK));
            cbHdr = static_cast<uint32>(respHdr.ByteSizeLong());
            if (cbHdr > kMaxHdrSize ||
                !respHdr.SerializeToArray(hdrBuf, kMaxHdrSize))
                return;
        }

        const uint32 total = sizeof(MsgHdr) + cbHdr + cbBody;
        if (cbBody > kMaxBodySize || total > kMaxPacketSize) return;

        std::vector<uint8> pkt(total);
        auto* mhdr = reinterpret_cast<MsgHdr*>(pkt.data());
        mhdr->eMsg = static_cast<EMsg>(static_cast<uint32>(k_EMsgClientStoreUserStatsResponse) |
                                      (protoHdr ? kMsgHdrProtoFlag : 0));
        mhdr->headerLength = cbHdr;
        if (cbHdr) memcpy(pkt.data() + sizeof(MsgHdr), hdrBuf, cbHdr);
        if (!resp.SerializeToArray(pkt.data() + sizeof(MsgHdr) + cbHdr, cbBody))
            return;
        QueueStoreResponse(std::move(pkt));
    }

    // Shared tail: journal (or clear), notify CR, synthesize success.
    // Returns true so the caller suppresses the outbound frame.
    bool SuppressStore(AppId_t appId, uint64_t gameId, uint32_t crc,
                       const std::vector<std::pair<uint32_t, uint32_t>>& pairs,
                       bool explicitReset,
                       const CMsgProtoBufHeader* reqHdr, bool protoHdr) {
        if (explicitReset)
            LocalStats::Clear(appId);
        else
            LocalStats::RecordStore(appId, pairs);
        // CloudRedirect sync keeps working off this notification.
        CloudRedirectHost::NotifyStatsStored(appId);

        uint64_t jobId = 0, steamId = 0;
        if (reqHdr) {
            if (reqHdr->has_jobid_source()) jobId   = reqHdr->jobid_source();
            if (reqHdr->has_steamid())      steamId = reqHdr->steamid();
        }
        QueueStoreSuccess(gameId, crc, jobId, steamId, protoHdr);
        LOG_ACHIEVEMENT_INFO("StoreUserStats: handled locally app={} ({} pair(s), reset={}), "
                             "suppressed from server", appId, pairs.size(), explicitReset);
        return true;
    }

    // Returns true when the frame must be suppressed (handled locally).
    bool HandleSend_StoreUserStats(const uint8* pBody, uint32 cbBody,
                                   const uint8* pHdr, uint32 cbHdr)
    {
        if (!Config::GetStatsLocalOnly()) return false;

        CMsgClientStoreUserStats req;
        if (!req.ParseFromArray(pBody, cbBody)) return false;
        if (!req.has_game_id()) return false;
        const AppId_t appId = static_cast<AppId_t>(req.game_id());
        // When local_only is enabled, allow all games (including cracked) to store achievements locally.
        // Otherwise, only allow games in the depot config (owned games).
        if (!Config::GetStatsLocalOnly() && !LuaConfig::HasDepot(appId)) return false;

        std::vector<std::pair<uint32_t, uint32_t>> pairs;
        pairs.reserve(static_cast<size_t>(req.stats_to_store_size()));
        for (const auto& s : req.stats_to_store())
            pairs.emplace_back(s.stat_id(), s.stat_value());

        CMsgProtoBufHeader hdr;
        const CMsgProtoBufHeader* ph =
            hdr.ParseFromArray(pHdr, cbHdr) ? &hdr : nullptr;
        return SuppressStore(appId, req.game_id(), 0, pairs,
                             req.explicit_reset(), ph, /*protoHdr=*/true);
    }

    // Non-proto fallback: if 820 ever arrives without the proto flag it never
    // reaches SendJob (UnpackRaw bails). Caught straight off the send hook;
    // true = answered locally, suppress the real send.
    bool HandleSend_StoreUserStats_Raw(const uint8* pubData, uint32 cubData) {
        if (!Config::GetStatsLocalOnly()) return false;
        if (cubData <= sizeof(MsgHdr)) return false;

        CMsgClientStoreUserStats req;
        if (!req.ParseFromArray(pubData + sizeof(MsgHdr), cubData - sizeof(MsgHdr)))
            return false;
        if (!req.has_game_id()) return false;
        const AppId_t appId = static_cast<AppId_t>(req.game_id());
        // When local_only is enabled, allow all games (including cracked) to store achievements locally.
        // Otherwise, only allow games in the depot config (owned games).
        if (!Config::GetStatsLocalOnly() && !LuaConfig::HasDepot(appId)) return false;

        std::vector<std::pair<uint32_t, uint32_t>> pairs;
        pairs.reserve(static_cast<size_t>(req.stats_to_store_size()));
        for (const auto& s : req.stats_to_store())
            pairs.emplace_back(s.stat_id(), s.stat_value());

        return SuppressStore(appId, req.game_id(), 0, pairs,
                             req.explicit_reset(), nullptr, /*protoHdr=*/false);
    }

    // Returns true when the frame must be suppressed (handled locally).
    bool HandleSend_StoreUserStats2(const uint8* pBody, uint32 cbBody,
                                    const uint8* pHdr, uint32 cbHdr)
    {
        if (!Config::GetStatsLocalOnly()) return false;

        CMsgClientStoreUserStats2 req;
        if (!req.ParseFromArray(pBody, cbBody)) return false;
        if (!req.has_game_id()) return false;
        const AppId_t appId = static_cast<AppId_t>(req.game_id());
        // When local_only is enabled, allow all games (including cracked) to store achievements locally.
        // Otherwise, only allow games in the depot config (owned games).
        if (!Config::GetStatsLocalOnly() && !LuaConfig::HasDepot(appId)) return false;

        std::vector<std::pair<uint32_t, uint32_t>> pairs;
        pairs.reserve(static_cast<size_t>(req.stats_size()));
        for (const auto& s : req.stats())
            pairs.emplace_back(s.stat_id(), s.stat_value());

        CMsgProtoBufHeader hdr;
        const CMsgProtoBufHeader* ph =
            hdr.ParseFromArray(pHdr, cbHdr) ? &hdr : nullptr;
        // NOTE: 5466 has no dedicated ack message in the protocol; a best-
        // effort 821 (game_id-keyed) is synthesized so the client can toast.
        // If some title ignores it, the journal + library display below still
        // hold the unlock — check achievement.log for the path games use.
        return SuppressStore(appId, req.game_id(), req.crc_stats(), pairs,
                             req.explicit_reset(), ph, /*protoHdr=*/true);
    }

    // ── Recv: CMsgClientGetUserStatsResponse (eMsg 819) ────────
    //     Clear donor stats, overlay local journal + CR achievements, patch eresult->OK.
    bool HandleRecv_ClientGetUserStatsResponse(const uint8* pBody, uint32 cbBody)
    {
        CMsgClientGetUserStatsResponse resp;
        if (!resp.ParseFromArray(pBody, cbBody))
            return false;
        LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats response: original body:\n{}", resp.DebugString());
        if(!resp.has_game_id() || !LuaConfig::HasDepot(static_cast<AppId_t>(resp.game_id()))) {
            LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats response: no modification needed");
            return false;
        }
        resp.clear_stats();
        resp.clear_achievement_blocks();
        resp.set_eresult(1);  // k_EResultOK

        // Donor data is gone. Overlay order: CloudRedirect's synced state
        // first (it wins on conflict), then the local journal for everything
        // CR does not cover — progress earned locally always shows in the
        // overlay and on the library page, with or without CR.
        const auto appId = static_cast<uint32_t>(resp.game_id());
        CloudRedirectHost::AchievementBlock blocks[64];
        uint32_t n = CloudRedirectHost::GetAchievements(appId, blocks, 64);
        if (n > 0) {
            uint32_t crc = 0;
            for (uint32_t i = 0; i < n; i++) {
                auto* s = resp.add_stats();
                s->set_stat_id(blocks[i].statId);
                s->set_stat_value(blocks[i].bits);
                auto* ab = resp.add_achievement_blocks();
                ab->set_achievement_id(blocks[i].statId);
                for (uint32_t bit = 0; bit < 32; bit++)
                    ab->add_unlock_time(blocks[i].unlockTimes[bit]);
                crc ^= blocks[i].bits ^ blocks[i].statId;
            }
            resp.set_crc_stats(crc);
            LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats response: injected {} CR achievement blocks for app {}", n, appId);
        } else {
            LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats response: no CR data for app {}", appId);
        }

        // Local journal injection (capped so the message stays well under the
        // replace pool). Stat values carry achievement bits, which the client
        // maps through the schema for display.
        constexpr size_t kMaxJournalInject = 512;
        size_t injected = 0;
        for (const auto& [statId, statValue] : LocalStats::GetStats(appId)) {
            if (injected >= kMaxJournalInject) break;
            bool covered = false;
            for (uint32_t i = 0; i < n; ++i) {
                if (blocks[i].statId == statId) { covered = true; break; }
            }
            if (covered) continue;
            auto* s = resp.add_stats();
            s->set_stat_id(statId);
            s->set_stat_value(statValue);
            ++injected;
        }
        if (injected)
            LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats response: injected {} local stat(s) for app {}",
                                  injected, appId);

        auto newSize = resp.ByteSizeLong();
        if (newSize > sizeof(g_NewBody)) {
            LOG_ACHIEVEMENT_WARN("ClientGetUserStats response: modified message too large ({} bytes)", newSize);
            return false;
        }
        if (!resp.SerializeToArray(g_NewBody, sizeof(g_NewBody)))
            return false;

        g_cbNewBody = static_cast<uint32>(newSize);
        g_NeedReplaceBody = true;
        LOG_ACHIEVEMENT_DEBUG("ClientGetUserStats response: modified body:\n{}", resp.DebugString());
        return true;
    }

} // namespace Hooks_NetPacket_UserStats


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_ETicket
//
//  Incoming: CMsgClientRequestEncryptedAppTicketResponse (eMsg 5527)
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_ETicket {

    void HandleEncryptedAppTicketResponse(const uint8* pBody, uint32 cbBody)
    {
        CMsgClientRequestEncryptedAppTicketResponse resp;
        if (!resp.ParseFromArray(pBody, cbBody)) {
            LOG_NETPACKET_WARN("ClientRequestEncryptedAppTicketResponse: failed to ParseFromArray");
            return;
        }
        LOG_NETPACKET_DEBUG("ClientRequestEncryptedAppTicketResponse: original body:\n{}", resp.DebugString());

        if (resp.eresult() == k_EResultOK) return;
        if (!LuaConfig::HasDepot(resp.app_id())) return;

        auto ticket = AppTicket::GetEncryptedTicketFromCredentialStore(resp.app_id());
        if (ticket.empty()) return;

        if (!resp.mutable_encrypted_app_ticket()->ParseFromArray(
                ticket.data(), static_cast<int>(ticket.size()))) {
            LOG_NETPACKET_WARN("ClientRequestEncryptedAppTicketResponse: failed to ParseFromArray EncryptedAppTicket");
            return;
        }

        resp.set_eresult(k_EResultOK);

        auto encSize = resp.ByteSizeLong();
        if (encSize > sizeof(g_NewBody)) {
            LOG_NETPACKET_WARN("ClientRequestEncryptedAppTicketResponse: modified message too large");
            return;
        }
        if (!resp.SerializeToArray(g_NewBody, sizeof(g_NewBody))) {
            LOG_NETPACKET_WARN("ClientRequestEncryptedAppTicketResponse: failed to SerializeToArray modified response");
            return;
        }
        
        LOG_NETPACKET_DEBUG("ClientRequestEncryptedAppTicketResponse: modified body:\n{}", resp.DebugString());

        g_cbNewBody = static_cast<uint32>(encSize);
        g_NeedReplaceBody = true;
    }

} // namespace Hooks_NetPacket_ETicket


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_OwnershipTicket
//
//  Incoming: MsgClientGetAppOwnershipTicketResponse (eMsg 858).
//  Some Denuvo titles (e.g. Suicide Squad: KTJL) verify ownership via this
//  network message instead of the IPC GetAppOwnershipTicketExtendedData hook,
//  so OST's IPC ownership spoof never engages and the real (non-owning) account
//  leaks through -> 88500012. 858 is a legacy NON-protobuf message with no
//  schema in-tree and responses of varying size, so log the raw layout first;
//  the spoof (inject the owner's signed ticket from the credential store) is
//  wired once the exact field offsets are confirmed from a live capture.
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_OwnershipTicket {

    void HandleRecv(const uint8* pBody, uint32 cbBody)
    {
        CMsgClientGetAppOwnershipTicketResponse resp;
        if (!resp.ParseFromArray(pBody, cbBody)) {
            LOG_NETPACKET_WARN("OwnershipTicketResponse[858]: failed to ParseFromArray (cbBody={})", cbBody);
            return;
        }

        // Steam already returned a valid ticket (account owns it) — leave it.
        if (resp.eresult() == k_EResultOK) return;
        if (!LuaConfig::HasDepot(resp.app_id())) return;

        const int32 origEresult = resp.eresult();

        // Prefer the credential-store ticket when it is already valid: that
        // ensures GetAppOwnershipTicketExtendedData and the 858 response hand
        // Denuvo the identical bytes. Serving a different (backend-minted) ticket
        // here caused a cross-check mismatch → 012 even when the SteamID was the
        // same account. Only mint from the backend when the credential store has
        // no valid ticket (existingSteamId == 0).
        auto stored = AppTicket::GetAppOwnershipTicketFromCredentialStore(resp.app_id());
        const uint64_t existingSteamId = AppTicket::ExtractSteamIdFromTicketBytes(stored);

        std::vector<uint8_t> ticketBytes;
        if (existingSteamId != 0) {
            ticketBytes = std::move(stored);
        } else {
            auto minted = EticketClient::FetchOwnershipTicket(resp.app_id(), {}, 0);
            if (!minted) {
                LOG_NETPACKET_WARN("OwnershipTicketResponse[858]: appid={} eresult={} but no owner ticket available",
                                   resp.app_id(), origEresult);
                return;
            }
            ticketBytes = std::move(*minted);
        }

        resp.set_ticket(ticketBytes.data(), ticketBytes.size());
        resp.set_eresult(k_EResultOK);

        const auto encSize = resp.ByteSizeLong();
        if (encSize > sizeof(g_NewBody)) {
            LOG_NETPACKET_WARN("OwnershipTicketResponse[858]: modified message too large ({})", encSize);
            return;
        }
        if (!resp.SerializeToArray(g_NewBody, sizeof(g_NewBody))) {
            LOG_NETPACKET_WARN("OwnershipTicketResponse[858]: failed to SerializeToArray");
            return;
        }

        g_cbNewBody = static_cast<uint32>(encSize);
        g_NeedReplaceBody = true;
        LOG_NETPACKET_INFO("OwnershipTicketResponse[858]: spoofed appid={} ticket_bytes={} (orig eresult={} -> OK)",
                           resp.app_id(), ticketBytes.size(), origEresult);
    }

} // namespace Hooks_NetPacket_OwnershipTicket


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_FamilySharing
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_FamilySharing {

    void ClearBody(const uint8*, uint32)
    {
        LOG_NETPACKET_DEBUG("Clearing family sharing message...");
        g_cbNewBody = 0;
        g_NeedReplaceBody = true;
    }

} // namespace Hooks_NetPacket_FamilySharing


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_Licenses
//
//  Incoming: CMsgClientLicenseList (eMsg 780)
//
//  Steam sends this once shortly after logon. It is the only place the
//  full set of owned package ids appears — CheckAppOwnership answers per
//  app and only for apps something asks about, so it can never enumerate.
//  Read-only: the message is handed on untouched.
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_Licenses {

    void HandleRecv(const uint8* pBody, uint32 cbBody)
    {
        CMsgClientLicenseList msg;
        if (!msg.ParseFromArray(pBody, cbBody)) {
            LOG_PACKAGE_WARN("LicenseList: failed to parse CMsgClientLicenseList");
            return;
        }

        std::vector<Hooks_Package::License> licenses;
        licenses.reserve(static_cast<size_t>(msg.licenses_size()));

        for (int i = 0; i < msg.licenses_size(); ++i) {
            const auto& lic = msg.licenses(i);
            if (!lic.has_package_id()) continue;
            licenses.push_back({static_cast<PackageId_t>(lic.package_id()),
                                lic.has_access_token() ? lic.access_token() : 0});
        }

        LOG_PACKAGE_INFO("LicenseList: {} license(s), eresult={}",
                         licenses.size(), msg.has_eresult() ? msg.eresult() : 0);

        Hooks_Package::OnLicenseList(std::move(licenses));
        Hooks_Package::TryDumpOwnedDepots();
    }

} // namespace Hooks_NetPacket_Licenses


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_ManifestProbe
//
//  Originates ContentServerDirectory.GetManifestRequestCode#1 rather
//  than waiting for Steam to ask, and logs the code that comes back.
//
//  Everything else in this file reacts: it rewrites frames Steam is
//  already sending, or manufactures inbound ones. This is the only
//  path that initiates, which needs three things Steam normally
//  supplies and we have to borrow:
//
//    * the websocket object    — only visible inside the send hook
//    * a valid header          — steamid/session must be right, so a
//                                real outbound header is kept as a
//                                template rather than built from parts
//    * a jobid                 — taken from a high, distinctive range
//                                so it can never collide with Steam's
//
//  Calling oBBuildAndAsyncSendFrame directly bypasses the send hook,
//  so Hooks_NetPacket_Manifest::HandleSend never sees these and no
//  provider fetch is started for them. The reply still passes through
//  that namespace's HandleRecv, which bails on an unrecognised jobid.
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_ManifestProbe {

    // Captured from the send hook; needed to transmit at all. The send
    // trampoline is handed over rather than referenced directly, because
    // HOOK_FUNC declares it further down this file.
    using SendFrameFn = bool(__fastcall*)(void*, EWebSocketOpCode, uint8*, uint32);
    void*       g_pWebSocket = nullptr;
    SendFrameFn g_sendFrame  = nullptr;

    // A real outbound ServiceMethodCallFromClient header, kept whole and
    // reused. Cheaper and far more robust than assembling one: whatever
    // routing fields Steam includes come along automatically.
    std::vector<uint8> g_HdrTemplate;
    std::mutex         g_Mutex;

    // Well clear of Steam's own job ids, which count up from small values.
    constexpr uint64 kJobIdBase = 0x7E51'0000'0000'0000ull;
    uint64 g_NextJobId = kJobIdBase;

    struct Pending {
        AppId_t appId;
        uint32  depotId;
        uint64  manifestGid;
        std::promise<uint64> result;
        std::chrono::steady_clock::time_point sentAt;
    };
    std::unordered_map<uint64, Pending> g_Pending;

    // Steam answers everything it is asked, but a disconnect between send and
    // reply would otherwise leave a promise nobody ever fulfils and a caller
    // blocked on it forever. Swept on each new request.
    constexpr auto kPendingTimeout = std::chrono::seconds(30);

    void ExpireStale()   // caller holds g_Mutex
    {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = g_Pending.begin(); it != g_Pending.end(); ) {
            if (now - it->second.sentAt > kPendingTimeout) {
                LOG_MANIFEST_WARN("ManifestProbe: no reply for depot {} (jobid={}) after {}s",
                                  it->second.depotId, it->first,
                                  std::chrono::duration_cast<std::chrono::seconds>(kPendingTimeout).count());
                it->second.result.set_value(0);
                it = g_Pending.erase(it);
            } else {
                ++it;
            }
        }
    }

    void CaptureContext(void* pObject, SendFrameFn sendFrame,
                        const uint8* pHdr, uint32 cbHdr)
    {
        std::lock_guard<std::mutex> lock(g_Mutex);
        if (pObject)   g_pWebSocket = pObject;
        if (sendFrame) g_sendFrame  = sendFrame;
        if (g_HdrTemplate.empty() && pHdr && cbHdr)
            g_HdrTemplate.assign(pHdr, pHdr + cbHdr);
    }

    bool Ready()
    {
        std::lock_guard<std::mutex> lock(g_Mutex);
        return g_pWebSocket && g_sendFrame && !g_HdrTemplate.empty();
    }

    // Sends the request and hands back a future for the code. A future holding
    // 0 means the request failed, was refused by Steam, or timed out — callers
    // treat all three the same way.
    std::future<uint64> Request(AppId_t appId, uint32 depotId, uint64 manifestGid)
    {
        // Every early exit resolves the promise with 0 rather than dropping it,
        // so a caller waiting on the future is never left hanging on a request
        // that was never sent.
        std::promise<uint64> promise;
        std::future<uint64>  future = promise.get_future();
        auto failWith = [&promise, &future]() -> std::future<uint64> {
            promise.set_value(0);
            return std::move(future);
        };

        std::vector<uint8> hdrTemplate;
        void*       ws    = nullptr;
        SendFrameFn send  = nullptr;
        uint64      jobId = 0;
        {
            std::lock_guard<std::mutex> lock(g_Mutex);
            ExpireStale();
            if (!g_pWebSocket || !g_sendFrame || g_HdrTemplate.empty()) {
                LOG_MANIFEST_WARN("ManifestProbe: no send context captured yet "
                                  "(websocket={}, sendFn={}, header={} bytes) - is Steam logged in?",
                                  g_pWebSocket != nullptr, g_sendFrame != nullptr,
                                  g_HdrTemplate.size());
                return failWith();
            }
            hdrTemplate = g_HdrTemplate;
            ws          = g_pWebSocket;
            send        = g_sendFrame;
            jobId       = ++g_NextJobId;
        }

        CMsgProtoBufHeader hdr;
        if (!hdr.ParseFromArray(hdrTemplate.data(), static_cast<int>(hdrTemplate.size()))) {
            LOG_MANIFEST_WARN("ManifestProbe: header template failed to parse");
            return failWith();
        }
        hdr.set_target_job_name("ContentServerDirectory.GetManifestRequestCode#1");
        hdr.set_jobid_source(jobId);
        hdr.clear_jobid_target();

        CContentServerDirectory_GetManifestRequestCode_Request req;
        req.set_app_id(appId);
        req.set_depot_id(depotId);
        req.set_manifest_id(manifestGid);

        const uint32 cbHdr  = static_cast<uint32>(hdr.ByteSizeLong());
        const uint32 cbBody = static_cast<uint32>(req.ByteSizeLong());
        std::vector<uint8> frame(sizeof(MsgHdr) + cbHdr + cbBody);

        auto* mhdr = reinterpret_cast<MsgHdr*>(frame.data());
        mhdr->eMsg = static_cast<EMsg>(
            static_cast<uint32>(k_EMsgServiceMethodCallFromClient) | kMsgHdrProtoFlag);
        mhdr->headerLength = cbHdr;

        if (!hdr.SerializeToArray(frame.data() + sizeof(MsgHdr), cbHdr) ||
            !req.SerializeToArray(frame.data() + sizeof(MsgHdr) + cbHdr, cbBody)) {
            LOG_MANIFEST_WARN("ManifestProbe: failed to serialise request frame");
            return failWith();
        }

        // Registered before sending: the reply can arrive on another thread the
        // instant the frame goes out, and it must find the entry already there.
        {
            std::lock_guard<std::mutex> lock(g_Mutex);
            Pending& p     = g_Pending[jobId];
            p.appId        = appId;
            p.depotId      = depotId;
            p.manifestGid  = manifestGid;
            p.result       = std::move(promise);
            p.sentAt       = std::chrono::steady_clock::now();
        }

        LOG_MANIFEST_INFO("ManifestProbe send: app={} depot={} gid={} jobid={} ({} bytes)",
                          appId, depotId, manifestGid, jobId, frame.size());

        if (!send(ws, k_eWebSocketOpCode_Binary,
                  frame.data(), static_cast<uint32>(frame.size()))) {
            LOG_MANIFEST_WARN("ManifestProbe: send returned false for jobid={}", jobId);
            std::lock_guard<std::mutex> lock(g_Mutex);
            auto it = g_Pending.find(jobId);
            if (it != g_Pending.end()) {
                it->second.result.set_value(0);
                g_Pending.erase(it);
            }
        }
        return future;
    }

    // True when the reply belonged to us, meaning the normal manifest
    // handler should not look at it.
    bool HandleRecv(const uint8* pBody, uint32 cbBody, const uint8* pHdr, uint32 cbHdr)
    {
        CMsgProtoBufHeader hdr;
        if (!hdr.ParseFromArray(pHdr, cbHdr) || !hdr.has_jobid_target()) return false;

        const uint64 jobId = hdr.jobid_target();
        if (jobId < kJobIdBase) return false;   // cheap reject before locking

        AppId_t appId = 0;
        uint32  depotId = 0;
        uint64  gid = 0;
        std::promise<uint64> result;
        {
            std::lock_guard<std::mutex> lock(g_Mutex);
            auto it = g_Pending.find(jobId);
            if (it == g_Pending.end()) return false;
            appId   = it->second.appId;
            depotId = it->second.depotId;
            gid     = it->second.manifestGid;
            result  = std::move(it->second.result);
            g_Pending.erase(it);
        }

        CContentServerDirectory_GetManifestRequestCode_Response resp;
        if (!resp.ParseFromArray(pBody, cbBody)) {
            LOG_MANIFEST_WARN("ManifestProbe recv: failed to parse response for jobid={}", jobId);
            result.set_value(0);
            return true;
        }

        const uint64 code = resp.has_manifest_request_code() ? resp.manifest_request_code() : 0;
        const int32  res  = hdr.has_eresult() ? hdr.eresult() : 0;

        if (code) {
            LOG_MANIFEST_INFO("ManifestProbe recv: app={} depot={} gid={} -> code={} (eresult={})",
                              appId, depotId, gid, code, res);
        } else {
            // eresult 2 is generic failure, which normally means the depot is
            // not licensed to this account. eresult 8 (InvalidParam) has also
            // been seen on an app_id=0 request for a depot the account does
            // own — 0 satisfies the access check most of the time but not
            // reliably, so a failure here is not proof of missing ownership.
            LOG_MANIFEST_WARN("ManifestProbe recv: app={} depot={} gid={} -> NO CODE (eresult={})",
                              appId, depotId, gid, res);
        }
        result.set_value(code);
        return true;
    }

} // namespace Hooks_NetPacket_ManifestProbe


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_Manifest
//
//  Outgoing: ContentServerDirectory.GetManifestRequestCode#1  (eMsg 151)
//  Incoming: ContentServerDirectory.GetManifestRequestCode#1  (eMsg 147)
//
//  Launches an async HTTP fetch on send; the recv handler waits up to
//  kMaxWaitSeconds for the result and patches both header (eresult=OK) and
//  body (manifest_request_code).  On timeout or failure the original
//  response passes through unmodified.
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_Manifest {

    struct CodeFetch {
        std::shared_future<uint64> future;
        std::chrono::steady_clock::time_point created;
    };
    std::unordered_map<uint64, CodeFetch> g_CodeFutures;
    std::mutex g_CodeMutex;
    // HTTP fetch budget is resolve+connect+send+recv = 5+5+10+10 = 30 s worst
    // case (plus Lua http_get). The old 12 s waiter timed out on any slow edge
    // and the download failed (reset to 0%) while the fetch completed a moment
    // later — the classic "random fail, retry works". Wait out the full budget.
    constexpr uint32 kMaxWaitSeconds = 30;
    // Replies that never arrive (batched inside k_EMsgMulti, which RecvJob
    // skips, or a dropped job) must not leak map entries forever.
    constexpr auto kFutureStaleAfter = std::chrono::seconds(120);

    // Passive capture: jobid_source -> (depot, gid) for every outgoing request,
    // so HandleRecv can harvest the genuine code Steam returns for depots this
    // account can access. Capped to bound memory if a reply never arrives.
    struct SentReq { uint32 depot; uint64 gid; };
    std::unordered_map<uint64, SentReq> g_SentRequests;
    std::mutex g_SentMutex;
    constexpr size_t kMaxSentTracked = 4096;

    bool HandleSend(const uint8* pBody, uint32 cbBody,
                    const uint8* pHdr, uint32 cbHdr)
    {
        CContentServerDirectory_GetManifestRequestCode_Request req;
        if (!req.ParseFromArray(pBody, cbBody)) {
            LOG_MANIFEST_WARN("GetManifestRequestCode: failed to parse request");
            return false;
        }
        if (!req.has_depot_id() || !req.has_manifest_id()) return false;

        const uint64 manifestGid = req.manifest_id();
        const uint32 depotId     = req.depot_id();
        const uint32 appId       = req.has_app_id() ? req.app_id() : 0;

        // Parse the header up front: the jobid_source correlates the reply, and
        // both the passive-capture and injection paths below need it.
        CMsgProtoBufHeader hdr;
        const bool haveJob = hdr.ParseFromArray(pHdr, cbHdr) && hdr.has_jobid_source();
        const uint64 jobId = haveJob ? hdr.jobid_source() : 0;

        // Passive capture: remember this request so HandleRecv can harvest the
        // real code Steam is about to return — every request, not just Lua ones,
        // because a genuine code from any depot the user actually downloads is
        // worth keeping and costs no extra Steam traffic. Gated on [donate],
        // where captured codes are sent.
        if (haveJob && Config::GetDonateSettings().enabled) {
            std::lock_guard<std::mutex> lock(g_SentMutex);
            if (g_SentRequests.size() < kMaxSentTracked)
                g_SentRequests[jobId] = {depotId, manifestGid};
        }

        // ── Injection path: only Lua depots we don't own get their code swapped
        //    for a fetched one. Everything else passes through untouched (and is
        //    a passive-capture candidate above). ──────────────────────────────
        if (!LuaConfig::HasDepot(depotId)) return false;

        // A depot can be both Lua-added and genuinely owned — 680 of them on one
        // test machine. There Steam is about to receive a real, working code, so
        // replacing it with a fetched one can only make things worse: since Valve
        // made codes depot-bound the fetched one is carrier-minted and the CDN
        // 401s it, turning a download that would have worked into "Failed
        // downloading 1 manifests".
        //
        // HasDepot(checkOwned=true) above is meant to catch this but cannot: it
        // tests OwnedAppIdSet, which MarkOwned fills with *app* ids, against the
        // *depot* id passed here. BuildDepotDependency has already recorded the
        // depot -> app mapping (it runs seconds earlier), so bridge through that.
        // Fallback: on restart / resume the code request can arrive BEFORE
        // BuildDepotDependency runs this session, so the map is still empty.
        // The request itself usually carries app_id — if that app is owned,
        // leave Steam's code alone too. Without this, an owned depot gets a
        // carrier-minted code injected, the CDN 401s it, and the download
        // resets to 0%.
        AppId_t  seenApp = 0;
        uint64_t seenGid = 0;
        bool ownedDepot = false;
        if (Hooks_Manifest::LookupDepot(depotId, seenApp, seenGid) &&
            seenApp && LuaConfig::IsOwned(seenApp)) {
            ownedDepot = true;
        } else if (appId && LuaConfig::IsOwned(appId)) {
            seenApp = appId;
            ownedDepot = true;
        }
        if (ownedDepot) {
            LOG_MANIFEST_INFO("GetManifestRequestCode: depot={} belongs to owned app {}, "
                              "leaving Steam's own code alone", depotId, seenApp);
            return false;
        }

        if (!haveJob) {
            LOG_MANIFEST_WARN("GetManifestRequestCode: missing jobid_source in header");
            return false;
        }

        LOG_MANIFEST_DEBUG("GetManifestRequestCode send: depot={} gid={} jobid={} app_id={}",
                            depotId, manifestGid, jobId, appId);

        // Pre-seed <steam>\depotcache from the archive for the EXACT manifest
        // Steam is asking a code for. This request is the ground truth of what
        // Steam will download - BuildDepotDependency's gid can differ (an ACF-
        // pinned target vs the resolved latest), so trigger the fetch here where
        // the gid is authoritative. Detached + best-effort; if the archive has it,
        // Steam's own retry (~30 s) finds the manifest on disk and skips the code
        // path entirely. A miss just falls through to the fetched-code attempt.
        {
            const AppId_t  a = appId;
            const uint32   d = depotId;
            const uint64   g = manifestGid;
            // A code request fires for BOTH real user downloads and Steam's
            // background scheduled-update retries (~every 30 s). Only an app that
            // is actively downloading is a real user action; only then do we
            // bypass the negative cache (fetch fresh, to pick up a just-supplied
            // manifest) and surface the "not ready" box. Scheduled/queued requests
            // ride the negative cache and stay silent, so they neither hammer the
            // archive nor spam popups.
            // A game's DLC depots carry the DLC app id, but only the BASE game is
            // marked downloading - so checking this depot's own app id misses it
            // (verified: appActive=false while dlCount=1 during a Sims 4 DLC
            // download). Use "is any app actively downloading": true during a real
            // user download, false at idle startup when Steam is only retrying its
            // scheduled-update queue.
            // NOTE: the archive check below always bypasses the negative cache.
            // A pause -> resume inside the 10 min negative window must re-GET:
            // the donor may have supplied the manifest while paused, and the UI
            // active-flag can lag the network thread on resume, so gating the
            // bypass on `active` caused resume to ride a stale 404 and reset to
            // 0%. Steady-state cost is nil — archived manifests hit the
            // fs::exists short-circuit and never GET again; only genuinely
            // missing manifests re-GET on each ~30 s retry. `active` still gates
            // the "not ready" popup so idle retries stay silent.
            const bool active = Hooks_SteamUI::ActiveDownloadCount() > 0;
            OSTPlatform::Thread::StartDetached([a, d, g, active]() -> uint32_t {
                bool notArchived = false;
                bool ok = ManifestCache::EnsureCached(a, d, g, 0, &notArchived, /*bypassNeg=*/true);
                if (active && !ok && notArchived)
                    Hooks_Manifest::ReportMissingManifest(d, g);
                return 0;
            });
        }

        // Note: a manifest already present in config\depotcache does NOT let us
        // skip this. Measured 2026-09-09 — depot 4889481's manifest was on disk
        // and Steam still requested a code, put it straight into the CDN path
        // (/depot/<d>/manifest/<gid>/5/<code>) and downloaded the manifest
        // afresh. Answering with a placeholder produced 401 on every CDN and
        // "update canceled : Failed downloading 1 manifests". The code is used
        // and must be genuine.
        auto task = std::async(std::launch::async,
            [manifestGid, depotId, appId]() -> uint64 {
                uint64 code = 0;
                ManifestClient::FetchManifestRequestCode(manifestGid, &code, appId, depotId);
                return code;
            });

        {
            std::lock_guard<std::mutex> lock(g_CodeMutex);
            // Sweep replies that never arrived (e.g. batched inside
            // k_EMsgMulti, which RecvJob skips) so the map stays bounded.
            const auto now = std::chrono::steady_clock::now();
            for (auto it = g_CodeFutures.begin(); it != g_CodeFutures.end(); ) {
                if (now - it->second.created > kFutureStaleAfter)
                    it = g_CodeFutures.erase(it);
                else
                    ++it;
            }
            g_CodeFutures[jobId] = CodeFetch{task.share(), now};
        }

        return false; // Don't modify the outgoing request body
    }

    void HandleRecv(const uint8* pBody, uint32 cbBody,
                    const uint8* pHdr, uint32 cbHdr)
    {
        CMsgProtoBufHeader hdr;
        if (!hdr.ParseFromArray(pHdr, cbHdr)){
            LOG_MANIFEST_WARN("GetManifestRequestCode recv: failed to ParseFromArray original header");
            return;
        }

        uint64 jobId = hdr.jobid_target();

        // Passive capture: harvest the genuine code from this reply before the
        // injection path below can overwrite the body. Only real successes for a
        // request we tracked on send; the injected (non-owned) case naturally
        // filters out here because Steam's own reply carries no valid code.
        {
            SentReq sent{0, 0};
            bool tracked = false;
            {
                std::lock_guard<std::mutex> lock(g_SentMutex);
                auto it = g_SentRequests.find(jobId);
                if (it != g_SentRequests.end()) {
                    sent = it->second;
                    tracked = true;
                    g_SentRequests.erase(it);
                }
            }
            if (tracked && hdr.eresult() == static_cast<int32_t>(k_EResultOK)) {
                CContentServerDirectory_GetManifestRequestCode_Response resp;
                if (resp.ParseFromArray(pBody, cbBody) &&
                    resp.has_manifest_request_code() && resp.manifest_request_code()) {
                    const uint64 code = resp.manifest_request_code();
                    LOG_MANIFEST_DEBUG("GetManifestRequestCode recv: captured genuine code "
                                       "for depot={} gid={}", sent.depot, sent.gid);
                    ManifestDonor::SubmitCapturedCode(sent.depot, sent.gid, code);
                }
            }
        }

        std::shared_future<uint64> future;

        {
            std::lock_guard<std::mutex> lock(g_CodeMutex);
            auto it = g_CodeFutures.find(jobId);
            if (it == g_CodeFutures.end()) return;
            future = it->second.future;
            g_CodeFutures.erase(it); // Always clean up immediately
        }
        // Wait up to kMaxWaitSeconds seconds for the HTTP fetch to complete
        auto status = future.wait_for(std::chrono::seconds(kMaxWaitSeconds));
        if (status != std::future_status::ready) {
            LOG_MANIFEST_WARN("GetManifestRequestCode recv: HTTP timed out for jobid={}", jobId);
            return;
        }

        uint64 code = future.get();
        if (!code) {
            LOG_MANIFEST_WARN("GetManifestRequestCode recv: HTTP returned 0 for jobid={}", jobId);
            return;
        }

        LOG_MANIFEST_DEBUG("GetManifestRequestCode recv: injecting code={} for jobid={}",
                            code, jobId);

        // Header: set eresult=OK
        hdr.set_eresult(static_cast<int32_t>(k_EResultOK));
        g_cbNewHdr = static_cast<uint32>(hdr.ByteSizeLong());
        if (g_cbNewHdr > kMaxHdrSize || !hdr.SerializeToArray(g_NewHdr, kMaxHdrSize)){
            LOG_MANIFEST_WARN("GetManifestRequestCode recv: failed to SerializeToArray modified header,"
                    "g_cbNewHdr: {}, kMaxHdrSize: {}", g_cbNewHdr, kMaxHdrSize);
            return;
        }
        g_NeedReplaceHdr = true;

        // Body: set manifest_request_code
        CContentServerDirectory_GetManifestRequestCode_Response resp;
        resp.set_manifest_request_code(code);

        g_cbNewBody = static_cast<uint32>(resp.ByteSizeLong());
        if (g_cbNewBody > kMaxBodySize || !resp.SerializeToArray(g_NewBody, kMaxBodySize)){
            LOG_MANIFEST_WARN("GetManifestRequestCode recv: failed to SerializeToArray modified body,"
                "g_cbNewBody:{}, kMaxBodySize:{}", g_cbNewBody, kMaxBodySize);
            return;
        }
        g_NeedReplaceBody = true;
    }

} // namespace Hooks_NetPacket_Manifest


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_RichPresence
//
//  Outgoing: CMsgClientGamesPlayed   (eMsg 742 / 5410)
//  Incoming: CMsgClientPersonaState  (eMsg 766)
//
//  The server drops friend-side broadcasts for unowned AppIds, so the
//  banner stays on the last cached state.  Cache real self-pushes and
//  re-deliver a patched copy through oRecvPkt by borrowing the next
//  carrier packet's data pointer.
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_RichPresence {

    AppId_t g_PlayingAppId = 0;
    uint64  g_LocalSteamId = 0;

    // Most recent self-PersonaState bytes captured from a real server push.
    // Reused as the template every game launch.
    uint8   g_SelfHdr [kMaxHdrSize];
    uint32  g_cbSelfHdr      = 0;
    uint8   g_SelfBody[kMaxBodySize];
    uint32  g_cbSelfBody     = 0;
    bool    g_HaveSelfCached = false;

    // Manufactured PersonaState packet (eMsg 766) ready to inject.
    uint8   g_InjectPkt[kMaxPacketSize];
    uint32  g_cbInjectPkt   = 0;
    bool    g_InjectPending = false;

    // Rich presence KVs per AppId, captured from outbound
    // CMsgClientRichPresenceUpload.  Per-AppId so a multi-game stack
    // does not conflate KV state.
    std::unordered_map<AppId_t, std::vector<std::pair<std::string, std::string>>> g_RPKvsByAppId;

    // Walk Steam's binary KV1 stream (a top-level "RP" struct around
    // string KVs) and collect every string KV at any depth.  Type 0x00
    // starts a struct, 0x01 a string KV, 0x08 ends a struct.  String KVs
    // are null-terminated key + null-terminated value.
    static void ExtractStringKVs(const uint8* data, uint32 size,
                                 std::vector<std::pair<std::string, std::string>>& out)
    {
        uint32 pos = 0;
        int depth = 0;
        auto readCStr = [&](std::string& s) -> bool {
            uint32 start = pos;
            while (pos < size && data[pos] != 0) ++pos;
            if (pos >= size) return false;
            s.assign(reinterpret_cast<const char*>(data + start), pos - start);
            ++pos;
            return true;
        };
        while (pos < size) {
            uint8 type = data[pos++];
            if (type == 0x08) {
                if (depth > 0) { --depth; continue; }
                break;
            }
            if (type == 0x00) {
                std::string name;
                if (!readCStr(name)) return;
                ++depth;
            } else if (type == 0x01) {
                std::string key, value;
                if (!readCStr(key) || !readCStr(value)) return;
                out.emplace_back(std::move(key), std::move(value));
            } else {
                return;
            }
        }
    }

    // Patch the self Friend entry with the appid (0 = stopped) and per-app
    // KVs.  Mask status_flags's RichPresence bit (0x1000) on appid + empty
    // KVs so a freshly launched game's first inject does not wipe the UI's
    // m_mapRichPresence, which is rebuilt from rich_presence() whenever
    // that bit is set.
    static void ApplyGameFields(CMsgClientPersonaState& msg,
                                CMsgClientPersonaState::Friend* entry,
                                AppId_t appid)
    {
        // EClientPersonaStateFlag::k_EClientPersonaStateFlagRichPresence
        constexpr uint32 kStatusFlagRichPresence = 0x1000;

        if (appid) {
            entry->set_game_played_app_id(appid);
            entry->set_gameid(static_cast<uint64>(appid));
            std::string name = Hooks_Misc::GetGameNameByAppID(appid);
            if (!name.empty()) entry->set_game_name(name);
            entry->clear_rich_presence();
            auto it = g_RPKvsByAppId.find(appid);
            const bool hasKvs = (it != g_RPKvsByAppId.end()) && !it->second.empty();
            if (hasKvs) {
                for (const auto& [k, v] : it->second) {
                    auto* kv = entry->add_rich_presence();
                    kv->set_key(k);
                    kv->set_value(v);
                }
                msg.set_status_flags(msg.status_flags() | kStatusFlagRichPresence);
            } else {
                msg.set_status_flags(msg.status_flags() & ~kStatusFlagRichPresence);
            }
        } else {
            entry->clear_game_played_app_id();
            entry->clear_gameid();
            entry->clear_game_name();
            entry->clear_rich_presence();
            msg.set_status_flags(msg.status_flags() | kStatusFlagRichPresence);
        }
    }

    static bool BuildInject(AppId_t appid)
    {
        if (!g_HaveSelfCached) return false;

        CMsgClientPersonaState msg;
        if (!msg.ParseFromArray(g_SelfBody, g_cbSelfBody)) return false;

        // Find our entry (a self-push always contains it).
        CMsgClientPersonaState::Friend* entry = nullptr;
        for (int i = 0; i < msg.friends_size(); ++i) {
            auto* f = msg.mutable_friends(i);
            if (f->has_friendid() && f->friendid() == g_LocalSteamId) {
                entry = f;
                break;
            }
        }
        if (!entry) return false;

        ApplyGameFields(msg, entry, appid);

        uint32 hdrSize  = g_cbSelfHdr;
        uint32 bodySize = static_cast<uint32>(msg.ByteSizeLong());
        uint32 total    = sizeof(MsgHdr) + hdrSize + bodySize;
        if (total > sizeof(g_InjectPkt) || bodySize > kMaxBodySize) {
            LOG_RICHPRESENCE_WARN("Inject packet too large ({} bytes)", total);
            return false;
        }

        auto* mhdr = reinterpret_cast<MsgHdr*>(g_InjectPkt);
        mhdr->eMsg = static_cast<EMsg>(
            static_cast<uint32>(k_EMsgClientPersonaState) | kMsgHdrProtoFlag);
        mhdr->headerLength = hdrSize;
        memcpy(g_InjectPkt + sizeof(MsgHdr), g_SelfHdr, hdrSize);
        if (!msg.SerializeToArray(g_InjectPkt + sizeof(MsgHdr) + hdrSize, bodySize))
            return false;

        g_cbInjectPkt = total;
        LOG_RICHPRESENCE_INFO("Built inject for appid {} ({} bytes)", appid, total);
        return true;
    }

    // Decode outbound CMsgClientRichPresenceUpload into per-AppId KVs
    // and stage a fresh PersonaState inject.
    void TrackRPSend(const uint8* pBody, uint32 cbBody)
    {
        if (g_LocalSteamId == 0 || g_PlayingAppId == 0) return;

        CMsgClientRichPresenceUpload up;
        if (!up.ParseFromArray(pBody, cbBody)) return;
        if (!up.has_rich_presence_kv()) return;

        const std::string& kv = up.rich_presence_kv();
        auto& kvs = g_RPKvsByAppId[g_PlayingAppId];
        kvs.clear();
        ExtractStringKVs(reinterpret_cast<const uint8*>(kv.data()),
                         static_cast<uint32>(kv.size()), kvs);
        LOG_RICHPRESENCE_DEBUG("RP upload appid={}: kv_bytes={} extracted={} pairs",
            g_PlayingAppId, kv.size(), kvs.size());

        if (BuildInject(g_PlayingAppId)) g_InjectPending = true;
    }

    void TrackSend(const CMsgClientGamesPlayed& msg, const uint8* pHdr, uint32 cbHdr)
    {
        if (g_LocalSteamId == 0) {
            CMsgProtoBufHeader hdr;
            if (hdr.ParseFromArray(pHdr, cbHdr) && hdr.has_steamid() && hdr.steamid()) {
                g_LocalSteamId = hdr.steamid();
                LOG_RICHPRESENCE_DEBUG("Captured local SteamID 0x{:X}", g_LocalSteamId);
                CloudRedirectHost::SetAccountId(
                    static_cast<uint32_t>(g_LocalSteamId & 0xFFFFFFFF));
            }
        }

        // Steam stacks running games in games_played; the banner follows
        // the tail (most recently launched).  Mirror that — only the
        // tail's appid drives our inject.
        AppId_t topmost = 0;
        if (msg.games_played_size() > 0) {
            topmost = static_cast<AppId_t>(
                msg.games_played(msg.games_played_size() - 1).game_id() & UINT32_MAX);
        }

        // Only track when the topmost is an unlocked AppId we can inject for.
        // Owned games on top let the server's natural broadcast paint the
        // cache; -onlinefix games are already handled by the OnlineFix path.
        AppId_t newTracked = 0;
        if (topmost != 0 && topmost != kOnlineFixAppId && LuaConfig::HasDepot(topmost))
            newTracked = topmost;

        if (g_PlayingAppId == newTracked) return;
        AppId_t oldTracked = g_PlayingAppId;
        g_PlayingAppId = newTracked;

        if (oldTracked != 0)
            CloudRedirectHost::NotifyAppRunning(oldTracked, false);
        if (newTracked != 0)
            CloudRedirectHost::NotifyAppRunning(newTracked, true);

        if (newTracked != 0) {
            LOG_RICHPRESENCE_INFO("Tracking topmost appid {}", newTracked);
            if (BuildInject(newTracked)) g_InjectPending = true;
        } else if (topmost == 0) {
            // Stack went empty — inject a clear so the cache reverts.
            LOG_RICHPRESENCE_DEBUG("GamesPlayed empty, scheduling cache clear");
            if (BuildInject(0)) g_InjectPending = true;
        } else {
            // Topmost is owned (or -onlinefix); let the server's broadcast
            // paint it.  Skipping the clear-inject here avoids a brief
            // "Online" flicker between our drop and the server's push.
            LOG_RICHPRESENCE_DEBUG("Topmost is appid {} (owned or onlinefix); deferring to server", topmost);
        }
    }

    // Cache real self-pushes as the inject template; if we are tracking
    // an unowned game, patch the live message in place so a periodic
    // refresh does not overwrite the injected game info.
    bool HandleRecv(const uint8* pBody, uint32 cbBody, const uint8* pHdr, uint32 cbHdr)
    {
        CMsgClientPersonaState msg;
        if (!msg.ParseFromArray(pBody, cbBody)) return false;

        CMsgClientPersonaState::Friend* selfEntry = nullptr;
        for (int i = 0; i < msg.friends_size(); ++i) {
            auto* f = msg.mutable_friends(i);
            if (f->has_friendid() && f->friendid() == g_LocalSteamId) {
                selfEntry = f;
                break;
            }
        }
        if (!selfEntry) return false;

        LOG_RICHPRESENCE_DEBUG(
            "Recv self PersonaState: status_flags=0x{:X} friends_size={}",
            msg.status_flags(), msg.friends_size());

        if (cbHdr <= sizeof(g_SelfHdr) && cbBody <= sizeof(g_SelfBody)) {
            memcpy(g_SelfHdr,  pHdr,  cbHdr);
            memcpy(g_SelfBody, pBody, cbBody);
            g_cbSelfHdr      = cbHdr;
            g_cbSelfBody     = cbBody;
            g_HaveSelfCached = true;
        }

        if (g_PlayingAppId == 0) return false;

        ApplyGameFields(msg, selfEntry, g_PlayingAppId);
        g_cbNewBody = static_cast<uint32>(msg.ByteSizeLong());
        if (g_cbNewBody > kMaxBodySize) {
            LOG_RICHPRESENCE_WARN("In-place patch too large ({} bytes)", g_cbNewBody);
            return false;
        }
        if (!msg.SerializeToArray(g_NewBody, kMaxBodySize)) {
            LOG_RICHPRESENCE_WARN("In-place patch SerializeToArray failed");
            return false;
        }
        LOG_RICHPRESENCE_INFO("Patched live self push with appid {}", g_PlayingAppId);
        return true;
    }

    // Deliver the pending manufactured PersonaState by borrowing the
    // carrier's data pointer for one oRecvPkt call, then restore.
    void TryInject(void* pThis, CNetPacket* pCarrier,
                   bool (*invokeOriginal)(void*, CNetPacket*))
    {
        if (!g_InjectPending || g_cbInjectPkt == 0) return;
        g_InjectPending = false;

        uint8* origData = pCarrier->m_pubData;
        uint32 origSize = pCarrier->m_cubData;
        pCarrier->m_pubData = g_InjectPkt;
        pCarrier->m_cubData = g_cbInjectPkt;
        invokeOriginal(pThis, pCarrier);
        pCarrier->m_pubData = origData;
        pCarrier->m_cubData = origSize;
        LOG_RICHPRESENCE_INFO("Delivered manufactured self-PersonaState ({} bytes)", g_cbInjectPkt);
    }

} // namespace Hooks_NetPacket_RichPresence


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_OnlineFix
//
//  Outgoing: CMsgClientGamesPlayed (eMsg 742 / 5410)
//
//  When a game launched with -onlinefix reports appid 480, replace
//  game_extra_info with the real game's localized name so friends
//  see the correct title.
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_OnlineFix {

    bool HandleSend(const uint8* pBody, uint32 cbBody,
                    const uint8* pHdr, uint32 cbHdr)
    {
        CMsgClientGamesPlayed msg;
        if (!msg.ParseFromArray(pBody, cbBody)) {
            LOG_ONLINEFIX_WARN("OnlineFix: failed to parse CMsgClientGamesPlayed");
            return false;
        }
        LOG_ONLINEFIX_DEBUG("OnlineFix: original body:\n{}", msg.DebugString());

        Hooks_NetPacket_RichPresence::TrackSend(msg, pHdr, cbHdr);

        bool patched = false;
        for (int i = 0; i < msg.games_played_size(); ++i) {
            auto* game = msg.mutable_games_played(i);
            AppId_t appid = static_cast<AppId_t>(game->game_id() & UINT32_MAX);

            // SpawnProcess rewrites pGameID to 480, so game_id is already 480.
            // Fill game_extra_info with the real game name.
            if (appid == kOnlineFixAppId) {
                AppId_t realAppId = Hooks_Misc::ResolveAppId();
                if (realAppId && realAppId != kOnlineFixAppId) {
                    std::string name = Hooks_Misc::GetGameNameByAppID(realAppId);
                    if (!name.empty()) {
                        game->set_game_extra_info(name);
                        patched = true;
                        LOG_ONLINEFIX_INFO("OnlineFix: 480 -> name '{}' (real appid {})",
                            name, realAppId);
                    }
                }
            }
        }

        if (!patched) return false;

        g_cbSendNewBody = static_cast<uint32>(msg.ByteSizeLong());
        if (g_cbSendNewBody > kMaxBodySize) {
            LOG_ONLINEFIX_WARN("OnlineFix: encoded size {} exceeds buffer", g_cbSendNewBody);
            return false;
        }
        if (!msg.SerializeToArray(g_SendNewBody, kMaxBodySize)) {
            LOG_ONLINEFIX_WARN("OnlineFix: failed to SerializeToArray");
            return false;
        }

        LOG_ONLINEFIX_DEBUG("OnlineFix: modified body:\n{}", msg.DebugString());
        return true;
    }

} // namespace Hooks_NetPacket_OnlineFix


// ════════════════════════════════════════════════════════════════
//  Hooks_NetPacket_Cloud
//
//  Steam Cloud save redirection via CloudRedirect (cloud_redirect.dll).
//
//  Outgoing: ServiceMethodCallFromClient (eMsg 151) with target_job_name
//            "Cloud.*" for an addappid()-unlocked game.
//  Incoming: a synthesized ServiceMethodResponse (eMsg 147) carrying the
//            answer produced by CloudRedirect, correlated by jobid.
//
//  CloudRedirect answers the RPC locally (reading/writing the real save
//  bytes to the user's cloud provider). We therefore SUPPRESS the outbound
//  request (it must not reach Valve) and DELIVER the response the same way
//  the RichPresence path injects packets: by borrowing the next inbound
//  "carrier" packet for one oRecvPkt call (CloudRedirect's "Approach D").
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_Cloud {

    std::mutex                     g_queueMutex;
    std::deque<std::vector<uint8>> g_pending;        // ready-to-inject 147 packets
    uint64                         g_localSteamId = 0;

    // ── minimal top-level protobuf varint field reader ──────────
    // Avoids pulling the Cloud.* request message definitions into the
    // proto set just to read one appid field.
    static bool ReadVarint(const uint8* d, uint32 size, uint32& pos, uint64& out) {
        out = 0;
        int shift = 0;
        while (pos < size) {
            uint8 b = d[pos++];
            out |= static_cast<uint64>(b & 0x7F) << shift;
            if (!(b & 0x80)) return true;
            shift += 7;
            if (shift >= 64) return false;
        }
        return false;
    }

    static bool FindVarintField(const uint8* d, uint32 size, uint32 target, uint64& out) {
        uint32 pos = 0;
        while (pos < size) {
            uint64 tag;
            if (!ReadVarint(d, size, pos, tag)) return false;
            const uint32 field   = static_cast<uint32>(tag >> 3);
            const uint32 wireType = static_cast<uint32>(tag & 7);
            if (field == target && wireType == 0)
                return ReadVarint(d, size, pos, out);

            switch (wireType) {
            case 0: { uint64 tmp; if (!ReadVarint(d, size, pos, tmp)) return false; break; }
            case 1: if (pos + 8 > size) return false; pos += 8; break;
            case 5: if (pos + 4 > size) return false; pos += 4; break;
            case 2: {
                uint64 len;
                if (!ReadVarint(d, size, pos, len)) return false;
                if (pos + len > size) return false;
                pos += static_cast<uint32>(len);
                break;
            }
            default: return false;   // groups (3/4) — bail
            }
        }
        return false;
    }

    // appid lives in field 1 of every Cloud.* request except
    // ClientCommitFileUpload, where it is field 2 (mirrors CloudRedirect's
    // CloudRpcUtils::ExtractAppId).
    static uint32 ExtractAppId(const char* jobName, const uint8* body, uint32 cbBody) {
        uint32 fieldNum = 1;
        if (std::strcmp(jobName, "Cloud.ClientCommitFileUpload#1") == 0)
            fieldNum = 2;
        uint64 v = 0;
        if (FindVarintField(body, cbBody, fieldNum, v))
            return static_cast<uint32>(v);
        return 0;
    }

    // Returns true when CloudRedirect handled the request — the caller must
    // then suppress the outbound frame.
    bool HandleSend(const char* jobName,
                    const uint8* pBody, uint32 cbBody,
                    const uint8* pHdr, uint32 cbHdr)
    {
        if (!CloudRedirectHost::IsActive()) return false;

        CMsgProtoBufHeader reqHdr;
        if (!reqHdr.ParseFromArray(pHdr, cbHdr)) return false;
        if (reqHdr.has_steamid() && reqHdr.steamid())
            g_localSteamId = reqHdr.steamid();

        const uint32 appId = ExtractAppId(jobName, pBody, cbBody);
        if (appId == 0 || !CloudRedirectHost::IsApp(appId)) return false;

        const uint32 accountId = static_cast<uint32>(g_localSteamId & 0xFFFFFFFFull);

        static thread_local uint8 respBuf[kMaxBodySize];
        uint32  respLen  = 0;
        int32_t eresult  = 2;   // EResult::Fail
        if (!CloudRedirectHost::HandleCloudRpc(jobName, appId, accountId,
                                               pBody, cbBody,
                                               respBuf, static_cast<uint32_t>(sizeof(respBuf)),
                                               &respLen, &eresult)) {
            return false;   // not a namespace app / unrecognised — let it pass through
        }

        // Build the 147 ServiceMethodResponse correlated to the request job.
        CMsgProtoBufHeader respHdr;
        if (reqHdr.has_jobid_source()) respHdr.set_jobid_target(reqHdr.jobid_source());
        respHdr.set_eresult(eresult);
        respHdr.set_target_job_name(jobName);

        const uint32 cbRespHdr = static_cast<uint32>(respHdr.ByteSizeLong());
        const uint32 total     = sizeof(MsgHdr) + cbRespHdr + respLen;
        if (cbRespHdr > kMaxHdrSize || respLen > kMaxBodySize || total > kMaxPacketSize) {
            // Can't deliver a response this big — fall through so Steam errors
            // normally instead of leaving the job hung.
            LOG_NETPACKET_WARN("Cloud: {} response too large ({} bytes), passing through",
                               jobName, total);
            return false;
        }

        std::vector<uint8> pkt(total);
        auto* mhdr = reinterpret_cast<MsgHdr*>(pkt.data());
        mhdr->eMsg = static_cast<EMsg>(
            static_cast<uint32>(k_EMsgServiceMethodResponse) | kMsgHdrProtoFlag);
        mhdr->headerLength = cbRespHdr;
        if (!respHdr.SerializeToArray(pkt.data() + sizeof(MsgHdr), cbRespHdr))
            return false;
        if (respLen)
            memcpy(pkt.data() + sizeof(MsgHdr) + cbRespHdr, respBuf, respLen);

        {
            std::lock_guard lk(g_queueMutex);
            if (g_pending.size() < 64)
                g_pending.push_back(std::move(pkt));
        }
        LOG_NETPACKET_DEBUG("Cloud: handled {} app={} -> queued {}-byte response (eresult={})",
                            jobName, appId, total, eresult);
        return true;
    }

    // Deliver any queued cloud responses by borrowing the carrier packet for
    // one oRecvPkt call each (same trick as RichPresence::TryInject). Runs on
    // the network thread from inside the RecvPkt hook.
    void Drain(void* pThis, CNetPacket* pCarrier,
               bool (*invokeOriginal)(void*, CNetPacket*))
    {
        for (;;) {
            std::vector<uint8> pkt;
            {
                std::lock_guard lk(g_queueMutex);
                if (g_pending.empty()) return;
                pkt = std::move(g_pending.front());
                g_pending.pop_front();
            }

            uint8* origData = pCarrier->m_pubData;
            uint32 origSize = pCarrier->m_cubData;
            pCarrier->m_pubData = pkt.data();
            pCarrier->m_cubData = static_cast<uint32>(pkt.size());
            invokeOriginal(pThis, pCarrier);
            pCarrier->m_pubData = origData;
            pCarrier->m_cubData = origSize;
            LOG_NETPACKET_DEBUG("Cloud: delivered {}-byte response", pkt.size());
        }
    }

} // namespace Hooks_NetPacket_Cloud


// ════════════════════════════════════════════════════════════════
//  Legacy third-party CD key ("Updating product key")
//
//  k_EMsgClientGetLegacyGameKey (730) is a non-proto STRUCT message, so it
//  never reaches the proto SendJob/RecvJob path (UnpackRaw bails on the missing
//  proto flag). We catch the outbound request straight off the send hook,
//  answer it locally with a resolved key, suppress the real send, and deliver
//  the synthesized 785 response from the RecvPkt hook — the exact "answered
//  locally" trick Hooks_NetPacket_Cloud uses.
// ════════════════════════════════════════════════════════════════
namespace Hooks_NetPacket_LegacyKey {

    std::mutex                     g_queueMutex;
    std::deque<std::vector<uint8>> g_pending;   // ready-to-inject 785 struct frames

    // Returns true when we answered the request locally — the caller must then
    // suppress the outbound frame.
    bool HandleSend(const uint8* pubData, uint32 cubData) {
        if (cubData < sizeof(ExtendedMsgHdr) + sizeof(MsgClientGetLegacyGameKey))
            return false;

        const auto* reqHdr  = reinterpret_cast<const ExtendedMsgHdr*>(pubData);
        const auto* reqBody = reinterpret_cast<const MsgClientGetLegacyGameKey*>(
                                  pubData + sizeof(ExtendedMsgHdr));
        const AppId_t appId     = reqBody->m_unAppId;
        const uint32  accountId = static_cast<uint32>(reqHdr->m_ulSteamID & 0xFFFFFFFFull);

        std::optional<std::string> key = LegacyCDKey::Resolve(appId, accountId);
        if (!key) return false;   // not a managed app — let Steam's real flow run

        // Steam stores the legacy key as a NUL-terminated string; length counts
        // the terminator. (One runtime-verify point — see plan.)
        const uint32 cchKey = static_cast<uint32>(key->size()) + 1;
        const uint32 total  = sizeof(ExtendedMsgHdr)
                            + sizeof(MsgClientGetLegacyGameKeyResponse) + cchKey;
        if (total > kMaxPacketSize) {
            LOG_NETPACKET_WARN("LegacyKey: app={} response too large ({} bytes), passing through",
                               appId, total);
            return false;
        }

        std::vector<uint8> pkt(total);
        auto* rh = reinterpret_cast<ExtendedMsgHdr*>(pkt.data());
        *rh = *reqHdr;                                            // keep version/canary/steamid/session
        rh->eMsg          = k_EMsgClientGetLegacyGameKeyResponse; // non-proto (flag stays clear)
        rh->m_JobIDTarget = reqHdr->m_JobIDSource;               // correlate response to request
        rh->m_JobIDSource = k_GIDNil;

        auto* rb = reinterpret_cast<MsgClientGetLegacyGameKeyResponse*>(
                       pkt.data() + sizeof(ExtendedMsgHdr));
        rb->m_unAppId = appId;
        rb->m_eResult = k_EResultOK;
        rb->m_cchKey  = cchKey;
        memcpy(pkt.data() + sizeof(ExtendedMsgHdr) + sizeof(MsgClientGetLegacyGameKeyResponse),
               key->c_str(), cchKey);                             // includes the NUL

        {
            std::lock_guard lk(g_queueMutex);
            if (g_pending.size() < 64)
                g_pending.push_back(std::move(pkt));
        }
        LOG_NETPACKET_DEBUG("LegacyKey: app={} answered locally ({} bytes, key '{}')",
                            appId, total, *key);
        return true;
    }

    // Deliver queued responses by borrowing the carrier packet for one oRecvPkt
    // call each — identical to Hooks_NetPacket_Cloud::Drain. Runs on the network
    // thread from inside the RecvPkt hook.
    void Drain(void* pThis, CNetPacket* pCarrier,
               bool (*invokeOriginal)(void*, CNetPacket*))
    {
        for (;;) {
            std::vector<uint8> pkt;
            {
                std::lock_guard lk(g_queueMutex);
                if (g_pending.empty()) return;
                pkt = std::move(g_pending.front());
                g_pending.pop_front();
            }

            uint8* origData = pCarrier->m_pubData;
            uint32 origSize = pCarrier->m_cubData;
            pCarrier->m_pubData = pkt.data();
            pCarrier->m_cubData = static_cast<uint32>(pkt.size());
            invokeOriginal(pThis, pCarrier);
            pCarrier->m_pubData = origData;
            pCarrier->m_cubData = origSize;
            LOG_NETPACKET_DEBUG("LegacyKey: delivered {}-byte response", pkt.size());
        }
    }

} // namespace Hooks_NetPacket_LegacyKey


// ════════════════════════════════════════════════════════════════
//  Dispatch
// ════════════════════════════════════════════════════════════════
namespace {

    bool SendServiceJob(const char* targetJobName,
                        const uint8* pBody, uint32 cbBody,
                        const uint8* pHdr, uint32 cbHdr)
    {
        LOG_NETPACKET_DEBUG("Send target_job_name: {}", targetJobName);

        // Steam Cloud save redirection: hand every "Cloud.*" request to
        // CloudRedirect. If it answers, suppress the outbound frame (the
        // synthesized response is delivered from the RecvPkt hook).
        // ExitSyncDone/ConflictResolution are notifications that must reach
        // Steam's internal cloud state machine untouched.
        if (std::strncmp(targetJobName, "Cloud.", 6) == 0) {
            if (std::strcmp(targetJobName, "Cloud.SignalAppExitSyncDone#1") == 0 ||
                std::strcmp(targetJobName, "Cloud.ClientConflictResolution#1") == 0)
                return false;
            if (Hooks_NetPacket_Cloud::HandleSend(targetJobName, pBody, cbBody, pHdr, cbHdr))
                g_SuppressSend = true;
            return false;   // never body-replace a cloud frame
        }

        switch (Fnv1aHash(targetJobName)) {

        case HASH_JOB_GetUserStats:
            return Hooks_NetPacket_UserStats::HandleSend_GetUserStats(pBody, cbBody, pHdr, cbHdr);

        case HASH_JOB_GetManifestRequestCode:
            return Hooks_NetPacket_Manifest::HandleSend(pBody, cbBody, pHdr, cbHdr);

        // ---- add new 151 service methods here ----
        }
        return false;
    }

    void SendJob(EMsg eMsg, const uint8* pBody, uint32 cbBody,
                 const uint8* pHdr, uint32 cbHdr)
    {
        g_NeedReplaceSend = false;
        g_SuppressSend    = false;

        LOG_NETPACKET_DEBUG("Send eMsg {}({}) (cbBody={}, cbHdr={})",
                        MsgName(eMsg), static_cast<uint32>(eMsg), cbBody, cbHdr);

        switch (eMsg) {

        case k_EMsgServiceMethodCallFromClient: {   // 151
            // Keep one real header as a template for originated requests.
            Hooks_NetPacket_ManifestProbe::CaptureContext(nullptr, nullptr, pHdr, cbHdr);
            CMsgProtoBufHeader hdr;
            if (hdr.ParseFromArray(pHdr, cbHdr) && hdr.has_target_job_name()) {
                g_NeedReplaceSend = SendServiceJob(hdr.target_job_name().c_str(), pBody, cbBody, pHdr, cbHdr);
            }
            return;
        }

        case k_EMsgClientPICSProductInfoRequest:     // 8903
            g_NeedReplaceSend = Hooks_NetPacket_AccessToken::HandleSend(pBody, cbBody);
            return;

        case k_EMsgClientGamesPlayed:                 // 742
        case k_EMsgClientGamesPlayedWithDataBlob:     // 5410
            g_NeedReplaceSend = Hooks_NetPacket_OnlineFix::HandleSend(pBody, cbBody, pHdr, cbHdr);
            return;

        case k_EMsgClientRichPresenceUpload:           // 7501
            Hooks_NetPacket_RichPresence::TrackRPSend(pBody, cbBody);
            return;

        case k_EMsgClientGetUserStats:               // 818
            g_NeedReplaceSend = Hooks_NetPacket_UserStats::HandleSend_ClientGetUserStats(pBody, cbBody);
            return;

        case k_EMsgClientStoreUserStats: {          // 820
            // Local-only journal + synthesized ack; suppresses the real send
            // so nothing reaches the online profile.
            if (Hooks_NetPacket_UserStats::HandleSend_StoreUserStats(pBody, cbBody, pHdr, cbHdr))
                g_SuppressSend = true;
            return;
        }

        case k_EMsgClientStoreUserStats2: {         // 5466
            // Same local-only path (game_id parsed from the body, which also
            // fixes the old g_PlayingAppId approximation).
            if (Hooks_NetPacket_UserStats::HandleSend_StoreUserStats2(pBody, cbBody, pHdr, cbHdr))
                g_SuppressSend = true;
            return;
        }

        default:
            return;
        }
    }

    void RecvServiceJob(const char* targetJobName,
                        const uint8* pBody, uint32 cbBody,
                        const uint8* pHdr, uint32 cbHdr)
    {
        LOG_NETPACKET_DEBUG("Recv target_job_name: {}", targetJobName);
        g_NeedReplaceBody = false;
        g_NeedReplaceHdr  = false;

        switch (Fnv1aHash(targetJobName)) {

        case HASH_JOB_NotifyRunningApps:
            Hooks_NetPacket_FamilySharing::ClearBody(pBody, cbBody);
            return;

        case HASH_JOB_GetUserStats:
            Hooks_NetPacket_UserStats::HandleRecv_GetUserStatsResponse(pHdr, cbHdr, pBody, cbBody);
            return;

        case HASH_JOB_GetManifestRequestCode:
            // Replies to our own originated requests are consumed here; the
            // normal handler would ignore them anyway, but this keeps the two
            // paths from ever having to reason about each other.
            if (Hooks_NetPacket_ManifestProbe::HandleRecv(pBody, cbBody, pHdr, cbHdr))
                return;
            Hooks_NetPacket_Manifest::HandleRecv(pBody, cbBody, pHdr, cbHdr);
            return;

        // ---- add new 147 service methods here ----
        }
    }

    void RecvJob(EMsg eMsg, const uint8* pBody, uint32 cbBody,
                 const uint8* pHdr, uint32 cbHdr)
    {
        g_NeedReplaceBody = false;
        g_NeedReplaceHdr  = false;

        if(eMsg == k_EMsgMulti) {
            LOG_NETPACKET_TRACE("Received k_EMsgMulti, skipping dispatch");
            return;
        }
        LOG_NETPACKET_DEBUG("Recv eMsg {}({}) (cbBody={}, cbHdr={})",
                        MsgName(eMsg), static_cast<uint32>(eMsg), cbBody, cbHdr);

        switch (eMsg) {

        case k_EMsgServiceMethodResponse: {     // 147
            CMsgProtoBufHeader hdr;
            if (hdr.ParseFromArray(pHdr, cbHdr) && hdr.has_target_job_name())
                RecvServiceJob(hdr.target_job_name().c_str(), pBody, cbBody, pHdr, cbHdr);
            return;
        }

        // migrated to IPC Layer Hooks_IPC_ISteamUser::GetEncryptedAppTicketResponse
        // case k_EMsgClientRequestEncryptedAppTicketResponse:     // 5527
        //     Hooks_NetPacket_ETicket::HandleEncryptedAppTicketResponse(pBody, cbBody);
        //     return;

        case k_EMsgClientGetUserStatsResponse:     // 819
            g_NeedReplaceBody = Hooks_NetPacket_UserStats::HandleRecv_ClientGetUserStatsResponse(
                pBody, cbBody);
            return;

        case k_EMsgClientSharedLibraryStopPlaying:     // 9406
            Hooks_NetPacket_FamilySharing::ClearBody(pBody, cbBody);
            return;

        case k_EMsgClientPersonaState:                 // 766
            g_NeedReplaceBody = Hooks_NetPacket_RichPresence::HandleRecv(pBody, cbBody, pHdr, cbHdr);
            return;

        case k_EMsgClientGetAppOwnershipTicketResponse:   // 858
            Hooks_NetPacket_OwnershipTicket::HandleRecv(pBody, cbBody);
            return;

        case k_EMsgClientLicenseList:                  // 780
            Hooks_NetPacket_Licenses::HandleRecv(pBody, cbBody);
            return;

        default:
            return;
        }
    }

    // ════════════════════════════════════════════════════════════
    //  Hooks
    // ════════════════════════════════════════════════════════════

    HOOK_FUNC(BBuildAndAsyncSendFrame, bool,
              void* pObject, EWebSocketOpCode eWebSocketOpCode,
              uint8* pubData, uint32 cubData)
    {
        if (eWebSocketOpCode != k_eWebSocketOpCode_Binary)
            return oBBuildAndAsyncSendFrame(pObject, eWebSocketOpCode, pubData, cubData);

        // The connection object is only ever visible here, and originating a
        // request needs it. Captured on every binary frame so it tracks a
        // reconnect rather than going stale.
        Hooks_NetPacket_ManifestProbe::CaptureContext(
            pObject, oBBuildAndAsyncSendFrame, nullptr, 0);

        // Legacy CD-key request (EMsg 730) is a non-proto struct message that
        // UnpackRaw skips. Intercept it here: if we answer it locally, suppress
        // the real send (the 785 response is delivered from the RecvPkt hook).
        if (cubData >= sizeof(ExtendedMsgHdr)) {
            const uint32 rawEMsg = *reinterpret_cast<const uint32*>(pubData);
            if (!(rawEMsg & kMsgHdrProtoFlag) &&
                static_cast<EMsg>(rawEMsg) == k_EMsgClientGetLegacyGameKey &&
                Hooks_NetPacket_LegacyKey::HandleSend(pubData, cubData)) {
                return true;   // answered locally; report success so Steam treats it as sent
            }
        }

        // 820 arriving WITHOUT the proto flag never reaches SendJob
        // (UnpackRaw bails). Journal it locally all the same so the store
        // cannot leak to the online profile through that path.
        if (cubData >= sizeof(MsgHdr)) {
            const uint32 rawEMsg = *reinterpret_cast<const uint32*>(pubData);
            if (!(rawEMsg & kMsgHdrProtoFlag) &&
                static_cast<EMsg>(rawEMsg) == k_EMsgClientStoreUserStats &&
                Hooks_NetPacket_UserStats::HandleSend_StoreUserStats_Raw(pubData, cubData)) {
                return true;   // journaled locally; report success so Steam treats it as sent
            }
        }

        EMsg eMsg;
        const uint8 *pHdr, *pBody;
        uint32 cbHdr, cbBody;
        bool result;
        if (UnpackRaw(pubData, cubData, eMsg, pHdr, cbHdr, pBody, cbBody)) {
            SendJob(eMsg, pBody, cbBody, pHdr, cbHdr);

            if (g_SuppressSend) {
                // CloudRedirect answered this RPC locally; do not forward to
                // Valve. Report success so Steam treats the frame as sent.
                return true;
            }

            if (g_NeedReplaceSend) {
                uint32 newSize = 0;
                uint8* buf = ReplaceSendPacket(pubData, cbHdr, pHdr,
                                               g_SendNewBody, g_cbSendNewBody, &newSize);
                result = buf
                    ? oBBuildAndAsyncSendFrame(pObject, eWebSocketOpCode, buf, newSize)
                    : oBBuildAndAsyncSendFrame(pObject, eWebSocketOpCode, pubData, cubData);
            } else {
                result = oBBuildAndAsyncSendFrame(pObject, eWebSocketOpCode, pubData, cubData);
            }
        } else {
            result = oBBuildAndAsyncSendFrame(pObject, eWebSocketOpCode, pubData, cubData);
        }

        return result;
    }

    HOOK_FUNC(RecvPkt, void*, void* pThis, CNetPacket* pPacket)
    {
        Hooks_NetPacket_RichPresence::TryInject(
            pThis, pPacket,
            [](void* pT, CNetPacket* pP) -> bool { return oRecvPkt(pT, pP) != nullptr; });

        Hooks_NetPacket_Cloud::Drain(
            pThis, pPacket,
            [](void* pT, CNetPacket* pP) -> bool { return oRecvPkt(pT, pP) != nullptr; });

        Hooks_NetPacket_LegacyKey::Drain(
            pThis, pPacket,
            [](void* pT, CNetPacket* pP) -> bool { return oRecvPkt(pT, pP) != nullptr; });

        Hooks_NetPacket_UserStats::DrainStoreResponses(
            pThis, pPacket,
            [](void* pT, CNetPacket* pP) -> bool { return oRecvPkt(pT, pP) != nullptr; });

        EMsg eMsg;
        const uint8 *pBody, *pHdr;
        uint32 cbBody, cbHdr;
        if (UnpackRaw(pPacket->m_pubData, pPacket->m_cubData,
                     eMsg, pHdr, cbHdr, pBody, cbBody)) {
            g_ResizedInPlace = false;
            RecvJob(eMsg, pBody, cbBody, pHdr, cbHdr);

            if (g_ResizedInPlace && g_NeedReplaceHdr) {
                // Body shrunk in-place + header changed -> full replace via pool
                ReplaceRecvPacket(pPacket,
                    g_NewHdr, g_cbNewHdr,
                    pBody, g_NewBodySize);
            } else if (g_ResizedInPlace) {
                pPacket->m_cubData = sizeof(MsgHdr) + cbHdr + g_NewBodySize;
            } else if (g_NeedReplaceHdr || g_NeedReplaceBody) {
                ReplaceRecvPacket(pPacket,
                    g_NeedReplaceHdr  ? g_NewHdr  : pHdr,
                    g_NeedReplaceHdr  ? g_cbNewHdr : cbHdr,
                    g_NeedReplaceBody ? g_NewBody : pBody,
                    g_NeedReplaceBody ? g_cbNewBody : cbBody);
            }
        }

        return oRecvPkt(pThis, pPacket);
    }

} // anonymous namespace


namespace Hooks_NetPacket {
    void Install() {
        RESOLVE_C(PchMsgNameFromEMsg);
        HOOK_BEGIN();
        INSTALL_HOOK_C(BBuildAndAsyncSendFrame);
        INSTALL_HOOK_C(RecvPkt);
        HOOK_END();
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK(BBuildAndAsyncSendFrame);
        UNINSTALL_HOOK(RecvPkt);
        UNHOOK_END();
    }

    std::future<uint64_t> RequestManifestCode(AppId_t appId, uint32_t depotId, uint64_t gid) {
        return Hooks_NetPacket_ManifestProbe::Request(appId, depotId, gid);
    }

    bool ProbeManifest(uint32_t depotId) {
        AppId_t  appId = 0;
        uint64_t gid   = 0;
        if (!Hooks_Manifest::LookupDepot(depotId, appId, gid)) {
            LOG_MANIFEST_WARN("ManifestProbe: depot {} not seen yet - it only becomes known "
                              "once its app is installed or updated in this session", depotId);
            return false;
        }
        // Fire and forget: the recv handler logs the outcome. Detached so the
        // config-watcher thread is not blocked on a network round-trip.
        auto fut = std::make_shared<std::future<uint64_t>>(
            Hooks_NetPacket_ManifestProbe::Request(appId, depotId, gid));
        std::thread([fut] { fut->wait(); }).detach();
        return true;
    }
}
