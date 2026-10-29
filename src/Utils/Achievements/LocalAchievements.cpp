#include "LocalAchievements.h"

#include "dllmain.h"
#include "Utils/Logging/Log.h"

#include <cstring>
#include <fstream>
#include <vector>

namespace LocalAchievements {
namespace {

    // ── Binary KeyValues reader (ported from CloudRedirect stats_store.cpp) ──
    // Steam's UserGameStats*.bin are BKV trees; self-contained parse so we
    // never touch the client's KeyValues allocator.
    enum BkvType : uint8_t {
        BKV_SECTION = 0x00,
        BKV_STRING  = 0x01,
        BKV_INT     = 0x02,
        BKV_FLOAT   = 0x03,
        BKV_UINT64  = 0x07,
        BKV_END     = 0x08,
        BKV_INT64   = 0x0A,
    };

    struct BkvNode {
        BkvType type{};
        std::string name;
        uint32_t intVal = 0;
        std::string strVal;
        std::vector<BkvNode> children;
    };

    constexpr int    BKV_MAX_DEPTH = 128;
    constexpr size_t BKV_MAX_NODES = 200000;

    bool BkvRead(const uint8_t* data, size_t len, size_t& pos,
                 std::vector<BkvNode>& out, int depth, size_t& totalNodes) {
        if (depth > BKV_MAX_DEPTH) return false;
        while (pos < len) {
            uint8_t tag = data[pos++];
            if (tag == BKV_END) return true;

            BkvNode node;
            node.type = static_cast<BkvType>(tag);

            const char* nameStart = reinterpret_cast<const char*>(data + pos);
            size_t nameEnd = pos;
            while (nameEnd < len && data[nameEnd] != 0) nameEnd++;
            if (nameEnd >= len) return false;
            node.name.assign(nameStart, nameEnd - pos);
            pos = nameEnd + 1;

            switch (node.type) {
            case BKV_SECTION:
                if (!BkvRead(data, len, pos, node.children, depth + 1, totalNodes))
                    return false;
                break;
            case BKV_STRING: {
                const char* s = reinterpret_cast<const char*>(data + pos);
                size_t end = pos;
                while (end < len && data[end] != 0) end++;
                if (end >= len) return false;
                node.strVal.assign(s, end - pos);
                pos = end + 1;
                break;
            }
            case BKV_INT:
            case BKV_FLOAT:
                if (pos + 4 > len) return false;
                std::memcpy(&node.intVal, data + pos, 4);
                pos += 4;
                break;
            case BKV_UINT64:
            case BKV_INT64:
                if (pos + 8 > len) return false;
                // Only the low 32 bits matter for our use (bitfields / times).
                std::memcpy(&node.intVal, data + pos, 4);
                pos += 8;
                break;
            default:
                return false;
            }
            if (++totalNodes > BKV_MAX_NODES) return false;
            out.push_back(std::move(node));
        }
        return depth == 0;
    }

    const BkvNode* Find(const std::vector<BkvNode>& nodes, const char* name) {
        for (const auto& n : nodes)
            if (n.name == name) return &n;
        return nullptr;
    }

    bool IsNumeric(const std::string& s) {
        if (s.empty()) return false;
        for (char c : s) if (c < '0' || c > '9') return false;
        return true;
    }

    std::vector<uint8_t> ReadFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return {};
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                     std::istreambuf_iterator<char>());
    }

    bool ParseTree(const std::vector<uint8_t>& blob, std::vector<BkvNode>& root) {
        if (blob.empty()) return false;
        size_t pos = 0, nodes = 0;
        return BkvRead(blob.data(), blob.size(), pos, root, 0, nodes);
    }

    std::string StatsDir() {
        return std::string(SteamInstallPath) + "\\appcache\\stats\\";
    }

} // namespace

std::unordered_map<std::string, Unlock> Read(AppId_t appId, AccountID_t accountId) {
    std::unordered_map<std::string, Unlock> result;
    if (!SteamInstallPath[0] || accountId == 0) return result;

    const std::string dir = StatsDir();

    // ── schema: (statId<<32 | bit) -> api name ──
    std::vector<BkvNode> schemaRoot;
    if (!ParseTree(ReadFile(dir + "UserGameStatsSchema_" + std::to_string(appId) + ".bin"),
                   schemaRoot)) {
        LOG_ACHIEVEMENT_DEBUG("LocalAchievements: no schema .bin for app={}", appId);
        return result;
    }
    // Root is a single <appId> section; descend to "stats".
    const BkvNode* statsSec = nullptr;
    for (const auto& top : schemaRoot) {
        if (top.type != BKV_SECTION) continue;
        if (const BkvNode* s = Find(top.children, "stats")) { statsSec = s; break; }
        if (top.name == "stats") { statsSec = &top; break; }
    }
    if (!statsSec) return result;

    std::unordered_map<uint64_t, std::string> bitToName;
    std::unordered_map<std::string, uint32_t> statNameToId;      // "stat_1" -> 3
    std::unordered_map<std::string, std::string> progressStat;   // api name -> stat name
    for (const auto& stat : statsSec->children) {
        if (stat.type != BKV_SECTION || !IsNumeric(stat.name)) continue;
        uint32_t statId = static_cast<uint32_t>(strtoul(stat.name.c_str(), nullptr, 10));
        if (const BkvNode* sn = Find(stat.children, "name"))
            statNameToId[sn->strVal] = statId;
        const BkvNode* bits = Find(stat.children, "bits");
        if (!bits) continue;
        for (const auto& b : bits->children) {
            if (b.type != BKV_SECTION || !IsNumeric(b.name)) continue;
            uint32_t bit = static_cast<uint32_t>(strtoul(b.name.c_str(), nullptr, 10));
            if (bit >= 32) continue;
            const BkvNode* nm = Find(b.children, "name");
            if (!nm) continue;
            bitToName[(static_cast<uint64_t>(statId) << 32) | bit] = nm->strVal;
            // progress { value { operation="statvalue" operand1="<stat name>" } }
            if (const BkvNode* p = Find(b.children, "progress"))
                if (const BkvNode* v = Find(p->children, "value"))
                    if (const BkvNode* op = Find(v->children, "operation"); op && op->strVal == "statvalue")
                        if (const BkvNode* o1 = Find(v->children, "operand1"))
                            progressStat[nm->strVal] = o1->strVal;
        }
    }
    if (bitToName.empty()) return result;

    // Every schema achievement starts locked; the stats file flips unlocked ones.
    for (auto& [key, name] : bitToName) result[name] = Unlock{};

    // ── user stats: cache > <statId> > data (bitfield) + AchievementTimes ──
    std::vector<BkvNode> statsRoot;
    if (!ParseTree(ReadFile(dir + "UserGameStats_" + std::to_string(accountId) +
                            "_" + std::to_string(appId) + ".bin"), statsRoot)) {
        // No local unlocks yet: return all-locked (still a valid, complete list).
        return result;
    }
    const BkvNode* cache = Find(statsRoot, "cache");
    if (!cache) return result;

    size_t unlocked = 0;
    std::unordered_map<uint32_t, float> statValue;   // statId -> current value
    for (const auto& stat : cache->children) {
        if (stat.type != BKV_SECTION || !IsNumeric(stat.name)) continue;  // skip crc/PendingChanges
        uint32_t statId = static_cast<uint32_t>(strtoul(stat.name.c_str(), nullptr, 10));
        const BkvNode* dataNode = Find(stat.children, "data");
        uint32_t bitfield = dataNode ? dataNode->intVal : 0;
        if (dataNode) {
            float v;
            if (dataNode->type == BKV_FLOAT) std::memcpy(&v, &dataNode->intVal, 4);
            else v = static_cast<float>(static_cast<int32_t>(dataNode->intVal));
            statValue[statId] = v;
        }
        const BkvNode* times = Find(stat.children, "AchievementTimes");

        for (uint32_t bit = 0; bit < 32; bit++) {
            bool isUnlocked = (bitfield >> bit) & 1u;
            uint32_t t = 0;
            if (times) {
                if (const BkvNode* tn = Find(times->children, std::to_string(bit).c_str())) {
                    t = tn->intVal;
                    isUnlocked = true;   // a recorded time means unlocked
                }
            }
            if (!isUnlocked) continue;
            auto nit = bitToName.find((static_cast<uint64_t>(statId) << 32) | bit);
            if (nit == bitToName.end()) continue;
            result[nit->second].unlocked = true;
            result[nit->second].unlockTime = t;
            ++unlocked;
        }
    }

    for (const auto& [name, statName] : progressStat) {
        auto sid = statNameToId.find(statName);
        if (sid == statNameToId.end()) continue;
        if (auto sv = statValue.find(sid->second); sv != statValue.end())
            result[name].progress = sv->second;
    }

    LOG_ACHIEVEMENT_INFO("LocalAchievements: app={} acct={} -> {}/{} unlocked",
                         appId, accountId, unlocked, result.size());
    return result;
}

} // namespace LocalAchievements
