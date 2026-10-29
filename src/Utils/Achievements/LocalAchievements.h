#pragma once

#include "Steam/Types.h"

#include <cstdint>
#include <string>
#include <unordered_map>

// Reads the Steam client's own local achievement state for a game off disk:
//   <steam>/appcache/stats/UserGameStatsSchema_<app>.bin   (names <-> stat/bit)
//   <steam>/appcache/stats/UserGameStats_<acct>_<app>.bin   (per-bit unlocks)
// and joins them into api_name -> unlock state. Used to rebuild the new
// Player.GetUserAchievements#1 response (which Valve returns empty for unowned
// games), keyed later by internal_key via the GetGameAchievements schema.
namespace LocalAchievements {

    struct Unlock {
        bool     unlocked = false;
        uint32_t unlockTime = 0;   // unix seconds, 0 if none recorded
        float    progress = 0.0f;  // current value of the schema's progress stat
    };

    // api_name (schema "name" == GetGameAchievements internal_name) -> unlock.
    // Empty on any read/parse failure (missing files, etc).
    std::unordered_map<std::string, Unlock> Read(AppId_t appId, AccountID_t accountId);

} // namespace LocalAchievements
