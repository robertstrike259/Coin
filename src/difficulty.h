#pragma once
#include "uint256.h"
#include <cstdint>
// Bitcoin compact nBits <-> target.
uint256 bitsToTarget(uint32_t bits);
uint32_t targetToBits(const uint256& t);
bool hashMeetsBits(const uint256& h, uint32_t bits);
uint32_t retargetBits(uint32_t oldBits, int64_t actualSecs, int64_t targetSecs);
