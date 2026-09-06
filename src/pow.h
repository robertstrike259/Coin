#pragma once
#include "core.h"
#include "chainparams.h"
#include "uint256.h"
#include <vector>
// PoW: Argon2id(header80, salt) -> uint256 LE. Uses system libargon2 if present else bundled.
uint256 powHash(const BlockHeader& h, const ChainParams& p);
bool checkPow(const BlockHeader& h, const ChainParams& p);
