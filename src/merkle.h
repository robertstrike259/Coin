#pragma once
#include "core.h"
#include "uint256.h"
inline uint256 merkleRootOf(const std::vector<Transaction>& t){ return merkleRoot(t); }
