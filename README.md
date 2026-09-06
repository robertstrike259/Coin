# Coin (CON) — Bitcoin-like PoW with Argon2id
1 CON = 100,000,000 swarf. Ticker CON. See SPEC.md.

Cross-platform C++20 (Linux / macOS / Windows). All cryptography comes from
established open-source libraries — no hand-rolled crypto:

| Use | Library | License |
|---|---|---|
| ECDSA secp256k1 | libsecp256k1 (bitcoin-core) | MIT |
| Argon2id PoW | libargon2 reference (PHC winner) | CC0 / Apache-2.0 |
| SHA256, RIPEMD160, CSPRNG | OpenSSL | Apache-2.0 |
| JSON (RPC) | nlohmann/json | MIT |
| Tests | doctest | MIT |
| GUI (optional) | Qt6 | LGPL |
| Sockets | thin `src/platform.h` shim over BSD/WinSock | — |

`secp256k1`, `argon2`, `nlohmann/json`, `doctest` are fetched automatically
by CMake FetchContent (pinned tags). OpenSSL comes from the OS:

## Build
```
# Linux (Debian/Ubuntu)
sudo apt install libssl-dev cmake g++ git
# macOS
brew install openssl@3 cmake git
# Windows (vcpkg provides OpenSSL; or: choco install openssl)
vcpkg install openssl:x64-windows

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```
Binaries: `coind`, `coin-miner`, `coin-wallet`, `coin-cli` (+ `coin-qt` if Qt6 found).

Default datadirs: Linux `~/.coin/<net>`, macOS
`~/Library/Application Support/Coin/<net>`, Windows `%APPDATA%\Coin\<net>`.

## Quick regtest (2 nodes, mine, transfer, sync)
```
./build/coin-wallet --datadir /tmp/c1 --regtest newkey   # -> ADDR
./build/coind --datadir /tmp/c1 --regtest --port 19444 --rpcport 19443 --mining-address ADDR &
./build/coin-miner --rpcport 19443 --address ADDR --threads 2 --blocks 2
./build/coin-wallet --datadir /tmp/c1 --regtest --rpcport 19443 balance ADDR
./build/coind --datadir /tmp/c2 --regtest --port 19445 --rpcport 19446 --peer 127.0.0.1:19444 &
./build/coin-cli --rpcport 19446 getblockchaininfo   # same tip as node 1
```
## Layout
src/: uint256, serialize, amount (swarf), chainparams, core (tx/block/address),
difficulty (portable, MSVC-safe), pow (libargon2), validation (BIP30),
mempool, chain, ecc (libsecp256k1), hash (OpenSSL), p2p, rpc (JSON), wallet,
config, platform (OS shim)
apps/: coind, coin-miner, coin-wallet, coin-cli, coin-qt
tests/: doctest suites (crypto/core/validation/chain/wallet/net)
