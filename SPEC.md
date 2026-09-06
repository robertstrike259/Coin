# Coin (CON) consensus SPEC v0.1.0
- Ticker CON, name Coin. Units: 1 CON = 100,000,000 swarf (int64 CAmount).
- UTXO + P2PKH-only v1. No Script opcodes.
- Mainnet: MAX 84M CON + tail 1 CON/block; block 120s; genesis reward 100 CON;
  halving every 840000 blocks; retarget every 720 blocks (Bitcoin nBits format).
- Testnet/regtest same but regtest: fixed low difficulty, fast Argon2id (1 MiB, t=1).
- Header (80B): version|prevHash|merkleRoot|time|bits|nonce. PoW hash =
  reference libargon2 Argon2id(password=header, salt="CON…"+prevHash,
  m, t, lanes=1, out=32). Valid iff hash (LE uint256) <= target(bits).
  Lanes=1 in v1 (single-lane Argon2id is still memory-hard; p=4 reserved for a
  future header version). PoW memory: mainnet 32 MiB/t=1, testnet 16 MiB/t=1,
  regtest 1 MiB/t=1. Genesis bits are easy (0x207fffff) on every net so the
  genesis is findable at first load; difficulty retargets from there.
- Time rules: header time must exceed the median of the previous 11 blocks
  and must not be more than 2h in the future (by node clock).
- Reorgs: longest fully-valid branch wins. Side branches are stored with
  headers+bodies; on a longer competitor the node rewinds via per-block undo
  records and re-validates (inputs, signatures, fees, BIP30) before committing.
- BIP30: no two unspent outputs may share an OutPoint (duplicate coinbase
  txids rejected). Coinbase scriptSig carries height+time+extraNonce
  (BIP34-style) so txids are unique.
- IDs: txid = SHA256d(tx ser) (OpenSSL); merkle = Bitcoin pairwise SHA256d;
  block hash for linking = SHA256d(header) (PoW hash separate).
- Address: Base58Check(version 0x1C + hash160(compressed pubkey) + checksum).
  hash160 = RIPEMD160(SHA256(pubkey)) (OpenSSL).
- Sig: ECDSA secp256k1 via libsecp256k1 (deterministic RFC6979, low-S),
  sighash = SHA256d(tx digest), compact (r||s 64B) + pubkey 33B in scriptSig.
  Authorization is consensus-enforced: the signer's hash160 must equal the
  spent output's pubKeyHash (pkh-mismatch rejects), and duplicate inputs
  within one tx are rejected.
- Fees: swarf/byte, minrelay 100 swarf/tx (mempool), dust 1000 swarf
  (wallet folds sub-dust change into the fee). Mempool tracks spent outpoints
  (no unconfirmed chains or mempool double-spends in v0.1) and revalidates on
  every tip change.
- P2P: 2 MiB message cap, headers-first IBD (2000/page), block/tx gossip
  relay, real peer counts in RPC.
- Storage: atomic `blocks.dat` writes (`CON1` magic + checksum); corrupt files
  are archived to `.corrupt`, never silently wiped.
- Wallet: `wallet.dat` is PLAINTEXT in v0.1 (AES-256-GCM + KDF on roadmap).
- Coinbase maturity 100 blocks is NOT yet consensus-enforced in v0.1 (roadmap); max block 2MB.
