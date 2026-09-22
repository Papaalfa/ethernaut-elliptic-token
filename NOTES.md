# Elliptic Token — solve notes

Ethernaut #35. Solved on Sepolia. Kept concise on purpose — this is for
jogging memory later, not a full writeup (see README.md for that).

## The bug, in one line

`permit()` checks `ECDSA.recover(bytes32(amount), tokenOwnerSignature)` —
it signs the raw `amount`, never hashed. `amount` is attacker-chosen and
doubles as the value that gets approved.

## Why that's fatal: ECDSA existential forgery

Given *only* a public key `Q` (no private key), you can construct a valid
`(r, s)` for *some* digest `e` — you don't get to pick `e`, it falls out
of the algebra:

```
choose a, b (free, b != 0)
R = a*G + b*Q
r = R.x mod n
s = r * b^-1 mod n
e = a * s mod n
v = 27 + (R.y & 1)          -- then normalize: if s > n/2, s = n-s, flip v
```

Normally useless — real protocols hash the message first, so you'd need
a keccak *preimage* mapping to `e`, which you don't have. `permit` never
hashes, so `e` *is* the message (`amount`) — directly usable.

`redeemVoucher` is safe from this: its digest **is** hashed
(`keccak256(amount, receiver, salt)`), so forging a sig for a chosen `e`
doesn't give you a usable `(amount, receiver, salt)` preimage.

## The attack

1. Recover ALICE's real pubkey `Q_A` from the one signature she's known
   to have produced — the voucher signature hardcoded in
   `EllipticTokenFactory` (public info, no private key needed).
2. Forge `(amount=e, r, s, v)` so `ECDSA.recover(bytes32(amount), sig) == ALICE`.
3. `permit(amount, attacker, forgedSig, realSelfSig)` → `_approve(ALICE, attacker, amount)`.
   `amount` ≈ 2²⁵⁶, so it covers her whole balance.
4. `transferFrom(ALICE, attacker, 10 ether)` → her balance → 0.

Key values: `Q_A`, the forged `(amount, r, s, v)`, the digest math — all
in `script/recover_pubkey.py` (`ecrecover_point`, `forge`) and
`script/fetch_factory_data.py` (pulls BOB/ALICE's real constants straight
from the GitHub source and cross-checks them).

## Gotchas hit along the way (the actually memorable part)

- **Never round-trip a hex value through `int()`/`hex()`.** Python's
  `hex(int)` silently drops leading zero *bytes* — corrupted `r_bob` this
  way once. Byte-slice hex strings directly instead.
- OZ's `ECDSA.recover` rejects `s > n/2` (needs low-s normalization) and
  requires `v ∈ {27, 28}`.
- `vm.sign(address, digest)` in `forge script` needs the keystore wallet
  actually loaded for signing — in this Foundry build, an *interactively
  typed* keystore password didn't reliably wire the wallet in for
  `vm.sign` (worked fine for broadcasting oddly), while `--password`/
  `--password-file` did. Turned out to also just be a wrong password
  the first time — check that first.
- Ethereum accounts with EIP-7702 delegated code allow only **one
  in-flight transaction**. `forge script --broadcast`'s default batching
  can drop the 2nd tx of a multi-tx script ("gapped-nonce tx from
  delegated accounts"). Fix: `--slow`, or just `cast send` the missing
  call directly.
- Etherscan's API (even with a key) won't hand you an internal call's
  calldata — that needs `debug_traceTransaction`, gated behind a paid
  tier / their bot-protected trace UI. The factory's GitHub source is the
  reliable source for BOB/ALICE's hardcoded constants.

## Proof of solve (Sepolia)

- Instance: `0xc19ada373ec24bea6659151531a6c772a859972f`
- `permit` tx: `0x96849a2c1bf546ccbfe2e8dd5317541d3f076d49f14f565160d1834c3a5e9e19`
- `transferFrom` tx: `0x55450f475855f4e3f35961ef047916c8960122a4de6d3744b89f1aaa186085df`
- Final `balanceOf(ALICE)` → `0` (verified live via `cast call`)

## Files

- `src/EllipticToken.sol` — the vulnerable contract (level source)
- `test/EllipticToken.t.sol` — local, self-contained Foundry PoC
- `script/recover_pubkey.py` — the core ECDSA math (recovery + forgery)
- `script/fetch_factory_data.py` — pulls BOB/ALICE constants from GitHub, self-verifies
- `script/EllipticTokenSolverScript.s.sol` — runs the exploit against the real instance
- `script/attack_sepolia.sh` — earlier `cast`-only version of the same attack, kept for reference
