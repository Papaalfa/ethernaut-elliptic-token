# Elliptic Token — working notes

## Hint 1: map every signature check

There are 4 `ECDSA.recover(...)` calls across 2 functions. Fill this in.

| Function | Purpose | What is X (the digest passed to recover) | What is Missing |
| --- | --- | --- | --- |
| `redeemVoucher` — owner sig | validate owner's address | Hash of the Voucher | Nothing |
| `redeemVoucher` — receiver sig | validate receiver's address | Hash of the Voucher | nothing |
| `permit` — tokenOwner sig | validate tokenOwner's address | plain amount | hashing |
| `permit` — spender sig | validate spender's address | permit Accept Hash | nothing |

### ECDSA reference (fill from Wikipedia)

Signing `m`:
1.calculate hash of message `m`
2.calculate R = k*G
3.calculate r
4.calculate s

Verifying `(r, s)` against pubkey Q and message `m`:
1.calculate hash of message `m`
2.calculate u
3.calculate curve point

### Which step is missing, and in which recover call?

> hashing is missing in `permit` — tokenOwner sig

## Hint 2/3: attack plan (confirmed)

**Bug:** `permit` verifies the tokenOwner signature over `bytes32(amount)` — the raw
number, not `keccak256(anything)`. `amount` is fully attacker-chosen AND is reused as the
`_approve` value.

**Why `redeemVoucher` is NOT exploitable this way:** its digest is
`keccak256(abi.encodePacked(amount, receiver, salt))`. Existential forgery yields a valid
`(r,s)` for some `e`, but you'd need a keccak preimage `(amount, receiver, salt)` hashing
to `e`. Preimage resistance blocks it.

**Why `permit` IS exploitable:** digest = `bytes32(amount)`. Forge `(r,s)` for whatever
`e` the math spits out, then just pass `amount = e`. No hash to invert.

### Goal

`validateInstance` = `balanceOf(ALICE) == 0`. ALICE holds `INITIAL_AMOUNT = 10 ether`.

1. Existential-forge a tokenOwner signature so `permit` recovers `tokenOwner == ALICE`.
2. `amount = e` (forged, ~2^256, so >> 10 ether). `spender = attacker`.
   Sign `permitAcceptHash = keccak256(abi.encodePacked(ALICE, attacker, amount))` with the
   attacker key (normal signature — we own that key).
3. `permit(...)` runs `_approve(ALICE, attacker, amount)`.
4. `transferFrom(ALICE, attacker, 10 ether)` → ALICE balance = 0. Done.

### Recon values

| Item | Value |
| --- | --- |
| `redeemVoucher` selector | `0xbeb30836` |
| BOB (owner) | `0xB0B14927389CB009E0aabedC271AC29320156Eb8` |
| ALICE (receiver) | `0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e` |
| `INITIAL_AMOUNT` | `10 ether` |
| `salt` = `keccak256("BOB and ALICE are part of the secret sauce")` | `0x04a078de06d9d2ebd86ab2ae9c2b872b26e345d33f988d6d5d875f94e9c8ee1e` |
| setup voucher digest = `keccak256(abi.encodePacked(uint256(10 ether), ALICE, salt))` | `0x87f1c8cd4c0e19511304b612a9b4996f8c2bd795796636bd25812cd5b0b6a973` |
| `bobSignature` (factory constant, = `ownerSignature` arg) | `0x085a4f70d03930425d3d92b19b9d4e37672a9224ee2cd68381a9854bb3673ef86b35cfdeee0fb1d2168587fb188eefb4fe046109af063bf85d9d3d6859ceb4451c` |
| ↳ r_bob | `0x085a4f70d03930425d3d92b19b9d4e37672a9224ee2cd68381a9854bb3673ef8` |
| ↳ s_bob | `0x6b35cfdeee0fb1d2168587fb188eefb4fe046109af063bf85d9d3d6859ceb445` (low-s ✓) |
| ↳ v_bob | `28` |
| BOB pubkey Q_B.x | `0xbedb8b4d1d5c3a30d2703b9cd87428c6c7eef9958791447294bc05ff14b7c7e0` |
| BOB pubkey Q_B.y | `0xde9d549055204d85af2f85d8328a9037147b7f717af6940c4da51f5ae32de8e7` |
| `aliceSignature` (factory constant, = `receiverSignature` arg) | `0xab1dcd2a2a1c697715a62eb6522b7999d04aa952ffa2619988737ee675d9494f2b50ecce40040bcb29b5a8ca1da875968085f22b7c0a50f29a4851396251de121c` |
| ↳ r_alice | `0xab1dcd2a2a1c697715a62eb6522b7999d04aa952ffa2619988737ee675d9494f` |
| ↳ s_alice | `0x2b50ecce40040bcb29b5a8ca1da875968085f22b7c0a50f29a4851396251de12` (low-s ✓) |
| ↳ v_alice | `28` |
| **ALICE pubkey Q_A.x** | `0x33da8e7fe906411e4fc12842632ec77c2aee6a4324a4a3ca554b56667e4ccf97` |
| **ALICE pubkey Q_A.y** | `0xeda346ace5f9dce2781697ad353350c7509e1ffb491fedf49e37d4504185c676` |

Note: `bobSignature` isn't needed for the exploit itself (only `Q_A` is) — it's here for
completeness / because `setUp()` needs the literal bytes to replicate `redeemVoucher`.

secp256k1: `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`

OZ `ECDSA.recover` (v4.9) constraints on the forged sig: `s <= n/2` (else revert
`InvalidSignatureS`), `v in {27,28}`, recovered signer `!= address(0)`.

### Hint 4: forgery construction

Target (from `Q = r^-1 (s*R - e*G)`, want `Q = Q_A`):

    s * R = e * G + r * Q_A

Choose `R = a*G + b*Q_A` (a, b free, b != 0). Match coefficients of G and Q_A:

1. r = ?
2. s = ?   (then if s > n/2: s = n - s, flip v)
3. e = ?   -> this is `amount`
4. v = ?   (parity of R.y)

