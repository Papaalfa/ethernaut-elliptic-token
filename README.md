# Ethernaut — Elliptic Token

- **Level:** #35 — Elliptic Token
- **Difficulty:** 8
- **Author:** jack&Gianfranco
- **Created:** 2025-07-10
- **Level page:** https://ethernaut.openzeppelin.com/level/0x1696D4B915Ec980872a2685d580DE0e79C1Aa1a1
- **Status:** ✅ Solved on Sepolia — see [Proof of solve](#proof-of-solve)

> ⚠️ **Spoiler warning.** This repo contains a full working solution. If
> you want to solve the level yourself first, stop after the Description
> section.

## Description

BOB created and owns a new ERC20 token with an elliptic curve–based signed voucher
redemption system called EllipticToken ($ETK). Bob can create vouchers off-chain that
can be redeemed on-chain for $ETK. The contract also includes a permit system based on
elliptic curve signatures.

Bob is a lazy developer and "optimized" some steps of the ECDSA algorithm. Can you find
the flaw?

Your goal is to steal the $ETK tokens that ALICE (`0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e`)
just redeemed.

&nbsp;

Things that might help:
* Look for any missing step in the [Elliptic Curve Digital Signature Algorithm (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm).

Good luck. Elliptic curves do not forgive domain confusion.

---

## The vulnerability

`EllipticToken.permit()` authenticates the token owner like this:

```solidity
address tokenOwner = ECDSA.recover(bytes32(amount), tokenOwnerSignature);
```

It recovers the signer over the **raw, unhashed `amount`** — not
`keccak256(...)` of anything. `amount` is fully attacker-controlled *and*
is the exact value that gets approved a few lines later
(`_approve(tokenOwner, spender, amount)`).

Skipping the hash breaks the one property that makes ECDSA safe against
[existential forgery](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_forgery):
without it, anyone who knows a target's **public key** (recoverable from
any one of their real signatures — no private key needed) can construct
a valid `(r, s, v)` for *some* digest `e` the math produces. Normally
that's useless, because you can't find a message that hashes to that
`e`. Here there's no hash — `e` *is* `amount` — so the forged signature
is directly usable.

**The attack:**
1. Recover ALICE's public key from her one known signature (hardcoded in
   `EllipticTokenFactory`, public — no secret involved).
2. Forge `(amount, r, s, v)` so `permit`'s recovery resolves to ALICE,
   with `amount` coming out astronomically large.
3. Call `permit(amount, attacker, forgedSig, realSelfSig)` →
   `_approve(ALICE, attacker, amount)`.
4. `transferFrom(ALICE, attacker, 10 ether)` — her whole balance, gone.

Full derivation, the forgery formulas, and everything hit along the way
(including a couple of tooling gotchas worth remembering) are in
[`NOTES.md`](./NOTES.md).

## Repo layout

```
src/EllipticToken.sol              the vulnerable contract (level source)
test/EllipticToken.t.sol           self-contained local Foundry PoC
script/recover_pubkey.py           the ECDSA math: pubkey recovery + forge()
script/fetch_factory_data.py       pulls BOB/ALICE's real constants from GitHub, self-verifies
script/EllipticTokenSolverScript.s.sol   forge script: runs the exploit on a real instance
script/attack_sepolia.sh           earlier cast-only version of the same attack (reference)
NOTES.md                           the vulnerability writeup + forgery math
```

## Reproduce it

### 1. Local proof (no live instance needed)

```bash
git clone --recurse-submodules <this repo>
cd ethernaut-elliptic-token
forge test -vvvv
```

`test/EllipticToken.t.sol` deploys a fresh `EllipticToken` locally,
replicates the factory's setup (mints 10 ETK to Alice, exactly like the
real level), then runs the full exploit and asserts her balance ends at
`0`. This is the fastest way to see the bug proven, no network required.

### 2. Against your own real Sepolia instance

Needs: `forge`, `cast`, `python3`, a little Sepolia ETH.

1. On the [level page](https://ethernaut.openzeppelin.com/level/0x1696D4B915Ec980872a2685d580DE0e79C1Aa1a1),
   click **Get new instance**.
2. `cp .env.example .env` and fill in `LEVEL` (your instance address),
   `MY_ADDRESS` (your wallet), and `RPC_URL` (a Sepolia RPC).
3. Import your key as an encrypted Foundry keystore (never pass a raw
   private key on the command line):
   ```bash
   cast wallet import TestAccount --interactive
   ```
4. Dry-run first (simulates against real chain state, sends nothing):
   ```bash
   forge script script/EllipticTokenSolverScript.s.sol --rpc-url "$RPC_URL" --account TestAccount -vvvv
   ```
5. If the trace looks right, send it for real:
   ```bash
   forge script script/EllipticTokenSolverScript.s.sol --rpc-url "$RPC_URL" --account TestAccount --broadcast --slow -vvvv
   ```
   (`--slow` matters here — see the EIP-7702 gotcha in `NOTES.md` if you're curious why.)
6. Confirm and finish up:
   ```bash
   cast call "$LEVEL" "balanceOf(address)(uint256)" 0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e --rpc-url "$RPC_URL"
   # -> 0
   ```
   Then hit **Submit instance** on the level page.

## Proof of solve

Instance: [`0xc19ada373ec24bea6659151531a6c772a859972f`](https://sepolia.etherscan.io/address/0xc19ada373ec24bea6659151531a6c772a859972f)

| Tx | Hash |
| --- | --- |
| `permit` (forged signature) | [`0x96849a2c...`](https://sepolia.etherscan.io/tx/0x96849a2c1bf546ccbfe2e8dd5317541d3f076d49f14f565160d1834c3a5e9e19) |
| `transferFrom` (drain) | [`0x55450f47...`](https://sepolia.etherscan.io/tx/0x55450f475855f4e3f35961ef047916c8960122a4de6d3744b89f1aaa186085df) |

Alice's final balance: `0`.

## Credits

Solved with [Claude Code](https://claude.com/claude-code) as a support —
working through the ECDSA math, tooling gotchas, and the live exploit
together.
