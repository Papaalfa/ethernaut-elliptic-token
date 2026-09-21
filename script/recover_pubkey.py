#!/usr/bin/env python3
"""
recover_pubkey.py — recover a secp256k1 public key point from a known
(digest, signature) pair, the same way ecrecover / OpenZeppelin's
ECDSA.recover does internally, but returning the *point* instead of
collapsing it to an address.

Why this exists
----------------
An Ethereum address is keccak256(pubkey)[12:] — one-way. You can't go
from an address back to a public key. But `ecrecover` *does* reconstruct
the full pubkey point internally before hashing it down to an address;
it just throws the point away. This script does the same reconstruction
and keeps the point, because the point (not the address) is what you
need to build an existential-forgery signature for someone (see
`s*R = e*G + r*Q` in NOTES.md).

Where the (digest, signature) inputs come from
-----------------------------------------------
There is no keyless, scriptable way to pull these off a block explorer
for an internal contract call (see the recon notes in NOTES.md — public
RPCs lack debug_traceTransaction, Etherscan's trace UI is bot-gated, and
its API needs a paid key). They come from either:
  1. The level's open-source factory contract (GitHub) — canonical.
  2. Manually reading a trace in a real browser (Etherscan's vmtrace UI).

Usage
-----
  # Recover a specific (digest, r, s, v):
  python3 script/recover_pubkey.py \
      --digest 0x87f1c8cd4c0e19511304b612a9b4996f8c2bd795796636bd25812cd5b0b6a973 \
      --r 0xab1dcd2a2a1c697715a62eb6522b7999d04aa952ffa2619988737ee675d9494f \
      --s 0x2b50ecce40040bcb29b5a8ca1da875968085f22b7c0a50f29a4851396251de12 \
      --v 28 --expect 0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e

  # Or pass the full 65-byte r||s||v signature blob:
  python3 script/recover_pubkey.py --digest 0x87f1c8cd... --sig 0xab1dcd2a...121c

  # No args: recovers both BOB and ALICE's pubkeys for this level (the
  # voucher digest + both signatures are filled in as defaults below).
"""
import argparse
import subprocess

# --- secp256k1 domain parameters ---
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def inv(a, m):
    return pow(a % m, -1, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # point at infinity
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, p):
    result = None
    k %= N
    while k > 0:
        if k & 1:
            result = point_add(result, p)
        p = point_add(p, p)
        k >>= 1
    return result


def point_from_x(x, y_is_odd):
    """The curve has (at most) two points per x-coordinate; pick by parity,
    matching how `v` (27/28) selects between them in ecrecover."""
    y_squared = (x**3 + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)  # valid sqrt formula since P % 4 == 3
    if (y * y - y_squared) % P != 0:
        raise ValueError(f"x={hex(x)} is not a valid curve x-coordinate")
    if (y & 1) != y_is_odd:
        y = P - y
    return (x, y)


def ecrecover_point(digest: int, r: int, s: int, v: int):
    """Same math as the ecrecover precompile / ECDSA.recover, but returns
    the public key POINT Q instead of address(keccak256(Q)[12:])."""
    if not (0 < r < N and 0 < s < N):
        raise ValueError("r, s must be in [1, n-1]")
    R = point_from_x(r, (v - 27) & 1)
    r_inv = inv(r, N)
    sR = point_mul(s, R)
    eG = point_mul(digest, G)
    neg_eG = (eG[0], (-eG[1]) % P)
    return point_mul(r_inv, point_add(sR, neg_eG))


def address_of(point) -> str:
    pub = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    out = subprocess.run(
        ["cast", "keccak", "0x" + pub.hex()], capture_output=True, text=True, check=True
    ).stdout.strip()
    return "0x" + out[2:][24:]


def parse_sig(sig_hex: str):
    b = bytes.fromhex(sig_hex.removeprefix("0x"))
    if len(b) != 65:
        raise ValueError(f"signature must be 65 bytes (r||s||v), got {len(b)}")
    r = int.from_bytes(b[0:32], "big")
    s = int.from_bytes(b[32:64], "big")
    v = b[64]
    return r, s, v


def recover_and_report(label: str, digest: int, r: int, s: int, v: int, expect: str | None):
    print(f"\n=== {label} ===")
    print(f"  digest = {hex(digest)}")
    print(f"  r = {hex(r)}")
    print(f"  s = {hex(s)}  (low-s: {s <= N // 2})")
    print(f"  v = {v}")
    Q = ecrecover_point(digest, r, s, v)
    addr = address_of(Q)
    print(f"  Q.x = {hex(Q[0])}")
    print(f"  Q.y = {hex(Q[1])}")
    print(f"  recovered address = {addr}")
    if expect:
        ok = addr.lower() == expect.lower()
        print(f"  expected           = {expect.lower()}  {'✅ match' if ok else '❌ MISMATCH'}")
    return Q

def normalize_low_s(s: int, v: int) -> tuple[int, int]:
    if s > N // 2:
        s = N - s
        v = 55 - v   # 27+28=55, so this swaps 27<->28
    return s, v

def forge(a: int, b: int, Q: tuple[int, int]) -> tuple[int, int, int, int]:
    """
    Given free scalars a, b and a target pubkey point Q = (x, y),
    construct a forged ECDSA signature (r, s, v) and the digest e
    such that ecrecover(e, v, r, s) == address(Q).

    Returns (e, r, s, v)  — e becomes `amount` in the exploit.
    """
    R = point_add(point_mul(a, G), point_mul(b, Q))   # R = a*G + b*Q
    r = R[0] % N
    s = (r * inv(b, N)) % N
    e = (a * s) % N
    v = 27 + (R[1] & 1)
    s, v = normalize_low_s(s, v)
    return e, r, s, v

DEFAULTS = {
    # keccak256(abi.encodePacked(uint256(10 ether), ALICE, salt)) — the
    # voucher digest both BOB and ALICE signed in EllipticTokenFactory.
    "digest": "0x87f1c8cd4c0e19511304b612a9b4996f8c2bd795796636bd25812cd5b0b6a973",
    "bob_sig": "0x085a4f70d03930425d3d92b19b9d4e37672a9224ee2cd68381a9854bb3673ef86"
    "b35cfdeee0fb1d2168587fb188eefb4fe046109af063bf85d9d3d6859ceb4451c",
    "bob_addr": "0xB0B14927389CB009E0aabedC271AC29320156Eb8",
    "alice_sig": "0xab1dcd2a2a1c697715a62eb6522b7999d04aa952ffa2619988737ee675d9494f"
    "2b50ecce40040bcb29b5a8ca1da875968085f22b7c0a50f29a4851396251de121c",
    "alice_addr": "0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--digest", help="32-byte message digest, hex")
    ap.add_argument("--sig", help="65-byte r||s||v signature, hex")
    ap.add_argument("--r", help="r, hex (alternative to --sig)")
    ap.add_argument("--s", help="s, hex (alternative to --sig)")
    ap.add_argument("--v", type=int, help="v, 27 or 28 (alternative to --sig)")
    ap.add_argument("--expect", help="expected recovered address, for a sanity check")
    ap.add_argument("--forge", action="store_true", help="build an existential-forgery signature for ALICE's Q_A")
    ap.add_argument("-a", type=lambda x: int(x, 0), help="scalar a, for --forge (decimal or 0x-hex)")
    ap.add_argument("-b", type=lambda x: int(x, 0), help="scalar b, for --forge (decimal or 0x-hex)")
    args = ap.parse_args()

    if args.forge:
        a = args.a if args.a is not None else int.from_bytes(__import__("os").urandom(16), "big") + 1
        b = args.b if args.b is not None else int.from_bytes(__import__("os").urandom(16), "big") + 1
        QA = (
            int(DEFAULTS.get("alice_pubkey_x", "0x33da8e7fe906411e4fc12842632ec77c2aee6a4324a4a3ca554b56667e4ccf97"), 16),
            int(DEFAULTS.get("alice_pubkey_y", "0xeda346ace5f9dce2781697ad353350c7509e1ffb491fedf49e37d4504185c676"), 16),
        )
        e, r, s, v = forge(a, b, QA)
        Q_check = ecrecover_point(e, r, s, v)
        print(f"a = {hex(a)}")
        print(f"b = {hex(b)}")
        print(f"amount (= e) = {hex(e)}")
        print(f"r = {hex(r)}")
        print(f"s = {hex(s)}  (low-s: {s <= N // 2})")
        print(f"v = {v}")
        print(f"self-check: ecrecover(amount, r, s, v) == Q_A -> {Q_check == QA}")
        print()
        print("Solidity paste:")
        print(f"  uint256 amount = {hex(e)};")
        print(f"  bytes32 r = {hex(r)};")
        print(f"  bytes32 s = {hex(s)};")
        print(f"  uint8   v = {v};")
        return

    if args.digest and (args.sig or (args.r and args.s and args.v is not None)):
        digest = int(args.digest, 16)
        if args.sig:
            r, s, v = parse_sig(args.sig)
        else:
            r, s, v = int(args.r, 16), int(args.s, 16), args.v
        recover_and_report("recovered pubkey", digest, r, s, v, args.expect)
        return

    # No args -> recover both known signers for this level, as a demo /
    # independent check that the constants in NOTES.md are self-consistent.
    digest = int(DEFAULTS["digest"], 16)
    r, s, v = parse_sig(DEFAULTS["bob_sig"])
    recover_and_report("BOB (owner)", digest, r, s, v, DEFAULTS["bob_addr"])
    r, s, v = parse_sig(DEFAULTS["alice_sig"])
    recover_and_report("ALICE (receiver) — this is Q_A", digest, r, s, v, DEFAULTS["alice_addr"])


if __name__ == "__main__":
    main()
