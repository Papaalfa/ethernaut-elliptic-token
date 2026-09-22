#!/usr/bin/env python3
"""
fetch_factory_data.py — pull BOB's and ALICE's addresses, their voucher
signatures, and the salt string straight from the open-source
EllipticTokenFactory contract on GitHub, parse them precisely, and
cross-check everything by recovering both public keys and confirming
they match BOB/ALICE.

Why a script instead of copy-pasting once and hardcoding: we already got
bitten by this once (see NOTES.md / the bug history) — a value was
hand-transcribed through Python's hex(int), which silently drops a
leading zero *byte*, corrupting r_bob. This script never round-trips a
signature through an int; it stays as raw hex the whole way, so that
class of bug can't happen again. It's also just the reproducible way to
re-derive NOTES.md's recon table from the canonical source, any time.

Usage:
    python3 script/fetch_factory_data.py            # human-readable report
    python3 script/fetch_factory_data.py --json      # machine-readable
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

# reuse the secp256k1 math already written and verified in recover_pubkey.py
sys.path.insert(0, str(Path(__file__).parent))
import recover_pubkey as rp  # noqa: E402

FACTORY_URL = (
    "https://raw.githubusercontent.com/OpenZeppelin/ethernaut/master/"
    "contracts/src/levels/EllipticTokenFactory.sol"
)


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=15) as resp:  # nosec - public raw GitHub content
        return resp.read().decode()


def cast_keccak(hex_data: str) -> str:
    out = subprocess.run(["cast", "keccak", hex_data], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def parse_factory(src: str) -> dict:
    def addr(name: str) -> str:
        m = re.search(rf"address constant {name}\s*=\s*(0x[0-9a-fA-F]{{40}})", src)
        if not m:
            raise ValueError(f"couldn't find address constant {name} in factory source")
        return m.group(1)

    def hex_var(varname: str) -> str:
        # matches: bytes memory <varname> =\n    hex"....";
        m = re.search(rf'{varname}\s*=\s*\n?\s*hex"([0-9a-fA-F]+)"', src)
        if not m:
            raise ValueError(f"couldn't find {varname} in factory source")
        h = m.group(1)
        if len(h) % 2 != 0:
            raise ValueError(f"{varname}: odd number of hex digits ({len(h)}) — bad parse")
        return h

    def initial_amount_wei() -> int:
        m = re.search(r"INITIAL_AMOUNT\s*=\s*([0-9]+)\s*ether", src)
        if not m:
            raise ValueError("couldn't find INITIAL_AMOUNT")
        return int(m.group(1)) * 10**18

    def salt_string() -> str:
        m = re.search(r'bytes32 salt\s*=\s*keccak256\("([^"]*)"\)', src)
        if not m:
            raise ValueError("couldn't find the salt's source string")
        return m.group(1)

    return {
        "bob_addr": addr("BOB"),
        "alice_addr": addr("ALICE"),
        "initial_amount_wei": initial_amount_wei(),
        "bob_sig_hex": hex_var("bobSignature"),
        "alice_sig_hex": hex_var("aliceSignature"),
        "salt_string": salt_string(),
    }


def split_sig(sig_hex: str) -> tuple[str, str, int]:
    """65-byte r||s||v hex -> (r_hex, s_hex, v). Stays in string/bytes form
    throughout — never passes through int(...)/hex(...), which is exactly
    what dropped a leading zero byte the first time this was done by hand."""
    b = bytes.fromhex(sig_hex)
    if len(b) != 65:
        raise ValueError(f"expected 65-byte signature, got {len(b)} bytes")
    r_hex = "0x" + b[0:32].hex()
    s_hex = "0x" + b[32:64].hex()
    v = b[64]
    return r_hex, s_hex, v


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON instead of a report")
    ap.add_argument("--url", default=FACTORY_URL, help="override the factory source URL")
    args = ap.parse_args()

    src = fetch(args.url)
    data = parse_factory(src)

    # string literal (e.g. "salt string") -> ascii hex -> keccak256
    salt_ascii_hex = "0x" + data["salt_string"].encode().hex()
    salt = cast_keccak(salt_ascii_hex)

    # voucherHash = keccak256(abi.encodePacked(uint256(amount), address(ALICE), bytes32(salt)))
    packed = (
        data["initial_amount_wei"].to_bytes(32, "big").hex()
        + data["alice_addr"][2:].lower()
        + salt[2:]
    )
    voucher_hash = cast_keccak("0x" + packed)

    r_bob, s_bob, v_bob = split_sig(data["bob_sig_hex"])
    r_alice, s_alice, v_alice = split_sig(data["alice_sig_hex"])

    digest = int(voucher_hash, 16)
    Q_bob = rp.ecrecover_point(digest, int(r_bob, 16), int(s_bob, 16), v_bob)
    Q_alice = rp.ecrecover_point(digest, int(r_alice, 16), int(s_alice, 16), v_alice)
    addr_bob = rp.address_of(Q_bob)
    addr_alice = rp.address_of(Q_alice)

    result = {
        "source_url": args.url,
        "bob_addr": data["bob_addr"],
        "alice_addr": data["alice_addr"],
        "initial_amount_wei": data["initial_amount_wei"],
        "salt_string": data["salt_string"],
        "salt": salt,
        "voucher_hash": voucher_hash,
        "bob_signature": "0x" + data["bob_sig_hex"],
        "bob_r": r_bob, "bob_s": s_bob, "bob_v": v_bob,
        "bob_recovered_addr": addr_bob,
        "bob_addr_matches": addr_bob.lower() == data["bob_addr"].lower(),
        "alice_signature": "0x" + data["alice_sig_hex"],
        "alice_r": r_alice, "alice_s": s_alice, "alice_v": v_alice,
        "alice_recovered_addr": addr_alice,
        "alice_addr_matches": addr_alice.lower() == data["alice_addr"].lower(),
        "alice_pubkey_x": hex(Q_alice[0]),
        "alice_pubkey_y": hex(Q_alice[1]),
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return

    ok = "✅" if result["bob_addr_matches"] else "❌ MISMATCH"
    ok2 = "✅" if result["alice_addr_matches"] else "❌ MISMATCH"
    print(f"source: {args.url}\n")
    print(f"BOB   = {data['bob_addr']}")
    print(f"ALICE = {data['alice_addr']}")
    print(f"INITIAL_AMOUNT = {data['initial_amount_wei']} wei")
    print(f'salt string    = "{data["salt_string"]}"')
    print(f"salt           = {salt}")
    print(f"voucher digest = {voucher_hash}\n")
    print(f"bobSignature   = 0x{data['bob_sig_hex']}")
    print(f"  r = {r_bob}\n  s = {s_bob}\n  v = {v_bob}")
    print(f"  recovers to {addr_bob}  vs BOB   {data['bob_addr']}  {ok}\n")
    print(f"aliceSignature = 0x{data['alice_sig_hex']}")
    print(f"  r = {r_alice}\n  s = {s_alice}\n  v = {v_alice}")
    print(f"  recovers to {addr_alice}  vs ALICE {data['alice_addr']}  {ok2}\n")
    print(f"ALICE pubkey Q_A.x = {result['alice_pubkey_x']}")
    print(f"ALICE pubkey Q_A.y = {result['alice_pubkey_y']}")


if __name__ == "__main__":
    main()
