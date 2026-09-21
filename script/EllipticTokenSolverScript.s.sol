// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "lib/forge-std/src/Script.sol";
import {EllipticToken} from "../src/EllipticToken.sol";

contract EllipticTokenSolveScript is Script {

    address EllipticTokenAddr;
    address player;
    EllipticToken token;

    address ALICE = 0xA11CE84AcB91Ac59B0A4E2945C9157eF3Ab17D4e;

    uint256 amount = 0xc63c77409ca2154f3808507d07f3ac0c4c61578ea06f99ab9c83fc9970c7c4e4;
    bytes32 rAlice = 0xb47af4938548c0bcfa7071ce6d307201cdd81834411e0d6e38226fbf71c50394;
    bytes32 sAlice = 0x2a5d3faca421e43527b7e2fd6e499bd3e9a7f183fba7119ff1aa3202fe51c07d;
    uint8 vAlice = 28;

    bytes AliceSig;
    bytes playerSig;

    bytes32 permitAcceptHash;

    function setUp() public {

        EllipticTokenAddr = vm.envAddress("LEVEL");
        token = EllipticToken(EllipticTokenAddr);
        player = vm.envAddress("MY_ADDRESS");

        AliceSig = abi.encodePacked(rAlice, sAlice, vAlice);

        permitAcceptHash = keccak256(abi.encodePacked(ALICE, player, amount));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player, permitAcceptHash);
        playerSig = abi.encodePacked(r, s, v);
    }

    function run() public {       
        vm.startBroadcast();

        token.permit(amount, player, AliceSig, playerSig);
        token.transferFrom(ALICE, player, 10 ether);

        vm.stopBroadcast();

        require(token.balanceOf(ALICE) == 0, "not drained");
    }
}
