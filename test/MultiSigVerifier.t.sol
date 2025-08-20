// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/MultiSigVerifier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MultiSigVerifierTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    MultiSigVerifier verifier;

    address alice = vm.addr(1);
    address bob = vm.addr(2);
    address carol = vm.addr(3);

    address[] owners;
    bytes32 message;
    function setUp() public {
        owners = new address[](3);
        owners[0] = alice;
        owners[1] = bob;
        owners[2] = carol;

        // Compute the prefixed hash like the contract does
        message = keccak256("hello world").toEthSignedMessageHash();

        // Require at least 2 signatures
        verifier = new MultiSigVerifier(owners, 2);
        
    }

    function testVerifyWithEnoughSignatures() view public {
        // Sign message with alice and bob
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(1, message);
        bytes memory sig1 = abi.encodePacked(r1, s1, v1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, message);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = sig1;
        sigs[1] = sig2;

        bool ok = verifier.verify(message, sigs);
        assertTrue(ok, "Should be valid with 2 signatures");
    }

    function testVerifyFailsWithSingleSignature() view public {
        // Only signed by Alice
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(1, message);
        bytes memory sig1 = abi.encodePacked(r1, s1, v1);

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = sig1;

        bool ok = verifier.verify(message, sigs);
        assertFalse(ok, "Should fail with only 1 signature");
    }

    function testVerifyRejectsNonOwnerSignature() view public {
        // Signed by non-owner
        (uint8 vX, bytes32 rX, bytes32 sX) = vm.sign(99, message);
        bytes memory sigX = abi.encodePacked(rX, sX, vX);

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = sigX;

        bool ok = verifier.verify(message, sigs);
        assertFalse(ok, "Non-owner signature should not be valid");
    }
}