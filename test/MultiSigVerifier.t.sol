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
    address newOwner1 = vm.addr(11);
    address newOwner2 = vm.addr(12);
    
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

    function _signUpdate(
        uint256 privKey,
        address[] memory newOwners,
        uint256 newRequired,
        bytes32 noteHash,
        uint256 nonce
    ) internal view returns (bytes memory sig) {
        bytes32 actionHash = keccak256(abi.encode(newOwners, newRequired, noteHash));
        bytes32 typeHash   = keccak256("UPDATE_OWNERS(address contract,uint256 nonce,bytes32 action)");
        bytes32 digest     = keccak256(abi.encode(typeHash, address(verifier), nonce, actionHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function testUpdateOwnersSuccess() public {
        // Prepare new owners set
        address[] memory newOwners = new address[](2);
        newOwners[0] = newOwner1;
        newOwners[1] = newOwner2;
        uint256 newRequired = 2;
        bytes32 noteHash = keccak256("rotation-1");

        // Sign with alice (privKey=1) and bob (privKey=2)
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signUpdate(1, newOwners, newRequired, noteHash, verifier.nonce());
        sigs[1] = _signUpdate(2, newOwners, newRequired, noteHash, verifier.nonce());

        verifier.updateOwners(newOwners, newRequired, noteHash, sigs);

        address[] memory ownersOut = verifier.getOwners();
        assertEq(ownersOut.length, 2);
        assertEq(ownersOut[0], newOwner1);
        assertEq(ownersOut[1], newOwner2);

        assertEq(verifier.requiredSignatures(), 2);
        assertEq(verifier.nonce(), 1);
    }

    function testUpdateOwnersFail_NotEnoughSignatures() public {
        address[] memory newOwners = new address[](2);
        newOwners[0] = newOwner1;
        newOwners[1] = newOwner2;
        uint256 newRequired = 2;
        bytes32 noteHash = keccak256("rotation-2");

        // Only Alice signs
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _signUpdate(1, newOwners, newRequired, noteHash, verifier.nonce());

        vm.expectRevert("Not enough valid owner sigs");
        verifier.updateOwners(newOwners, newRequired, noteHash, sigs);
    }

    function testUpdateOwnersFail_ReusedNonce() public {
        address[] memory newOwners = new address[](2);
        newOwners[0] = newOwner1;
        newOwners[1] = newOwner2;
        uint256 newRequired = 2;
        bytes32 noteHash = keccak256("rotation-3");

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signUpdate(1, newOwners, newRequired, noteHash, verifier.nonce());
        sigs[1] = _signUpdate(2, newOwners, newRequired, noteHash, verifier.nonce());

        verifier.updateOwners(newOwners, newRequired, noteHash, sigs);

        // Try replay with same signatures and same nonce
        vm.expectRevert("Not enough valid owner sigs");
        verifier.updateOwners(newOwners, newRequired, noteHash, sigs);
    }
}