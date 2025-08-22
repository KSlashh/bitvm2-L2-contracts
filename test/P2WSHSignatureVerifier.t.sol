// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/P2WSHSignatureVerifier.sol";

contract P2WSHSignatureVerifierTest is Test {
    P2WSHSignatureVerifier verifier;
    address signer;
    uint256 signerKey;

    function setUp() public {
        verifier = new P2WSHSignatureVerifier();
        signerKey = 0x1; // test private key
        signer = vm.addr(signerKey);
    }

    function testVerifyRSV() public {
        bytes32 sighash = keccak256("pretend_bip143_sighash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, sighash);

        bool ok = verifier.verifyRSV(sighash, signer, v, r, s);
        assertTrue(ok, "valid r,s,v should verify");
    }

    function testRejectWrongSigner() public {
        bytes32 sighash = keccak256("pretend_bip143_sighash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, sighash);

        address other = vm.addr(0xB0B);
        bool ok = verifier.verifyRSV(sighash, other, v, r, s);
        assertFalse(ok, "wrong expected signer must fail");
    }
}
