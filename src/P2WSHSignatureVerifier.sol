// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title P2WSH-style signature verifier (raw sighash)
/// @notice Expects the raw BIP143/SegWit sighash (double-SHA256 over tx serialization).
///         Signature must be secp256k1 (r,s,v). We normalize v and enforce "low-s".
///         We compare the recovered address to an expected EVM address that corresponds
///         to the same secp256k1 key (i.e., keccak(uncompressed_pubkey)[12:]).
contract P2WSHSignatureVerifier {
    // secp256k1n/2 (EIP-2 low-s rule)
    uint256 private constant HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    /// @notice Verify r,s,v directly
    function verifyRSV(bytes32 sighash, address expectedSigner, uint8 v, bytes32 r, bytes32 s)
        external
        pure
        returns (bool)
    {
        // normalize v to {27,28}
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;

        // low-s rule (EIP-2 style) to prevent malleability
        if (uint256(s) > HALF_N) return false;

        // recover (use the raw sighash; do NOT add "\x19Ethereum Signed Message:\n32")
        address recovered = ecrecover(sighash, v, r, s);
        return recovered == expectedSigner;
    }
}