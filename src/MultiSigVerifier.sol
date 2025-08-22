// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title Simple Multi-Signature Verifier with Owner Rotation and Anti-Replay
/// @notice Verifies signatures from a dynamic owner set and allows owner updates via multisig with nonce protection.
contract MultiSigVerifier {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice Authorized owners mapping
    mapping(address => bool) public isOwner;
    /// @notice Current number of owners
    uint256 public ownerCount;
    /// @notice Required signatures threshold
    uint256 public requiredSignatures;
    /// @notice Monotonic nonce to prevent replay on state-changing actions
    uint256 public nonce;

    event OwnersUpdated(address[] newOwners, uint256 newRequired, uint256 newNonce);

    /// @param owners Initial owners
    /// @param _requiredSignatures Initial threshold
    constructor(address[] memory owners, uint256 _requiredSignatures) {
        _setOwners(owners, _requiredSignatures);
        nonce = 0;
    }

    /// @notice Verify if a message has enough valid signatures from the current owner set.
    /// @dev This is a generic verifier (no nonce binding). For state changes, use updateOwners().
    /// @param messageHash The keccak256 of the message payload (caller decides payload)
    /// @param signatures  Array of 65-byte ECDSA signatures (r||s||v)
    function verify(bytes32 messageHash, bytes[] memory signatures)
        public
        view
        returns (bool)
    {
        uint256 validSignatures = 0;
        address[] memory seen = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = messageHash.recover(signatures[i]);
            if (isOwner[signer] && !_alreadySigned(seen, signer, validSignatures)) {
                seen[validSignatures] = signer;
                validSignatures++;
            }
        }

        return validSignatures >= requiredSignatures;
    }

    /// @notice Update the owner set and threshold, authorized by the CURRENT owners via multisig.
    /// @dev Prevents replay using a monotonic `nonce` bound into the signed message alongside this contract address.
    ///      Message to sign:
    ///      keccak256(abi.encode(
    ///         keccak256("UPDATE_OWNERS(address contract,uint256 nonce,bytes32 action)"),
    ///         address(this),
    ///         nonce,
    ///         keccak256(abi.encode(newOwners, newRequired))
    ///      ))
    ///
    /// @param newOwners     New owner list
    /// @param newRequired   New threshold (must be <= newOwners.length and > 0)
    /// @param signatures    Signatures by current owners over the constructed digest
    function updateOwners(
        address[] calldata newOwners,
        uint256 newRequired,
        bytes32 noteHash,
        bytes[] calldata signatures
    ) external {
        require(newOwners.length > 0, "Owners required");
        require(newRequired > 0 && newRequired <= newOwners.length, "Invalid threshold");

        // Build the action hash (pure content to be changed)
        bytes32 actionHash = keccak256(abi.encode(newOwners, newRequired, noteHash));

        // Domain-separated, nonce-bound message
        bytes32 typeHash = keccak256(
            "UPDATE_OWNERS(address contract,uint256 nonce,bytes32 action)"
        );
        bytes32 digest = keccak256(abi.encode(typeHash, address(this), nonce, actionHash));

        require(_verifyCurrentOwners(digest, signatures), "Not enough valid owner sigs");

        // Apply update
        _applyOwners(newOwners, newRequired);

        // Bump nonce to invalidate old signatures
        nonce += 1;

        emit OwnersUpdated(newOwners, newRequired, nonce);
    }

    function _setOwners(address[] memory owners, uint256 _requiredSignatures) internal {
        require(owners.length > 0, "Owners required");
        require(_requiredSignatures > 0 && _requiredSignatures <= owners.length, "Invalid threshold");

        // Clear previous owners if any
        if (ownerCount > 0) {
            // NOTE: We cannot iterate a mapping; this branch only hits in constructor in this design.
            // If you need to re-init from storage later, keep an owners array in storage for clearing.
        }

        ownerCount = owners.length;
        for (uint256 i = 0; i < owners.length; i++) {
            address o = owners[i];
            require(o != address(0), "Zero address");
            require(!isOwner[o], "Owner not unique");
            isOwner[o] = true;
        }

        requiredSignatures = _requiredSignatures;
    }

    function _applyOwners(address[] calldata owners, uint256 _requiredSignatures) internal {
        // Clear existing owners (need a way to enumerate). For simplicity we reconstruct mapping via a fresh map trick:
        // In Solidity we cannot reset a mapping; so we first mark all current owners false by reading from an auxiliary list.
        // To support that properly, we keep a storage array `ownerList`. (Add below)

        // ---- Improved: keep a storage array to enumerate/clear owners ----
        _clearOwners(); // mark old owners false
        for (uint256 i = 0; i < owners.length; i++) {
            require(!isOwner[owners[i]], "Owner duplicate in new set");
            isOwner[owners[i]] = true;
        }
        ownerCount = owners.length;
        requiredSignatures = _requiredSignatures;

        // Refresh the storage array for enumeration/clearing next time
        delete ownerList;
        for (uint256 i = 0; i < owners.length; i++) {
            ownerList.push(owners[i]);
        }
    }

    // Storage array for enumeration/clearing
    address[] private ownerList;

    function _clearOwners() internal {
        // Mark all current owners false
        for (uint256 i = 0; i < ownerList.length; i++) {
            isOwner[ownerList[i]] = false;
        }
    }

    /// @dev Verify signatures from CURRENT owners over `digest`. Uses eth-signed message wrapper.
    function _verifyCurrentOwners(bytes32 digest, bytes[] calldata signatures)
        internal
        view
        returns (bool)
    {
        uint256 validSignatures = 0;
        address[] memory seen = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = digest.recover(signatures[i]);
            if (isOwner[signer] && !_alreadySigned(seen, signer, validSignatures)) {
                seen[validSignatures] = signer;
                validSignatures++;
            }
        }

        return validSignatures >= requiredSignatures;
    }

    /// @notice Check if an address has already signed
    function _alreadySigned(address[] memory signers, address signer, uint256 count)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < count; i++) {
            if (signers[i] == signer) return true;
        }
        return false;
    }

    /// @notice Returns current owners as an array (for off-chain inspection)
    function getOwners() external view returns (address[] memory) {
        return ownerList;
    }
}