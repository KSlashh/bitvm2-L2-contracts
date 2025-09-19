/ SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title Simple Multi-Signature Verifier with Owner Rotation and Anti-Replay
contract MultiSigVerifier {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    mapping(address => bool) public isOwner;
    address[] private ownerList;

    uint256 public ownerCount;
    uint256 public requiredSignatures;
    uint256 public nonce;

    event OwnersUpdated(
        address[] newOwners,
        uint256 newRequired,
        uint256 newNonce
    );

    constructor(address[] memory owners, uint256 _requiredSignatures) {
        _setOwners(owners, _requiredSignatures);
        nonce = 0;
    }

    /// @notice Verify if a message has enough valid signatures from the current owner set.
    function verify(
        bytes32 messageHash,
        bytes[] memory signatures
    ) public view returns (bool) {
        uint256 validSignatures = 0;
        address[] memory seen = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = messageHash.recover(signatures[i]);
            if (
                isOwner[signer] &&
                !_alreadySigned(seen, signer, validSignatures)
            ) {
                seen[validSignatures] = signer;
                validSignatures++;
            }
        }
        return validSignatures >= requiredSignatures;
    }

    /// @notice Update the owner set and threshold, authorized by the CURRENT owners.
    function updateOwners(
        address[] calldata newOwners,
        uint256 newRequired,
        bytes[] calldata signatures
    ) external {
        require(newOwners.length > 0, "Owners required");
        require(
            newRequired > 0 && newRequired <= newOwners.length,
            "Invalid threshold"
        );

        bytes32 digest = keccak256(
            abi.encode(nonce, newOwners, newRequired)
        );

        require(
            _verifyCurrentOwners(digest, signatures),
            "No enough valid owner sigs"
        );

        _applyOwners(newOwners, newRequired);

        nonce += 1;
        emit OwnersUpdated(newOwners, newRequired, nonce);
    }

    /// ----------------------------------------------------------------
    /// internal helpers
    /// ----------------------------------------------------------------
    function _setOwners(
        address[] memory owners,
        uint256 _requiredSignatures
    ) internal {
        require(owners.length > 0, "Owners required");
        require(
            _requiredSignatures > 0 && _requiredSignatures <= owners.length,
            "Invalid threshold"
        );

        for (uint256 i = 0; i < owners.length; i++) {
            address o = owners[i];
            require(o != address(0), "Zero address");
            require(!isOwner[o], "Owner not unique");
            isOwner[o] = true;
            ownerList.push(o);
        }
        ownerCount = owners.length;
        requiredSignatures = _requiredSignatures;
    }

    function _applyOwners(
        address[] calldata newOwners,
        uint256 _requiredSignatures
    ) internal {
        // clear old owners
        for (uint256 i = 0; i < ownerList.length; i++) {
            isOwner[ownerList[i]] = false;
        }
        delete ownerList;

        // ensure no duplicates in newOwners
        for (uint256 i = 0; i < newOwners.length; i++) {
            address o = newOwners[i];
            require(o != address(0), "Zero address");
            for (uint256 j = 0; j < i; j++) {
                require(newOwners[j] != o, "Duplicate owner");
            }
            isOwner[o] = true;
            ownerList.push(o);
        }

        ownerCount = newOwners.length;
        requiredSignatures = _requiredSignatures;
    }

    function _verifyCurrentOwners(
        bytes32 digest,
        bytes[] calldata signatures
    ) internal view returns (bool) {
        uint256 validSignatures = 0;
        address[] memory seen = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = digest.recover(signatures[i]);
            if (
                isOwner[signer] &&
                !_alreadySigned(seen, signer, validSignatures)
            ) {
                seen[validSignatures] = signer;
                validSignatures++;
            }
        }
        return validSignatures >= requiredSignatures;
    }

    function _alreadySigned(
        address[] memory signers,
        address signer,
        uint256 count
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < count; i++) {
            if (signers[i] == signer) return true;
        }
        return false;
    }

    function getOwners() external view returns (address[] memory) {
        return ownerList;
    }
}
