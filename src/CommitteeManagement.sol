// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MultiSigVerifier} from "./MultiSigVerifier.sol";

contract CommitteeManagement is MultiSigVerifier {
    constructor(address[] memory initialMembers, uint256 requiredSignatures)
        MultiSigVerifier(initialMembers, requiredSignatures)
    {}

    function isCommitteeMember(address member) external view returns (bool) {
        return isOwner[member];
    }

    function committeeSize() external view returns (uint256) {
        return ownerCount;
    }

    function quorumSize() external view returns (uint256) {
        return requiredSignatures;
    }

    function verifySignatures(bytes32 msgHash, bytes[] memory signatures) external view returns (bool) {
        return verify(msgHash, signatures);
    }
}
