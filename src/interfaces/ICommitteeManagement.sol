// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICommitteeManagement {
    function isCommitteeMember(address member) external view returns (bool);
    function committeeSize() external view returns (uint256);
    function quorumSize() external view returns (uint256);
    function verifySignatures(bytes32 msgHash, bytes[] memory signatures) external view returns (bool);
}
