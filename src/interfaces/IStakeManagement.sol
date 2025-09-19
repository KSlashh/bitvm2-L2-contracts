// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IStakeManagement {
    function stakeTokenAddress() external view returns (address);
    function pubkeyToAddress(bytes32 pubkey) external view returns (address); // XOnlyPubkey
    function stakeOf(address operator) external view returns (uint256);
    function lockedStakeOf(address operator) external view returns (uint256);
    function slashStake(address operator, uint256 amount) external;
    function lockStake(address operator, uint256 amount) external;
    function unlockStake(address operator, uint256 amount) external;
}
