// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IBitcoinSPV {
    function blockHash(uint256 height) external view returns (bytes32);
    function latestConfirmedHeight() external view returns (uint256);
}
