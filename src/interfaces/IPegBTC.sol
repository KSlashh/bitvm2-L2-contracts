// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IPegBTC is IERC20 {
    function mint(address to, uint256 amount) external;
    function burn(uint256 amount) external;
}
