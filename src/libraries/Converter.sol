// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Constants} from "../Constants.sol";

library Converter {
    uint8 constant BtcDecimals = 8;

    function amountFromSats(uint64 amountSats) internal pure returns (uint256) {
        uint8 TokenDecimals = Constants.TokenDecimals;
        if (TokenDecimals >= BtcDecimals) {
            return uint256(amountSats * uint64(10 ** (TokenDecimals - BtcDecimals)));
        } else {
            return uint256(amountSats / uint64(10 ** (BtcDecimals - TokenDecimals)));
        }
    }

    function amountToSats(uint256 amount) internal pure returns (uint64) {
        uint8 TokenDecimals = Constants.TokenDecimals;
        if (TokenDecimals >= BtcDecimals) {
            return uint64(amount / uint256(10 ** (TokenDecimals - BtcDecimals)));
        } else {
            return uint64(amount * uint256(10 ** (BtcDecimals - TokenDecimals)));
        }
    }
}
