// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import "./Secp256k1.sol";
library EthSign {
    using MessageHashUtils for bytes32;
    function recoverPersonalSignAddress(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address) {
        bytes memory publicKey = recoverPersonalSignPublicKey(message, v, r, s);
        return recover(publicKey);
    }

    function recover(bytes memory publicKey) public pure returns (address) {
        return address(uint160(uint256(keccak256(publicKey))));
    }

    function recoverPersonalSignPublicKey(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (bytes memory) {
        (uint256 x, uint256 y) = SECP256K1.recover(
            uint256(message),
            v - 27,
            uint256(r),
            uint256(s)
        );
        return abi.encodePacked(x, y);
    }
}
