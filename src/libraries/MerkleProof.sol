// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BitvmTxParser} from "./BitvmTxParser.sol";

library MerkleProof {
    struct BitcoinTxProof {
        bytes rawHeader;
        uint256 height;
        bytes32[] proof;
        uint256 index;
    }

    function parseBtcBlockHeader(bytes calldata rawHeader)
        public
        pure
        returns (bytes32 blockHash, bytes32 merkleRoot)
    {
        blockHash = BitvmTxParser.hash256(rawHeader);
        merkleRoot = BitvmTxParser.memLoad(rawHeader, 0x44);
    }

    function verifyMerkleProof(bytes32 root, bytes32[] memory proof, bytes32 leaf, uint256 index)
        public
        pure
        returns (bool)
    {
        bytes32 computedHash = leaf;

        for (uint256 i; i < proof.length; ++i) {
            if (index % 2 == 0) {
                computedHash = _doubleSha256Pair(computedHash, proof[i]);
            } else {
                computedHash = _doubleSha256Pair(proof[i], computedHash);
            }
            index /= 2;
        }

        return computedHash == root;
    }

    function _doubleSha256Pair(bytes32 txA, bytes32 txB) internal pure returns (bytes32) {
        // concatenate and do sha256 once
        bytes32 hash = sha256(abi.encodePacked(txA, txB));

        // do sha256 once again
        return sha256(abi.encodePacked(hash));
    }
}
