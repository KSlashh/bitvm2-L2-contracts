// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Constants} from "../Constants.sol";

library BitvmTxParser {
    struct BitcoinTx {
        bytes4 version;
        bytes inputVector;
        bytes outputVector;
        bytes4 locktime;
    }

    uint32 constant CHALLENGE_CONNECTOR_VOUT = 0;
    uint32 constant DISPROVE_CONNECTOR_VOUT = 3;

    function parsePegin(BitcoinTx memory bitcoinTx)
        internal
        pure
        returns (bytes32 peginTxid, uint64 peginAmountSats, address depositorAddress, bytes16 instanceId)
    {
        peginTxid = computeTxid(bitcoinTx);
        bytes memory txouts = bitcoinTx.outputVector;

        //  memory layout of bitcoinTx.outputVector:
        // | outputVector.length(32-bytes) | outputcount(compact-size).[amount(8-bytes).scriptpubkeysize(compact-size).scriptpubkey(x-bytes); n]
        // peginAmountSats is the amount of txout[0]
        (, uint256 offset) = parseCompactSize(txouts, 32);
        uint64 peginAmountSatsRev = uint64(bytes8(memLoad(txouts, offset)));
        uint256 scriptpubkeysize;
        (scriptpubkeysize, offset) = parseCompactSize(txouts, offset + 8);
        uint256 nextTxoutOffset = scriptpubkeysize + offset;

        // instance-id & depositorAddress is op_return data of txout[1]
        // Bitvm pegin OP_RETURN script (46-bytes):
        // OP_RETURN OP_PUSHBYTES44 {magic-bytes(8-bytes)} {instance-id(16-bytes)} {depositorAddress(20-bytes)}
        (uint256 opReturnScriptSize, uint256 opReturnScriptOffset) = parseCompactSize(txouts, nextTxoutOffset + 8);
        bytes2 firstTwoOpcode = bytes2(memLoad(txouts, opReturnScriptOffset));
        require(opReturnScriptSize == 46 && firstTwoOpcode == 0x6a2c, "invalid pegin OP_RETURN script");
        require(bytes8(memLoad(txouts, opReturnScriptOffset + 2)) == Constants.magic_bytes, "magic_bytes mismatch");
        instanceId = bytes16(memLoad(txouts, opReturnScriptOffset + 10));
        depositorAddress = address(bytes20(memLoad(txouts, opReturnScriptOffset + 26)));
        peginAmountSats = reverseUint64(peginAmountSatsRev);
    }

    function parseKickoffTx(BitcoinTx memory bitcoinTx) internal pure returns (bytes32 kickoffTxid) {
        return computeTxid(bitcoinTx);
    }

    function parseChallengeTx(BitcoinTx memory bitcoinTx)
        internal
        pure
        returns (bytes32 challengeTxid, bytes32 kickoffTxid, uint32 kickoffVout, address challengerAddress)
    {
        challengeTxid = computeTxid(bitcoinTx);

        // kickoffTxid is txid of the txin[0]
        //  memory layout of bitcoinTx.inputVector:
        // | inputVector.length(32-bytes) | inputcount(compact-size).input_0_txid(32-bytes).input_0_vout(4-bytes little-endian)...
        bytes memory txin = bitcoinTx.inputVector;
        (, uint256 offset) = parseCompactSize(txin, 32);
        kickoffTxid = memLoad(txin, offset);
        // kickoffVout is vout of the txin[0]
        kickoffVout = reverseUint32(uint32(bytes4(memLoad(txin, offset + 32))));

        // challengerAddress is op_return data of txout[1]
        // if txout[1] is not op_return, return address(0)
        // Bitvm challenge OP_RETURN script (22-bytes):
        // OP_RETURN OP_PUSHBYTES20 {challengerAddress(20-bytes)}
        challengerAddress = address(0);
        bytes memory txouts = bitcoinTx.outputVector;
        uint256 outputCount;
        (outputCount, offset) = parseCompactSize(txouts, 32);
        if (outputCount >= 2) {
            uint256 scriptpubkeysize;
            (scriptpubkeysize, offset) = parseCompactSize(txouts, offset + 8);
            uint256 nextTxoutOffset = scriptpubkeysize + offset;
            (uint256 opReturnScriptSize, uint256 opReturnScriptOffset) = parseCompactSize(txouts, nextTxoutOffset + 8);
            bytes2 firstTwoOpcode = bytes2(memLoad(txouts, opReturnScriptOffset));
            if (opReturnScriptSize == 22 && firstTwoOpcode == 0x6a14) {
                challengerAddress = address(bytes20(memLoad(txouts, opReturnScriptOffset + 2)));
            }
        }
    }

    function parseTake1Tx(BitcoinTx memory bitcoinTx) internal pure returns (bytes32 take1Txid) {
        return computeTxid(bitcoinTx);
    }

    function parseTake2Tx(BitcoinTx memory bitcoinTx) internal pure returns (bytes32 take2Txid) {
        return computeTxid(bitcoinTx);
    }

    function parseAssertTimeoutTx(BitcoinTx memory bitcoinTx) internal pure returns (bytes32 assertTimeoutTxid) {
        return computeTxid(bitcoinTx);
    }

    function parseDisproveTx(BitcoinTx memory bitcoinTx)
        internal
        pure
        returns (bytes32 disproveTxid, bytes32 kickoffTxid, uint32 kickoffVout, address challengerAddress)
    {
        disproveTxid = computeTxid(bitcoinTx);

        // kickoffTxid is txid of the txin[0]
        bytes memory txin = bitcoinTx.inputVector;
        (, uint256 offset) = parseCompactSize(txin, 32);
        kickoffTxid = memLoad(txin, offset);
        // kickoffVout is vout of the txin[0]
        kickoffVout = reverseUint32(uint32(bytes4(memLoad(txin, offset + 32))));

        // challengerAddress is op_return data of txout[0]
        // if txout[0] is not op_return, return address(0)
        // Bitvm disprove OP_RETURN script (22-bytes):
        // OP_RETURN OP_PUSHBYTES20 {challengerAddress(20-bytes)}
        challengerAddress = address(0);
        bytes memory txouts = bitcoinTx.outputVector;
        (, offset) = parseCompactSize(txouts, 32);
        (uint256 opReturnScriptSize, uint256 opReturnScriptOffset) = parseCompactSize(txouts, offset + 8);
        bytes2 firstTwoOpcode = bytes2(memLoad(txouts, opReturnScriptOffset));
        if (opReturnScriptSize == 22 && firstTwoOpcode == 0x6a14) {
            challengerAddress = address(bytes20(memLoad(txouts, opReturnScriptOffset + 2)));
        }
    }

    function parseCommitTimeoutTx(BitcoinTx memory bitcoinTx) internal pure returns (bytes32 commitTimeoutTxid) {
        return computeTxid(bitcoinTx);
    }

    function parseNackTx(BitcoinTx memory bitcoinTx) internal pure returns (bytes32 nackTxid) {
        return computeTxid(bitcoinTx);
    }

    function computeTxid(BitcoinTx memory bitcoinTx) internal pure returns (bytes32) {
        bytes memory rawTx =
            abi.encodePacked(bitcoinTx.version, bitcoinTx.inputVector, bitcoinTx.outputVector, bitcoinTx.locktime);
        return hash256(rawTx);
    }

    function hash256(bytes memory raw) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(raw)));
    }

    function memLoad(bytes memory data, uint256 offset) internal pure returns (bytes32 res) {
        assembly {
            res := mload(add(data, offset))
        }
    }

    function reverseUint64(uint64 _b) internal pure returns (uint64 v) {
        v = _b;
        // swap bytes
        v = ((v >> 8) & 0x00FF00FF00FF00FF) | ((v & 0x00FF00FF00FF00FF) << 8);
        // swap 2-byte long pairs
        v = ((v >> 16) & 0x0000FFFF0000FFFF) | ((v & 0x0000FFFF0000FFFF) << 16);
        // swap 4-byte long pairs
        v = (v >> 32) | (v << 32);
    }

    function reverseUint32(uint32 _b) internal pure returns (uint32 v) {
        v = _b;

        // swap bytes
        v = ((v >> 8) & 0x00FF00FF) | ((v & 0x00FF00FF) << 8);
        // swap 2-byte long pairs
        v = (v >> 16) | (v << 16);
    }

    function reverseUint16(uint16 _b) internal pure returns (uint16 v) {
        v = (_b << 8) | (_b >> 8);
    }

    function parseCompactSize(bytes memory data, uint256 offset)
        internal
        pure
        returns (uint256 size, uint256 nextOffset)
    {
        // match leading bytes
        require(offset >= 32, "cannot point to memory size slot");
        if (uint8(data[offset - 32]) == 0xff) {
            nextOffset = offset + 9; // one-byte flag, 8 bytes data
            uint64 sizeRev;
            assembly {
                sizeRev := mload(sub(add(data, offset), 23)) // -23 = 1 + 8 - 32
            }
            size = reverseUint64(sizeRev);
        }
        if (uint8(data[offset - 32]) == 0xfe) {
            nextOffset = offset + 5; // one-byte flag, 4 bytes data
            uint32 sizeRev;
            assembly {
                sizeRev := mload(sub(add(data, offset), 27)) // -27 = 1 + 4 - 32
            }
            size = reverseUint32(sizeRev);
        }
        if (uint8(data[offset - 32]) == 0xfd) {
            nextOffset = offset + 3; // one-byte flag, 2 bytes data
            uint16 sizeRev;
            assembly {
                sizeRev := mload(sub(add(data, offset), 29)) // -29 = 1 + 2 - 32
            }
            size = reverseUint16(sizeRev);
        }
        nextOffset = offset + 1; // one-byte flag, 0 bytes data
        size = uint8(data[offset - 32]);
    }
}
