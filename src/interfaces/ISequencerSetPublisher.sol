// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISequencerSetPublisher {
    struct SequencerSet {
        bytes32 sequencerSetHash; // validator_hash
        bytes32 publishersHash; 
        bytes32 p2wshSigHash;
        bytes32 nextSequencerSetHash; // next_validator_hash
        uint256 goatBlockNumber;
    }

    error P2WSHSignatureMismatch();
    error DoubleCommit();
    error InvalidSequencerSet();
    error InvalidQuorumSequencerSet();
    error MismatchPublisher();
    error InvalidGOATHeight();
    error k256Decompress_Invalid_Length_Error();
    error k256DeriveY_Invalid_Prefix_Error();

    function updateSequencerSet(
        SequencerSet calldata ss,
        bytes calldata signature
    ) external;

     // Update publisher at once by multi-sig
    function updatePublisherSet(
        bytes[] calldata newPublisherPubkeys,
        bytes[] calldata signatures,
        bytes32 p2wshSigHash
    ) external; 
}