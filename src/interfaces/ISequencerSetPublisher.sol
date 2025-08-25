// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISequencerSetPublisher {
    struct SequencerSet {
        bytes32 sequencer_set_hash; // validator_hash
        bytes32 publishers_hash; 
        bytes32 p2wsh_sig_hash;
        bytes32 next_sequencer_set_hash; // next_validator_hash
        uint256 goat_block_number;
    }

    function updateSequencerSet(
        SequencerSet calldata ss,
        bytes calldata signature
    ) external;

     // Update publisher at once by multi-sig
    function updatePublisherSet(
        address[] calldata newOwners,
        bytes[] calldata signatures,
        SequencerSet calldata ss,
        bytes calldata sequencerSetCmtSigs
    ) external; 
}