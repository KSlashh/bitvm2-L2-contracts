pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./MultiSigVerifier.sol";
import "./P2WSHSignatureVerifier.sol";

// Sequencer Set Publisher
contract SequencerSetPublisher is Initializable, OwnableUpgradeable {
    struct SequencerSet {
        bytes32 sequencer_set_hash; // validator_hash
        bytes32 publishers_hash; 
        bytes32 p2wsh_sig_hash;
        uint256 voting_power;
        bytes32 next_sequencer_set_hash; // next_validator_hash
        uint256 goat_block_number;
    }

    mapping(uint256 height => bytes32[] cmts) public height_cmts;
    mapping(bytes32 cmt => SequencerSet[] ss) public cmt_ss;

    uint256 latest_height;
    MultiSigVerifier multiSigVerifier;
    P2WSHSignatureVerifier p2wshSigVerifier;

    function initialize(address initialOwner, address[] calldata initPublishers) public initializer {
        __Ownable_init(initialOwner);
        // ensure valid sigs >= 2/3
        uint quorum = (initPublishers.length * 2 + 1)/3; 
        multiSigVerifier = new MultiSigVerifier(initPublishers, quorum);
        p2wshSigVerifier = new P2WSHSignatureVerifier();
    }

    error P2WSHSignatureMismatch();
    error DoubleCommit();
    error InvalidSequencerSet();
    error AddressConversionOutOfBounds();
    error MismatchPublisher();
    error InvalidGOATHeight();
    error InvalidVotingPower();

    /// @notice Publish a new sequencer set, which should be signed by the older publishers.
    /// @param ss The Sequencer Set 
    /// @param _v The v-value of the P2WSH signature
    /// @param _r The r-value of the P2WSH signature
    /// @param _s The s-value of the P2WSH signature
    function updateSequencerSet(
        SequencerSet calldata ss,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external {
        // Check goat block number is valid
        require(ss.goat_block_number >= latest_height, InvalidGOATHeight());
        require(ss.voting_power > 0, InvalidVotingPower());
        require(p2wshSigVerifier.verifyRSV(ss.p2wsh_sig_hash, msg.sender, _v, _r, _s), P2WSHSignatureMismatch());

        // ensure the publishers is not changed.
        bytes32 expectedPublishersHash = keccak256(
            abi.encodePacked(multiSigVerifier.getOwners())
        ); 
        require(ss.publishers_hash == expectedPublishersHash, MismatchPublisher());

        bytes32 cmt = keccak256(
            abi.encodePacked(ss.sequencer_set_hash, ss.next_sequencer_set_hash, ss.goat_block_number, ss.publishers_hash)
        );

        // Avoid double-commit
        bytes32[] memory cur_cmts = height_cmts[ss.goat_block_number];
        for (uint i=0; i<cur_cmts.length; i++) {
            require(cur_cmts[i] != cmt, DoubleCommit());
        }

        height_cmts[ss.goat_block_number].push(cmt);
        cmt_ss[cmt].push(ss);
        latest_height = ss.goat_block_number;
    }

    // Update publisher at once by multi-sig
    function updatePublisherSet(
        address[] calldata newOwners,
        bytes[] calldata signatures
    ) external {
        bytes32 latest_cmt = calcSequencerSetCmtAtHeightOrLatest(latest_height); 
        // ensure valid sigs >= 2/3
        uint quorum = (newOwners.length * 2 + 1)/3; 
        multiSigVerifier.updateOwners(newOwners, quorum, latest_cmt, signatures);
    }

    // Anyone can calculate the commitment for a given height, and publish it to Bitcoin
    function calcSequencerSetCmtAtHeightOrLatest(uint256 height) public view returns (bytes32) {
        if (height > latest_height) {
            height = latest_height;
        }

        bytes32[] memory cmts = height_cmts[height];
        require(cmts.length > 0);

        bytes32 cmt_with_max_power = 0; 
        uint max_power = 0;
        uint total_power = 0;
        for (uint i=0; i<cmts.length; i++) {
            SequencerSet[] memory ss = cmt_ss[cmts[i]];
            uint power = 0; 
            for (uint j=0; j < ss.length; j++) {
                power += ss[j].voting_power; 
            }
            if (power > max_power) {
               max_power = power;
               cmt_with_max_power = cmts[i]; 
            }
            total_power += power;
        }
        require(max_power * 3 >= 2 * total_power, InvalidSequencerSet());
        return cmt_with_max_power;
    }
}
