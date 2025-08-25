pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import "./MultiSigVerifier.sol";
import "./interfaces/ISequencerSetPublisher.sol";

// Sequencer Set Publisher
contract SequencerSetPublisher is Initializable, OwnableUpgradeable, ISequencerSetPublisher {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
  
    mapping(uint256 height => bytes32[] cmts) public height_cmts;
    mapping(bytes32 cmt => SequencerSet[] ss) public cmt_ss;

    uint256 latest_height;
    MultiSigVerifier multiSigVerifier;

    function initialize(address initialOwner, address[] calldata initPublishers) public initializer {
        __Ownable_init(initialOwner);
        // ensure valid sigs >= 2/3
        uint quorum = (initPublishers.length * 2 + 1)/3; 
        multiSigVerifier = new MultiSigVerifier(initPublishers, quorum);
    }

    error P2WSHSignatureMismatch();
    error DoubleCommit();
    error InvalidSequencerSet();
    error MismatchPublisher();
    error InvalidGOATHeight();
    error InvalidVotingPower();

    /// @notice Publish a new sequencer set, which should be signed by the older publishers.
    /// @param ss The Sequencer Set 
    /// @param signature The P2WSH signature
    function updateSequencerSet(
        SequencerSet calldata ss,
        bytes calldata signature
    ) external override {
        // Check goat block number is valid
        require(ss.goat_block_number >= latest_height, InvalidGOATHeight());
        require(ss.voting_power > 0, InvalidVotingPower());
        require(msg.sender == ss.p2wsh_sig_hash.recover(signature), P2WSHSignatureMismatch());

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

    /// @notice Update publishers. 
    /// @param newOwners The new publishers
    /// @param changeOwnerSigs The signatures for changing owners, signed by old signers 
    /// @param ss The latest sequencer set metadata 
    /// @param sequencerSetCmtSig The signature of the metadata 
    function updatePublisherSet(
        address[] calldata newOwners,
        bytes[] calldata changeOwnerSigs,
        SequencerSet calldata ss,
        bytes calldata sequencerSetCmtSig
    ) external override {
        // if there is no agreement on the latest sequencer set, it should panic.
        bytes32 previous_cmt = calcSequencerSetCmtAtHeightOrLatest(latest_height); 
        this.updateSequencerSet(ss, sequencerSetCmtSig);
        // ensure valid sigs >= 2/3
        uint quorum = (newOwners.length * 2 + 1)/3; 
        multiSigVerifier.updateOwners(newOwners, quorum, previous_cmt, changeOwnerSigs);
    }

    /// @notice Check if we have an aggrement on the cmt of given height.
    /// @param height Use latest_height if the height is larger than latest_height
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
