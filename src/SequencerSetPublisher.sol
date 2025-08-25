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
  
    mapping(uint256 height => mapping(address publisher => bytes32 cmt)) public height_publisher_cmt;
    mapping(bytes32 cmt => uint cnt) cmt_cnt;

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
    error InvalidQuorumSequencerSet();
    error MismatchPublisher();
    error InvalidGOATHeight();

    /// @notice Publish a new sequencer set, which should be signed by the older publishers.
    /// @param ss The Sequencer Set 
    /// @param signature The P2WSH signature
    function updateSequencerSet(
        SequencerSet calldata ss,
        bytes calldata signature
    ) external override {
        require(ss.goat_block_number >= latest_height, InvalidGOATHeight());
        require(msg.sender == ss.p2wsh_sig_hash.recover(signature), P2WSHSignatureMismatch());
        // Ensure the publisher set is not changed.
        bytes32 expectedPublishersHash = keccak256(
            abi.encodePacked(multiSigVerifier.getOwners())
        ); 
        require(ss.publishers_hash == expectedPublishersHash, MismatchPublisher());

        bytes32 cmt = keccak256(
            abi.encodePacked(ss.sequencer_set_hash, ss.next_sequencer_set_hash, ss.goat_block_number, ss.publishers_hash)
        );
        // Avoid double commit
        require(height_publisher_cmt[ss.goat_block_number][msg.sender] == bytes32(0), DoubleCommit());

        height_publisher_cmt[ss.goat_block_number][msg.sender] = cmt;
        cmt_cnt[cmt] += 1;
        latest_height = ss.goat_block_number;
    }

    /// @notice Update publishers. 
    /// @param newOwners The new publishers
    /// @param changeOwnerSigs The signatures for changing owners, signed by old signers 
    /// @param ss The latest sequencer set metadata 
    /// @param sequencerSetCmtSigs The signature of the metadata 
    function updatePublisherSet(
        address[] calldata newOwners,
        bytes[] calldata changeOwnerSigs,
        SequencerSet calldata ss,
        bytes calldata sequencerSetCmtSigs
    ) external override {
        // if there is no agreement on the latest sequencer set, it should panic.
        bytes32 previous_cmt = calcMajoritySequencerSetCmtAtHeightOrLatest(); 
        this.updateSequencerSet(ss, sequencerSetCmtSigs);
        // ensure valid sigs >= 2/3
        uint quorum = (newOwners.length * 2 + 1)/3; 
        multiSigVerifier.updateOwners(newOwners, quorum, previous_cmt, changeOwnerSigs);
    }

    /// @notice Check if we have an aggrement on the cmt of the latest height.
    function calcMajoritySequencerSetCmtAtHeightOrLatest() public view returns (bytes32) {
        address[] memory publishers = multiSigVerifier.getOwners();
        // Check if we have 2/3 publishers signed
        uint total_number_publishers = publishers.length;
        bytes32 cmt_of_majority = 0; 
        uint num_majority = 0;
        for (uint i=0; i<total_number_publishers; i++) {
            bytes32 cmt = height_publisher_cmt[latest_height][publishers[i]];
            if (cmt != bytes32(0) && cmt_cnt[cmt] > num_majority) {
                num_majority = cmt_cnt[cmt];
                cmt_of_majority = cmt; 
            }
        } 
        require(num_majority * 3 >= 2 * total_number_publishers, InvalidQuorumSequencerSet());
        return cmt_of_majority;
    }
}
