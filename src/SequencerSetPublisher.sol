/ SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import "./MultiSigVerifier.sol";
import "./interfaces/ISequencerSetPublisher.sol";
import "./Constants.sol";

// Sequencer Set Publisher
contract SequencerSetPublisher is
    Initializable,
    OwnableUpgradeable,
    ISequencerSetPublisher
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    mapping(uint256 height => mapping(address publisher => bytes32 cmt))
        public heightSequencerCmt;
    mapping(bytes32 cmt => uint cnt) sequencerCmtCnt;
    mapping(uint256 height => address[]) heightPublishers;

    mapping(address publisher => bytes pubkey) public publisherBTCPubkeys;    
    mapping(bytes32 cmt => SequencerSet ss) public cmtSequencerSet;

    uint256 public latestConfirmedHeight;
    MultiSigVerifier public multiSigVerifier;

    function initialize(
        address initialOwner,
        address[] calldata initPublishers,
        bytes[] calldata initPublisherBTCPubkeys
    ) public initializer {
        require(initPublisherBTCPubkeys.length == initPublishers.length, "Invalid Publishers");
        __Ownable_init(initialOwner);
        // ensure valid sigs >= 2/3
        uint quorum = (initPublishers.length * 2 + 2) / 3;
        latestConfirmedHeight = 0;
        for (uint i = 0; i < initPublisherBTCPubkeys.length; i++) {
            assert(initPublisherBTCPubkeys[i].length == 33);
            publisherBTCPubkeys[initPublishers[i]] = initPublisherBTCPubkeys[i];
        }
        multiSigVerifier = new MultiSigVerifier(initPublishers, quorum);
        heightPublishers[0] = initPublishers;
    }

    /// @notice Publish a new sequencer set, which should be signed by the older publishers.
    /// @param ss The Sequencer Set
    /// @param signature The P2WSH signature
    function updateSequencerSet(
        SequencerSet calldata ss,
        bytes calldata signature
    ) external override {
        require(ss.goatBlockNumber >= latestConfirmedHeight, InvalidGOATHeight());
        require(multiSigVerifier.isOwner(msg.sender), InvalidPublisherSet());
        require(
            msg.sender == ss.p2wshSigHash.recover(signature),
            P2WSHSignatureMismatch()
        );
        // Ensure the publisher set is not changed.
        bytes32 expectedPublishersHash = keccak256(
            abi.encodePacked(multiSigVerifier.getOwners())
        );
        require(
            ss.publishersHash == expectedPublishersHash,
            MismatchPublisher()
        );

        bytes32 cmt = keccak256(
            abi.encodePacked(
                ss.sequencerSetHash,
                ss.nextSequencerSetHash,
                ss.publishersHash,
                ss.nextPublishersHash,
                ss.p2wshSigHash,
                ss.goatBlockNumber
            )
        );
        // Avoid double commit
        require(
            heightSequencerCmt[ss.goatBlockNumber][msg.sender] == bytes32(0),
            DoubleCommit()
        );

        heightSequencerCmt[ss.goatBlockNumber][msg.sender] = cmt;
        sequencerCmtCnt[cmt] += 1;
        cmtSequencerSet[cmt] = ss;
        heightPublishers[ss.goatBlockNumber].push(msg.sender);
    }

    /// @notice Update publishers.
    /// @param newPublishers The new publisher's address 
    /// @param newPublisherBTCPubkeys The new publisher's compressed BTC public key
    /// @param changePublisherSigs The signatures for changing owners, co-signed by old signers
    function updatePublisherSet(
        address[] calldata newPublishers,
        bytes[] calldata newPublisherBTCPubkeys,
        bytes[] calldata changePublisherSigs,
        uint256 height 
    ) external override {
        bytes32 cmt = calcMajoritySequencerSetCmtAtHeightOrLatest(height);
        SequencerSet storage ss = cmtSequencerSet[cmt];
        require(latestConfirmedHeight < height, InvalidGOATHeight());
        require(height == ss.goatBlockNumber, InvalidGOATHeight());
      
        address[] memory publishers = multiSigVerifier.getOwners();
        bytes32 expectedPublishersHash = keccak256(
            abi.encodePacked(publishers)
        );
        require(
            ss.publishersHash == expectedPublishersHash,
            MismatchPublisher()
        );

        if (latestConfirmedHeight > 0) {
            // check the continuality of the update chain
            bytes32 prevCmt = calcMajoritySequencerSetCmtAtHeightOrLatest(latestConfirmedHeight);
            SequencerSet storage prevSs = cmtSequencerSet[prevCmt];
            require(prevSs.nextPublishersHash == ss.publishersHash, InvalidPublisherSet());
            // TODO: we should check this when update sequencer set.  
            //require(prevSs.nextSequencerSetHash == ss.sequencerSetHash, InvalidSequencerSet());
        }

        // ensure valid sigs >= 2/3
        uint quorum = (newPublishers.length * 2 + 2) / 3;
        multiSigVerifier.updateOwners(newPublishers, quorum, changePublisherSigs);

        for (uint i = 0; i < newPublisherBTCPubkeys.length; i++) {
            assert(newPublisherBTCPubkeys[i].length == 33);
            publisherBTCPubkeys[newPublishers[i]] = newPublisherBTCPubkeys[i];
        }
        latestConfirmedHeight = height;
    }

    /// @notice Check if we have an aggrement on the cmt of the latest height.
    function calcMajoritySequencerSetCmtAtHeightOrLatest(uint256 height)
        public
        view
        returns (bytes32)
    {
        require(height > 0, InvalidGOATHeight());
        address[] memory publishers = heightPublishers[height];

        // Check if we have 2/3 publishers signed
        bytes32 agreement = 0;
        uint quorum = 0;
        for (uint i = 0; i < publishers.length; i++) {
            bytes32 cmt = heightSequencerCmt[height][publishers[i]];
            if (cmt != bytes32(0) && sequencerCmtCnt[cmt] > quorum) {
                quorum = sequencerCmtCnt[cmt];
                agreement = cmt;
            }
        }

        require(
            quorum * 3 >= 2 * publishers.length,
            InvalidQuorumSequencerSet()
        );
        return agreement;
    }
}