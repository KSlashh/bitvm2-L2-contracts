// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import "./MultiSigVerifier.sol";
import "./interfaces/ISequencerSetPublisher.sol";
import "./libraries/EthSign.sol";

import "forge-std/Test.sol";

// Sequencer Set Publisher
contract SequencerSetPublisher is
    Initializable,
    OwnableUpgradeable,
    ISequencerSetPublisher
{
    using ECDSA for bytes32;
    using EthSign for bytes;
    using MessageHashUtils for bytes32;

    mapping(uint256 height => mapping(address publisher => bytes32 cmt))
        public heightPublisherCmt;
    mapping(bytes32 cmt => uint cnt) cmtCnt;
    mapping(address publisher => bytes pubkey) public publisherPubkeys;

    bytes32 constant INIT_CMT = keccak256("GOAT");

    uint256 public latestHeight;
    MultiSigVerifier public multiSigVerifier;

    function initialize(
        address initialOwner,
        address[] calldata initPublishers
    ) public initializer {
        __Ownable_init(initialOwner);
        // ensure valid sigs >= 2/3
        uint quorum = (initPublishers.length * 2 + 2) / 3;
        latestHeight = 0;
        multiSigVerifier = new MultiSigVerifier(initPublishers, quorum);
    }

    /// @notice Publish a new sequencer set, which should be signed by the older publishers.
    /// @param ss The Sequencer Set
    /// @param signature The P2WSH signature
    function updateSequencerSet(
        SequencerSet calldata ss,
        bytes calldata signature
    ) external override {
        require(ss.goatBlockNumber >= latestHeight, InvalidGOATHeight());
        require(multiSigVerifier.isOwner(msg.sender), MismatchPublisher());
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
                ss.goatBlockNumber,
                ss.publishersHash
            )
        );
        // Avoid double commit
        require(
            heightPublisherCmt[ss.goatBlockNumber][msg.sender] == bytes32(0),
            DoubleCommit()
        );

        heightPublisherCmt[ss.goatBlockNumber][msg.sender] = cmt;
        cmtCnt[cmt] += 1;
        latestHeight = ss.goatBlockNumber;
    }

    /// @notice Update publishers.
    /// @param newPublisherPubkeys The new publisher's public key
    /// @param changeOwnerSigs The signatures for changing owners, co-signed by old signers
    /// @param p2wshSigHash The p2wsgh sighash of publisher change BTC transaction, co-signed by old signers
    function updatePublisherSet(
        bytes[] calldata newPublisherPubkeys,
        bytes[] calldata changeOwnerSigs,
        bytes32 p2wshSigHash
    ) external override {
        address[] memory newPublishers = new address[](
            newPublisherPubkeys.length
        );
        for (uint i = 0; i < newPublisherPubkeys.length; i++) {
            newPublishers[i] = newPublisherPubkeys[i].recover();
            console.log("publishers", newPublishers[i]);
            publisherPubkeys[newPublishers[i]] = newPublisherPubkeys[i];
        }
        // if there is no agreement on the latest sequencer set, it should panic.
        bytes32 prevCmt = calcMajoritySequencerSetCmtAtHeightOrLatest();
        // ensure valid sigs >= 2/3
        uint quorum = (newPublishers.length * 2 + 2) / 3;
        multiSigVerifier.updateOwners(
            newPublishers,
            quorum,
            prevCmt,
            p2wshSigHash,
            changeOwnerSigs
        );
    }

    /// @notice Check if we have an aggrement on the cmt of the latest height.
    function calcMajoritySequencerSetCmtAtHeightOrLatest()
        public
        view
        returns (bytes32)
    {
        if (latestHeight == 0) {
            return INIT_CMT;
        }
        address[] memory publishers = multiSigVerifier.getOwners();
        // Check if we have 2/3 publishers signed
        bytes32 cmtOfMajority = 0;
        uint num_majority = 0;
        for (uint i = 0; i < publishers.length; i++) {
            bytes32 cmt = heightPublisherCmt[latestHeight][publishers[i]];
            if (cmt != bytes32(0) && cmtCnt[cmt] > num_majority) {
                num_majority = cmtCnt[cmt];
                cmtOfMajority = cmt;
            }
        }
        require(
            num_majority * 3 >= 2 * publishers.length,
            InvalidQuorumSequencerSet()
        );
        return cmtOfMajority;
    }
}