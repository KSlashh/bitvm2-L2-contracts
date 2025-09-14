// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/SequencerSetPublisher.sol";
import "../src/MultiSigVerifier.sol";
import "../src/interfaces/ISequencerSetPublisher.sol";

contract SequencerSetPublisherTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using stdStorage for StdStorage;

    SequencerSetPublisher publisher;

    address owner = vm.addr(1);
    address[] initPublishers;

    function setUp() public {
        initPublishers = new address[](3);
        initPublishers[0] = vm.addr(11);
        initPublishers[1] = vm.addr(12);
        initPublishers[2] = vm.addr(13);
        publisher = new SequencerSetPublisher();
        publisher.initialize(owner, initPublishers);
    }

    function testInitialize() public view {
        // Quorum should be ceil(2/3 * n)
        MultiSigVerifier verifier = publisher.multiSigVerifier();
        address[] memory owners = verifier.getOwners();
        assertEq(owners.length, 3);
        assertEq(owners[0], initPublishers[0]);
    }

    function run_publisher_update_test(uint256[] memory oldPublisherKeys, uint256[] memory newPublisherKeys, uint256 height) public {
        address[] memory oldPublishers = new address[](oldPublisherKeys.length);
        for (uint i = 0; i < oldPublisherKeys.length; i++) {
            oldPublishers[i] = vm.addr(oldPublisherKeys[i]);
            console.log(oldPublishers[i]);
        }

        console.log("new");
        address[] memory newPublishers = new address[](newPublisherKeys.length);
        for (uint i = 0; i < newPublisherKeys.length; i++) {
            newPublishers[i] = vm.addr(newPublisherKeys[i]);
            console.log(newPublishers[i]);
        }

        //ISequencerSetPublisher.SequencerSet memory ss = ISequencerSetPublisher.SequencerSet({
        //    sequencer_set_hash: keccak256("set1"),
        //    next_sequencer_set_hash: keccak256("set2"),
        //    goat_block_number: height,
        //    publishers_hash: keccak256(abi.encodePacked(publisher.multiSigVerifier().getOwners())),
        //    p2wsh_sig_hash: keccak256("sig").toEthSignedMessageHash()
        //});
        //console.logBytes32(ss.publishers_hash);

        bytes32 prevCmt = publisher.calcMajoritySequencerSetCmtAtHeightOrLatest();    
        console.logBytes32(prevCmt);
        uint256 nonce = publisher.multiSigVerifier().nonce();
        console.log("nonce", nonce);
        uint newRequired = (newPublishers.length * 2 + 2)/3; 
        bytes32 digest = keccak256(abi.encode(nonce, newPublishers, newRequired, prevCmt));
        console.logBytes32(digest);

        uint oldRequired = (oldPublishers.length * 2 + 2)/3; 

        bytes[] memory sigs = new bytes[](oldRequired);
        console.log("signing number", oldRequired);
        for (uint j = 0; j < oldRequired; j ++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(oldPublisherKeys[j], digest);
            sigs[j] = abi.encodePacked(r, s, v);
        }
        vm.startPrank(oldPublishers[1]);
        publisher.updatePublisherSet(newPublishers, sigs);
        vm.stopPrank();

        MultiSigVerifier verifier = publisher.multiSigVerifier();
        address[] memory owners = verifier.getOwners();
        assertEq(owners[0], newPublishers[0]);
    }

    function testUpdatePublisherSet() public {
         // New publishers
        uint256[] memory batch = new uint256[](3);
        batch[0] = 11;
        batch[1] = 12;
        batch[2] = 13;
        run_sequencer_update_test(batch, 10, keccak256("commit1"));
        
        uint256[] memory batch1 = new uint256[](5);
        batch1[0] = 21;
        batch1[1] = 22;
        batch1[2] = 23;
        batch1[3] = 24;
        batch1[4] = 25;
        run_publisher_update_test(batch, batch1, 11);
        run_sequencer_update_test(batch1, 12, keccak256("commit2"));

        uint256[] memory batch2 = new uint256[](3);
        batch2[0] = 31;
        batch2[1] = 32;
        batch2[2] = 33;
        run_publisher_update_test(batch1, batch2, 13);
    }

    function run_sequencer_update_test(uint256[] memory publisherKeys, uint256 height, bytes32 commits) public {
       address[] memory oldPublishers = new address[](publisherKeys.length);
       for (uint i = 0; i < publisherKeys.length; i++) {
           oldPublishers[i] = vm.addr(publisherKeys[i]);
           console.log(oldPublishers[i]);
       }

       ISequencerSetPublisher.SequencerSet memory ss = ISequencerSetPublisher.SequencerSet({
           sequencer_set_hash: keccak256("set1"),
           next_sequencer_set_hash: keccak256("set2"),
           goat_block_number: height,
           publishers_hash: keccak256(abi.encodePacked(publisher.multiSigVerifier().getOwners())),
           p2wsh_sig_hash: commits.toEthSignedMessageHash()
       });

       uint oldRequired = (oldPublishers.length * 2 + 2)/3; 

       for (uint i = 0; i < oldRequired; i ++) {
           (uint8 v, bytes32 r, bytes32 s) = vm.sign(publisherKeys[i], ss.p2wsh_sig_hash);
           bytes memory sig = abi.encodePacked(r, s, v);
           vm.startPrank(oldPublishers[i]);
           publisher.updateSequencerSet(ss, sig);
           vm.stopPrank();
       }
    }

    function testUpdateSequencerSet() public {
        // New publishers
        uint256[] memory batch = new uint256[](3);
        batch[0] = 11;
        batch[1] = 12;
        batch[2] = 13;
        run_sequencer_update_test(batch, 10, keccak256("commit1"));
        run_sequencer_update_test(batch, 11, keccak256("commit2"));
        run_sequencer_update_test(batch, 12, keccak256("commit3"));
        run_sequencer_update_test(batch, 13, keccak256("commit4"));
    }
}