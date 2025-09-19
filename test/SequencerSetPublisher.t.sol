// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "forge-std/Test.sol";
import "../src/SequencerSetPublisher.sol";
import "../src/MultiSigVerifier.sol";
import "../src/interfaces/ISequencerSetPublisher.sol";
import "forge-std/console.sol";

contract SequencerSetPublisherTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using stdStorage for StdStorage;

    SequencerSetPublisher sspublisher;

    address owner = vm.addr(1);
    address[] initPublishers;
    uint256[] batch;
    uint256[] batch1;
    uint256[] batch2;

    function _get_pubkey_from_prvkey(uint number) internal pure returns (bytes[] memory) {
        bytes[5] memory newPublisherPubkeysConstant;
        newPublisherPubkeysConstant[0] = hex"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
        newPublisherPubkeysConstant[1] = hex"024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766";
        newPublisherPubkeysConstant[2] = hex"02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337";
        newPublisherPubkeysConstant[3] = hex"03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b";
        newPublisherPubkeysConstant[4] = hex"0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7";
        require(number <= newPublisherPubkeysConstant.length); 

        bytes[] memory newPublisherPubkeys = new bytes[](number);
        for (uint i = 0; i < number; i ++) {
            newPublisherPubkeys[i] = newPublisherPubkeysConstant[i];
        }

        return newPublisherPubkeys; 
    } 

    function setUp() public {
        batch = new uint256[](3);
        batch[0] = 11;
        batch[1] = 12;
        batch[2] = 13;
   
        batch1 = new uint256[](5);
        batch1[0] = 21;
        batch1[1] = 22;
        batch1[2] = 23;
        batch1[3] = 24;
        batch1[4] = 25;


        batch2 = new uint256[](4);
        batch2[0] = 31;
        batch2[1] = 32;
        batch2[2] = 33;
        batch2[3] = 34;


        initPublishers = new address[](3);
        initPublishers[0] = vm.addr(batch[0]);
        initPublishers[1] = vm.addr(batch[1]);
        initPublishers[2] = vm.addr(batch[2]);

        sspublisher = new SequencerSetPublisher();
        
        sspublisher.initialize(owner, initPublishers, _get_pubkey_from_prvkey(initPublishers.length));
    }

    function testInitialize() public view {
        // Quorum should be ceil(2/3 * n)
        MultiSigVerifier verifier = sspublisher.multiSigVerifier();
        address[] memory owners = verifier.getOwners();
        assertEq(owners.length, 3);
        assertEq(owners[0], initPublishers[0]);
    }

    function run_publisher_update_test(
        uint256[] memory oldPublisherKeys,
        uint256[] memory newPublisherKeys,
        uint256 height
    ) public {
        address[] memory oldPublishers = new address[](oldPublisherKeys.length);
        for (uint i = 0; i < oldPublisherKeys.length; i++) {
            oldPublishers[i] = vm.addr(oldPublisherKeys[i]);
        }

        address[] memory newPublishers = new address[](newPublisherKeys.length);
        for (uint i = 0; i < newPublisherKeys.length; i++) {
            newPublishers[i] = vm.addr(newPublisherKeys[i]);
        }

        uint256 nonce = sspublisher.multiSigVerifier().nonce();
        uint newRequired = (newPublishers.length * 2 + 2) / 3;
        bytes32 digest = keccak256(
            abi.encode(nonce, newPublishers, newRequired)
        );

        bytes[] memory newPublisherPubkeys = _get_pubkey_from_prvkey(newPublishers.length);

        uint oldRequired = (oldPublishers.length * 2 + 2) / 3;
        bytes[] memory sigs = new bytes[](oldRequired);
        for (uint j = 0; j < oldRequired; j++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                oldPublisherKeys[j],
                digest
            );
            sigs[j] = abi.encodePacked(r, s, v);
        }
        console.log("height: ", height);
        vm.startPrank(oldPublishers[1]);
        sspublisher.updatePublisherSet(newPublishers, newPublisherPubkeys, sigs, height);
        vm.stopPrank();

        MultiSigVerifier verifier = sspublisher.multiSigVerifier();
        address[] memory owners = verifier.getOwners();
        assertEq(owners[0], newPublishers[0]);
    }

    function testUpdatePublisherSet() public {
        // genesis sequencer set commit, publisher is not changed
        run_sequencer_update_test(batch, batch, 10, keccak256("commit1"), keccak256("set1"), keccak256("set2"));
        // publisher commit, sequencer set is not changed
        run_sequencer_update_test(batch, batch1, 11, keccak256("commit2"), keccak256("set2"), keccak256("set2"));
        // apply publisher update
        assert(sspublisher.latestConfirmedHeight() == 0);
        run_publisher_update_test(batch, batch1, 11);
        assert(sspublisher.latestConfirmedHeight() == 11);

        // sequencer set commit, publisher is not changed
        run_sequencer_update_test(batch1, batch1, 12, keccak256("commit3"), keccak256("set2"), keccak256("set22"));
        run_sequencer_update_test(batch1, batch1, 13, keccak256("commit3"), keccak256("set22"), keccak256("set3"));
        // publisher commit, sequencer set is not changed
        run_sequencer_update_test(batch1, batch2, 17, keccak256("commit4"), keccak256("set3"), keccak256("set3"));
        // apply publisher update
        assert(sspublisher.latestConfirmedHeight() == 11);
        run_publisher_update_test(batch1, batch2, 17);
        assert(sspublisher.latestConfirmedHeight() == 17);

        // sequencer set commit, publisher is not changed
        run_sequencer_update_test(batch2, batch2, 20, keccak256("commit5"), keccak256("set3"), keccak256("set4"));
    }

    function run_sequencer_update_test(
        uint256[] memory publisherKeys,
        uint256[] memory nextPublisherKeys,
        uint256 height,
        bytes32 p2wshSigHash,
        bytes32 sequencerSetHash,
        bytes32 nextSequencerSetHash
    ) public {
        address[] memory publishers = new address[](publisherKeys.length);
        for (uint i = 0; i < publisherKeys.length; i++) {
            publishers[i] = vm.addr(publisherKeys[i]);
        }
        address[] memory nextPublishers = new address[](nextPublisherKeys.length);
        for (uint i = 0; i < nextPublisherKeys.length; i++) {
            nextPublishers[i] = vm.addr(nextPublisherKeys[i]);
        }

        ISequencerSetPublisher.SequencerSet memory ss = ISequencerSetPublisher
            .SequencerSet({
                sequencerSetHash: sequencerSetHash,
                nextSequencerSetHash: nextSequencerSetHash,
                publishersHash: keccak256(abi.encodePacked(publishers)),
                nextPublishersHash: keccak256(abi.encodePacked(nextPublishers)),
                p2wshSigHash: p2wshSigHash.toEthSignedMessageHash(),
                goatBlockNumber: height
            });

        uint oldRequired = (publishers.length * 2 + 2) / 3;

        for (uint i = 0; i < oldRequired; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                publisherKeys[i],
                ss.p2wshSigHash
            );
            bytes memory sig = abi.encodePacked(r, s, v);
            vm.startPrank(publishers[i]);
            sspublisher.updateSequencerSet(ss, sig);
            vm.stopPrank();
        }
    }

    function testUpdateSequencerSet() public {
        // New publishers
        run_sequencer_update_test(batch, batch, 10, keccak256("commit1"), keccak256("set1"), keccak256("set2"));
        run_sequencer_update_test(batch, batch, 11, keccak256("commit2"), keccak256("set2"), keccak256("set3"));
        run_sequencer_update_test(batch, batch, 12, keccak256("commit3"), keccak256("set3"), keccak256("set4"));
        run_sequencer_update_test(batch, batch, 13, keccak256("commit4"), keccak256("set4"), keccak256("set5"));
    }
}
