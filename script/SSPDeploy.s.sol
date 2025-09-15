// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/SequencerSetPublisher.sol";

contract Deploy is Script {
    function run() external {
        // Load from environment variables or replace inline
        address initialOwner = vm.envAddress("OWNER"); 

        address[] memory initPublishers = new address[](5);
        initPublishers[0] = 0xcC1Bd124EA962Dd3e6f10F814FB6C4493CEA6d27;
        initPublishers[1] = 0x0b71c9fc399e7FE424f3c22d872735F32550eC09;
        initPublishers[2] = 0x55C55d24bBef5d79918270Af9366b97fC0C7AC7b;
        initPublishers[3] = 0xeBBa6C3BE7Dc14FAeB1c2547cF43D4ad6aD46Ef4;
        initPublishers[4] = 0xa0F88c27B535615A8D8808c6023986a540161021;

        bytes[] memory initPublisherBTCPubkeys = new bytes[](5);
        initPublisherBTCPubkeys[0] = hex"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
        initPublisherBTCPubkeys[1] = hex"024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766";
        initPublisherBTCPubkeys[2] = hex"02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337";
        initPublisherBTCPubkeys[3] = hex"03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b";
        initPublisherBTCPubkeys[4] = hex"0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7";

        vm.startBroadcast();

        SequencerSetPublisher publisher = new SequencerSetPublisher();

        publisher.initialize(initialOwner, initPublishers, initPublisherBTCPubkeys);

        vm.stopBroadcast();

        console.log("SequencerSetPublisher deployed at:", address(publisher));
    }
}