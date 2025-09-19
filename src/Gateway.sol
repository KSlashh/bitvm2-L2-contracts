// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IBitcoinSPV} from "./interfaces/IBitcoinSPV.sol";
import {IPegBTC} from "./interfaces/IPegBTC.sol";
import {Converter} from "./libraries/Converter.sol";
import {BitvmTxParser} from "./libraries/BitvmTxParser.sol";
import {MerkleProof} from "./libraries/MerkleProof.sol";

contract BitvmPolicy {
    uint64 constant rateMultiplier = 10000;

    uint64 public minStakeAmountSats;
    uint64 public stakeRate;
    uint64 public minChallengeAmountSats;
    uint64 public challengeRate;

    uint64 public minPeginFeeSats;
    uint64 public peginFeeRate;
    uint64 public minOperatorRewardSats;
    uint64 public operatorRewardRate;
    uint64 public minChallengerRewardSats;
    uint64 public challengerRewardRate;
    uint64 public minDisproverRewardSats;
    uint64 public disproverRewardRate;

    function isValidStakeAmount(uint64 peginAmountSats, uint64 stakeAmountSats) public view returns (bool) {
        return stakeAmountSats >= minStakeAmountSats + peginAmountSats * stakeRate / rateMultiplier;
    }

    function isValidChallengeAmount(uint64 peginAmountSats, uint64 challengeAmount) public view returns (bool) {
        return challengeAmount >= minChallengeAmountSats + peginAmountSats * challengeRate / rateMultiplier;
    }
}

contract GatewayUpgradeable is BitvmPolicy {
    event BridgeInRequest(
        bytes16 indexed instanceId,
        address indexed depositorAddress,
        uint64 peginAmountSats,
        uint64[3] txnFees,
        Utxo[] userInputs,
        bytes32 userXonlyPubkey,
        string userChangeAddress,
        string userRefundAddress
    );
    event CommitteeResponse(bytes16 indexed instanceId, address indexed committeeAddress, bytes32 committeeXonlyPubkey);
    event BridgeIn(
        address indexed depositorAddress,
        bytes16 indexed instanceId,
        uint64 indexed peginAmountSats,
        uint64 feeAmountSats
    );
    event InitWithdraw(
        bytes16 indexed instanceId, bytes16 indexed graphId, address indexed operatorAddress, uint64 withdrawAmountSats
    );
    event CancelWithdraw(bytes16 indexed instanceId, bytes16 indexed graphId, address indexed triggerAddress);
    event ProceedWithdraw(bytes16 indexed instanceId, bytes16 indexed graphId, bytes32 kickoffTxid);
    event WithdrawHappyPath(
        bytes16 indexed instanceId,
        bytes16 indexed graphId,
        bytes32 take1Txid,
        address indexed operatorAddress,
        uint64 rewardAmountSats
    );
    event WithdrawUnhappyPath(
        bytes16 indexed instanceId,
        bytes16 indexed graphId,
        bytes32 take2Txid,
        address indexed operatorAddress,
        uint64 rewardAmountSats
    );
    event WithdrawDisproved(
        bytes16 indexed instanceId,
        bytes16 indexed graphId,
        DisproveTxType disproveTxType,
        uint256 nackIndex,
        bytes32 challengeStartTxid,
        bytes32 challengeFinishTxid,
        address challengerAddress,
        address disproverAddress,
        uint64 challengerRewardAmountSats,
        uint64 disproverRewardAmountSats
    );

    enum DisproveTxType {
        AssertTimeout,
        OperatorCommitTimeout,
        OperatorNack,
        Disprove
    }
    enum PeginStatus {
        None,
        Pending,
        Withdrawbale,
        Processing,
        Locked,
        Claimed,
        Discarded
    }
    enum WithdrawStatus {
        None,
        Processing,
        Initialized,
        Canceled,
        Complete,
        Disproved
    }

    struct Utxo {
        bytes32 txid;
        uint32 vout;
        uint64 amountSats;
    }

    struct PeginDataInner {
        PeginStatus status;
        bytes16 instanceId;
        address depositorAddress;
        uint64 peginAmountSats;
        uint64[3] txnFees;
        Utxo[] userInputs;
        bytes32 userXonlyPubkey;
        string userChangeAddress;
        string userRefundAddress;
        bytes32 peginTxid;
        uint256 createdAt;
        // EnumerableMap
        address[] committeeAddresses;
        mapping(address value => uint256) committeeAddressPositions;
        mapping(address => bytes32) committeeXonlyPubkeys;
    }

    struct PeginData {
        PeginStatus status;
        bytes16 instanceId;
        address depositorAddress;
        uint64 peginAmountSats;
        uint64[3] txnFees;
        Utxo[] userInputs;
        bytes32 userXonlyPubkey;
        string userChangeAddress;
        string userRefundAddress;
        bytes32 peginTxid;
        uint256 createdAt;
        address[] committeeAddresses;
        bytes32[] committeeXonlyPubkeys;
    }

    struct WithdrawData {
        WithdrawStatus status;
        bytes32 peginTxid;
        address operatorAddress;
        bytes16 instanceId;
        uint256 lockAmount;
        uint256 btcBlockHeightAtWithdraw;
    }

    struct GraphData {
        uint64 stakeAmountSats;
        bytes1 operatorPubkeyPrefix;
        bytes32 operatorPubkey;
        bytes32 peginTxid;
        bytes32 kickoffTxid;
        bytes32 take1Txid;
        bytes32 take2Txid;
        bytes32 assertTimoutTxid;
        bytes32 commitTimoutTxid;
        bytes32[] NackTxids;
    }

    IPegBTC public pegBTC;
    IBitcoinSPV public bitcoinSPV;

    uint256 public responseWindowBlocks = 200;

    bytes16[] public instanceIds;
    mapping(bytes16 instanceId => bytes16[] graphIds) public instanceIdToGraphIds;
    mapping(bytes16 instanceId => PeginDataInner) public peginDataMap;
    mapping(bytes16 graphId => GraphData) public graphDataMap;
    mapping(bytes16 graphId => WithdrawData) public withdrawDataMap;

    // getters
    function getGraphIdsByInstanceId(bytes16 instanceId) external view returns (bytes16[] memory) {
        return instanceIdToGraphIds[instanceId];
    }

    function getPeginData(bytes16 instanceId) external view returns (PeginData memory) {
        PeginDataInner storage data = peginDataMap[instanceId];
        return PeginData({
            status: data.status,
            instanceId: data.instanceId,
            depositorAddress: data.depositorAddress,
            peginAmountSats: data.peginAmountSats,
            txnFees: data.txnFees,
            userInputs: data.userInputs,
            userXonlyPubkey: data.userXonlyPubkey,
            userChangeAddress: data.userChangeAddress,
            userRefundAddress: data.userRefundAddress,
            peginTxid: data.peginTxid,
            createdAt: data.createdAt,
            committeeAddresses: data.committeeAddresses,
            committeeXonlyPubkeys: getCommitteePubkeysUnsafe(instanceId)
        });
    }

    function getGraphData(bytes16 graphId) external view returns (GraphData memory) {
        return graphDataMap[graphId];
    }

    modifier onlyCommittee() {
        // TODO: only committee members can call this function
        _;
    }

    modifier onlyCommitteeOrOperator(bytes16 graphId) {
        // TODO: only committee members or operator can call this function
        _;
    }

    function postPeginRequest(
        bytes16 instanceId,
        uint64 peginAmountSats,
        uint64[3] calldata txnFees,
        address receiverAddress,
        Utxo[] calldata userInputs,
        bytes32 userXonlyPubkey,
        string calldata userChangeAddress,
        string calldata userRefundAddress
    ) external payable {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        require(peginData.status == PeginStatus.None, "instanceId already used");
        // TODO: check peginAmount,feeRate,userInputs
        // TODO: charge fee

        peginData.status = PeginStatus.Pending;
        peginData.instanceId = instanceId;
        peginData.depositorAddress = receiverAddress;
        peginData.peginAmountSats = peginAmountSats;
        peginData.txnFees = txnFees;
        peginData.userInputs = userInputs;
        peginData.userXonlyPubkey = userXonlyPubkey;
        peginData.userChangeAddress = userChangeAddress;
        peginData.userRefundAddress = userRefundAddress;
        peginData.createdAt = block.number;
        instanceIds.push(instanceId);

        emit BridgeInRequest(
            instanceId,
            receiverAddress,
            peginAmountSats,
            txnFees,
            userInputs,
            userXonlyPubkey,
            userChangeAddress,
            userRefundAddress
        );
    }

    function answerPeginRequest(bytes16 instanceId, bytes32 committeeXonlyPubkey) external onlyCommittee {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        require(peginData.status == PeginStatus.Pending, "not a pending pegin request");
        require(peginData.createdAt + responseWindowBlocks >= block.number, "response window expired");

        address committeeAddress = msg.sender;
        if (peginData.committeeAddressPositions[committeeAddress] == 0) {
            peginData.committeeAddresses.push(committeeAddress);
            // The value is stored at length-1, but we add 1 to all indexes and use 0 as a sentinel value
            peginData.committeeAddressPositions[committeeAddress] = peginData.committeeAddresses.length;
            peginData.committeeXonlyPubkeys[committeeAddress] = committeeXonlyPubkey;
        } else {
            peginData.committeeXonlyPubkeys[committeeAddress] = committeeXonlyPubkey;
        }

        emit CommitteeResponse(instanceId, committeeAddress, committeeXonlyPubkey);
    }

    function getCommitteePubkeys(bytes16 instanceId) public view returns (bytes32[] memory committeeXonlyPubkeys) {
        require(peginDataMap[instanceId].createdAt + responseWindowBlocks < block.number, "response window not expired");
        committeeXonlyPubkeys = getCommitteePubkeysUnsafe(instanceId);
        // TODO: check whether the number of committee has reached the threshold
        // TODO: key aggregation?
    }

    function getCommitteePubkeysUnsafe(bytes16 instanceId)
        public
        view
        returns (bytes32[] memory committeeXonlyPubkeys)
    {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        committeeXonlyPubkeys = new bytes32[](peginData.committeeAddresses.length);
        for (uint256 i = 0; i < peginData.committeeAddresses.length; ++i) {
            address committeeAddress = peginData.committeeAddresses[i];
            committeeXonlyPubkeys[i] = peginData.committeeXonlyPubkeys[committeeAddress];
        }
    }

    // TODO: post canceled pegin request?

    function postPeginData(
        bytes16 instanceId,
        BitvmTxParser.BitcoinTx calldata rawPeginTx,
        MerkleProof.BitcoinTxProof calldata peginProof,
        bytes[] calldata committeeSigs
    ) external onlyCommittee {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        require(peginData.status == PeginStatus.Pending, "not a pending pegin request");
        (bytes32 peginTxid, uint64 peginAmountSats, address depositorAddress, bytes16 parsedInstanceId) =
            BitvmTxParser.parsePegin(rawPeginTx);
        require(parsedInstanceId == instanceId, "instanceId mismatch");
        require(peginAmountSats == peginData.peginAmountSats, "pegin amount mismatch");

        // validate pegin tx
        (bytes32 blockHash, bytes32 merkleRoot) = MerkleProof.parseBtcBlockHeader(peginProof.rawHeader);
        require(bitcoinSPV.blockHash(peginProof.height) == blockHash, "invalid header");
        require(
            MerkleProof.verifyMerkleProof(merkleRoot, peginProof.proof, peginTxid, peginProof.index), "unable to verify"
        );
        // TODO: check commiitteeSigs
        // TODO: check whether the number of committee has reached the threshold

        // update storage
        peginData.status = PeginStatus.Withdrawbale;
        peginData.peginTxid = peginTxid;

        // mint pegBTC to user
        // deduct a fee from the User to cover the Operator's peg-out reward
        uint64 feeAmountSats = minPeginFeeSats + peginAmountSats * peginFeeRate / rateMultiplier;
        require(feeAmountSats < peginAmountSats, "pegin amount cannot cover fee");
        pegBTC.mint(depositorAddress, Converter.amountFromSats(peginAmountSats - feeAmountSats));
        pegBTC.mint(address(this), Converter.amountFromSats(feeAmountSats));

        emit BridgeIn(depositorAddress, instanceId, peginAmountSats, feeAmountSats);
    }

    function postGraphData(
        bytes16 instanceId,
        bytes16 graphId,
        GraphData calldata graphData,
        bytes[] calldata committeeSigs
    ) public onlyCommittee {
        require(graphDataMap[graphId].peginTxid == 0, "graph data already posted");
        PeginDataInner storage peginData = peginDataMap[instanceId];
        require(graphData.peginTxid == peginData.peginTxid, "graph data pegin txid mismatch");
        require(isValidStakeAmount(peginData.peginAmountSats, graphData.stakeAmountSats), "insufficient stake amount");
        // TODO: validate committeeSigs

        graphDataMap[graphId] = graphData;
        instanceIdToGraphIds[instanceId].push(graphId);
    }

    function initWithdraw(bytes16 instanceId, bytes16 graphId) external {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        require(
            withdrawData.status == WithdrawStatus.None || withdrawData.status == WithdrawStatus.Canceled,
            "invalid withdraw status"
        );
        PeginDataInner storage peginData = peginDataMap[instanceId];
        require(peginData.status == PeginStatus.Withdrawbale, "not a withdrawable pegin tx");

        // lock the pegin utxo so others can not withdraw it
        peginData.status = PeginStatus.Locked;

        // lock operator's pegBTC
        uint256 lockAmount = Converter.amountFromSats(peginData.peginAmountSats);
        pegBTC.transferFrom(msg.sender, address(this), lockAmount);

        withdrawData.peginTxid = peginData.peginTxid;
        withdrawData.operatorAddress = msg.sender;
        withdrawData.status = WithdrawStatus.Initialized;
        withdrawData.instanceId = instanceId;
        withdrawData.lockAmount = lockAmount;
        withdrawData.btcBlockHeightAtWithdraw = bitcoinSPV.latestConfirmedHeight();

        emit InitWithdraw(instanceId, graphId, withdrawData.operatorAddress, peginData.peginAmountSats);
    }

    function cancelWithdraw(bytes16 graphId) external onlyCommitteeOrOperator(graphId) {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        PeginDataInner storage peginData = peginDataMap[withdrawData.instanceId];
        require(withdrawData.status == WithdrawStatus.Initialized, "invalid withdraw index: not at init stage");
        withdrawData.status = WithdrawStatus.Canceled;
        pegBTC.transfer(msg.sender, withdrawData.lockAmount);
        peginData.status = PeginStatus.Withdrawbale;

        emit CancelWithdraw(withdrawData.instanceId, graphId, msg.sender);
    }

    // post kickoff tx
    function proceedWithdraw(
        bytes16 graphId,
        BitvmTxParser.BitcoinTx calldata rawKickoffTx,
        MerkleProof.BitcoinTxProof calldata kickoffProof
    ) external onlyCommittee {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        bytes16 instanceId = withdrawData.instanceId;
        require(withdrawData.status == WithdrawStatus.Initialized, "invalid withdraw index: not at init stage");
        require(
            withdrawData.btcBlockHeightAtWithdraw < kickoffProof.height,
            "kickoff height must be greater than init-withdraw height"
        );

        GraphData storage graphData = graphDataMap[graphId];
        bytes32 kickoffTxid = BitvmTxParser.parseKickoffTx(rawKickoffTx);
        require(kickoffTxid == graphData.kickoffTxid, "kickoff txid mismatch");
        (bytes32 blockHash, bytes32 merkleRoot) = MerkleProof.parseBtcBlockHeader(kickoffProof.rawHeader);
        require(bitcoinSPV.blockHash(kickoffProof.height) == blockHash, "invalid header");
        require(
            MerkleProof.verifyMerkleProof(merkleRoot, kickoffProof.proof, kickoffTxid, kickoffProof.index),
            "unable to verify"
        );

        // once kickoff is braodcasted , operator will not be able to cancel withdrawal
        withdrawData.status = WithdrawStatus.Processing;

        // burn pegBTC
        pegBTC.burn(withdrawData.lockAmount);

        emit ProceedWithdraw(instanceId, graphId, kickoffTxid);
    }

    function finishWithdrawHappyPath(
        bytes16 graphId,
        BitvmTxParser.BitcoinTx calldata rawTake1Tx,
        MerkleProof.BitcoinTxProof calldata take1Proof
    ) external onlyCommittee {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        bytes16 instanceId = withdrawData.instanceId;
        PeginDataInner storage peginData = peginDataMap[instanceId];
        require(withdrawData.status == WithdrawStatus.Processing, "invalid withdraw index: not at processing stage");

        GraphData storage graphData = graphDataMap[graphId];
        bytes32 take1Txid = BitvmTxParser.parseTake1Tx(rawTake1Tx);
        require(BitvmTxParser.parseTake1Tx(rawTake1Tx) == graphData.take1Txid, "take1 txid mismatch");
        (bytes32 blockHash, bytes32 merkleRoot) = MerkleProof.parseBtcBlockHeader(take1Proof.rawHeader);
        require(bitcoinSPV.blockHash(take1Proof.height) == blockHash, "invalid header");
        require(
            MerkleProof.verifyMerkleProof(merkleRoot, take1Proof.proof, take1Txid, take1Proof.index), "unable to verify"
        );

        peginData.status = PeginStatus.Claimed;
        withdrawData.status = WithdrawStatus.Complete;

        // incentive mechanism for honest Operators
        uint64 rewardAmountSats =
            minOperatorRewardSats + peginData.peginAmountSats * operatorRewardRate / rateMultiplier;
        pegBTC.transfer(withdrawData.operatorAddress, Converter.amountFromSats(rewardAmountSats));

        emit WithdrawHappyPath(instanceId, graphId, take1Txid, withdrawData.operatorAddress, rewardAmountSats);
    }

    function finishWithdrawUnhappyPath(
        bytes16 graphId,
        BitvmTxParser.BitcoinTx calldata rawTake2Tx,
        MerkleProof.BitcoinTxProof calldata take2Proof
    ) external onlyCommittee {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        bytes16 instanceId = withdrawData.instanceId;
        PeginDataInner storage peginData = peginDataMap[instanceId];
        require(withdrawData.status == WithdrawStatus.Processing, "invalid withdraw index: not at processing stage");

        GraphData storage graphData = graphDataMap[graphId];
        bytes32 take2Txid = BitvmTxParser.parseTake2Tx(rawTake2Tx);
        require(take2Txid == graphData.take2Txid, "take2 txid mismatch");
        (bytes32 blockHash, bytes32 merkleRoot) = MerkleProof.parseBtcBlockHeader(take2Proof.rawHeader);
        require(bitcoinSPV.blockHash(take2Proof.height) == blockHash, "invalid header");
        require(
            MerkleProof.verifyMerkleProof(merkleRoot, take2Proof.proof, take2Txid, take2Proof.index), "unable to verify"
        );

        peginData.status = PeginStatus.Claimed;
        withdrawData.status = WithdrawStatus.Complete;

        // incentive mechanism for honest Operators
        uint64 rewardAmountSats =
            minOperatorRewardSats + peginData.peginAmountSats * operatorRewardRate / rateMultiplier;
        pegBTC.transfer(withdrawData.operatorAddress, Converter.amountFromSats(rewardAmountSats));

        emit WithdrawUnhappyPath(instanceId, graphId, take2Txid, withdrawData.operatorAddress, rewardAmountSats);
    }

    function finishWithdrawDisproved(
        bytes16 graphId,
        DisproveTxType disproveTxType,
        uint256 nackIndex,
        BitvmTxParser.BitcoinTx calldata rawChallengeStartTx,
        MerkleProof.BitcoinTxProof calldata challengeStartTxProof,
        BitvmTxParser.BitcoinTx calldata rawChallengeFinishTx,
        MerkleProof.BitcoinTxProof calldata challengeFinishTxProof
    ) external onlyCommittee {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        GraphData storage graphData = graphDataMap[graphId];
        bytes16 instanceId = withdrawData.instanceId;
        // Malicious operator may skip initWithdraw & procceedWithdraw
        require(withdrawData.status != WithdrawStatus.Disproved, "already disproved");

        // verify ChallengeStart tx
        (bytes32 challengeStartTxid, bytes32 kickoffTxid, address challengerAddress) =
            BitvmTxParser.parseChallengeTx(rawChallengeStartTx);
        require(kickoffTxid == graphData.kickoffTxid, "ChallengeStartTx: kickoff txid mismatch");
        (bytes32 blockHash, bytes32 merkleRoot) = MerkleProof.parseBtcBlockHeader(challengeStartTxProof.rawHeader);
        require(
            bitcoinSPV.blockHash(challengeStartTxProof.height) == blockHash, "invalid header in challengeStartTxProof"
        );
        require(
            MerkleProof.verifyMerkleProof(
                merkleRoot, challengeStartTxProof.proof, challengeStartTxid, challengeStartTxProof.index
            ),
            "unable to verify challengeStartTx merkle proof"
        );

        // verify ChallengeFinish tx
        bytes32 challengeFinishTxid;
        address disproverAddress;
        if (disproveTxType == DisproveTxType.AssertTimeout) {
            (challengeFinishTxid, disproverAddress) = BitvmTxParser.parseAssertTimeoutTx(rawChallengeFinishTx);
            require(
                challengeFinishTxid == graphData.assertTimoutTxid, "ChallengeFinishTx: assert timeout txid mismatch"
            );
        } else if (disproveTxType == DisproveTxType.OperatorCommitTimeout) {
            (challengeFinishTxid, disproverAddress) = BitvmTxParser.parseCommitTimeoutTx(rawChallengeFinishTx);
            require(
                challengeFinishTxid == graphData.commitTimoutTxid, "ChallengeFinishTx: commit timeout txid mismatch"
            );
        } else if (disproveTxType == DisproveTxType.OperatorNack) {
            (challengeFinishTxid, disproverAddress) = BitvmTxParser.parseNackTx(rawChallengeFinishTx);
            require(graphData.NackTxids.length > nackIndex, "Nack tx index out of range");
            require(challengeFinishTxid == graphData.NackTxids[nackIndex], "ChallengeFinishTx: nack txid mismatch");
        } else if (disproveTxType == DisproveTxType.Disprove) {
            (challengeFinishTxid, kickoffTxid, disproverAddress) = BitvmTxParser.parseDisproveTx(rawChallengeFinishTx);
            require(kickoffTxid == graphData.kickoffTxid, "ChallengeFinishTx: kickoffTxid txid mismatch");
        }
        (blockHash, merkleRoot) = MerkleProof.parseBtcBlockHeader(challengeFinishTxProof.rawHeader);
        require(bitcoinSPV.blockHash(challengeFinishTxProof.height) == blockHash, "invalid header in disproveProof");
        require(
            MerkleProof.verifyMerkleProof(
                merkleRoot, challengeFinishTxProof.proof, challengeFinishTxid, challengeFinishTxProof.index
            ),
            "unable to verify disprove merkle proof"
        );
        withdrawData.status = WithdrawStatus.Disproved;

        // reward Challenger and Disprover
        // Committee temporarily holds the Operator's forfeiture, which will be distributed to both Challenger and Disprover as a reward
        uint64 peginAmountSats = peginDataMap[instanceId].peginAmountSats;
        uint64 challengerRewardAmountSats =
            minChallengerRewardSats + peginAmountSats * challengerRewardRate / rateMultiplier;
        uint64 disproverRewardAmountSats =
            minDisproverRewardSats + peginAmountSats * disproverRewardRate / rateMultiplier;
        if (challengerAddress != address(0)) {
            pegBTC.transfer(challengerAddress, Converter.amountFromSats(challengerRewardAmountSats));
        }
        if (disproverAddress != address(0)) {
            pegBTC.transfer(disproverAddress, Converter.amountFromSats(disproverRewardAmountSats));
        }

        emit WithdrawDisproved(
            instanceId,
            graphId,
            disproveTxType,
            nackIndex,
            challengeStartTxid,
            challengeFinishTxid,
            challengerAddress,
            disproverAddress,
            challengerRewardAmountSats,
            disproverRewardAmountSats
        );
    }
}
