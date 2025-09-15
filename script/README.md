# Deploy


```
export prv=...
export OWNER=0x8943545177806ED17B9F23F0a21ee5948eCaa776

forge script script/SSPDeploy.s.sol:Deploy \
    --rpc-url https://rpc.testnet3.goat.network --private-key=$prv --broadcast --legacy

forge verify-contract --compiler-version 0.8.28 0x8F0342A7060e76dfc7F6e9dEbfAD9b9eC919952c SequencerSetPublisher --verifier blockscout --verifier-url 'https://explorer.testnet3.goat.network/api/'

```