# Dapper-Contracts

## Overview

This repository implements the [Dapper](https://www.meetdapper.com/?utm_source=github) Ethereum smart contract wallet.  The wallet has recovery and multi-signature capabilities (via [`cosigner address`](#cosigner-address)) as well as allowing for users to have full sovereignty over all features. 

## Audit of Dapper
To view the audit of Dapper's smart contracts please see Sigma Prime's audit [here](https://github.com/sigp/public-audits/blob/master/dapper-wallet/review.pdf) and blog post describing the audit [here](https://blog.sigmaprime.io/dapper-wallet-review.html).

## Dev Setup

#### Requirements

Node 9

#### Run Tests

- `npm install`
- `npm run build`
- due to contract bytecode being dependent upon the path at which it was compiled, copy the bytecode from `FullWallet.json` into `WalletFactory.sol`
- `npm test`

### Definitions

**key** - Unless otherwise noted, a `key` is defined as an Ethereum compatible public/private key pair, used with [Ethereum Accounts](https://github.com/ethereum/wiki/wiki/White-Paper#ethereum-accounts).  When in the context of smart contracts, key refers to an [Ethereum address](http://gavwood.com/paper.pdf).

**transaction** - Unless otherwise noted, a `transaction` is defined as an [Ethereum transaction](https://github.com/ethereum/wiki/wiki/White-Paper#messages-and-transactions).

**value transfer** - the transferring of value by way of ETH, ERC20, ERC721, or any 3rd party contract call.

## Wallet Design and Features

<img src="./Dapper%20Wallet%20-%20Component%20Diagram.svg">

In contrast to the standard [HD wallet](https://en.bitcoin.it/wiki/Deterministic_wallet) implementation, rather than an [externally owned account](http://ethdocs.org/en/latest/contracts-and-transactions/account-types-gas-and-transactions.html), all assets (ETH, ERC20, ERC721, etc.) for the user are associated with the wallet's public address (contract account) for which by construction there exists no private key; hence **value transfer** actions from the wallet to another address require function calls to be performed on the wallet itself.  For *importing* assets, one simply sends them to the user wallet contract address.

### Recovery Key

The `recovery key` is an ephemeral key that exists only in memory on the clients device for a brief moment.  The key is generated and used to sign the `recovery transaction` and then erased from memory.  The wallet contract keeps track of the public address of the `recovery key` that signed the `recovery transaction`.

### Recovery Transaction

The `recovery transaction` is a transaction signed by the `recovery key`.  This transaction authorizes the **RECOVERY** operation.  The **RECOVERY** operation is defined as the one time atomic removal of all existing `device keys` and the assignment of the `backup key` as the sole `device key`.

It should be noted that the `recovery transaction` in and of itself is of no use to anyone without the corresponding `backup key`.

### Backup Key

The `backup key` is a key that is used in conjunction with the `recovery transaction` in order to perform a **RECOVERY**.

It should be noted that the `backup key` in and of itself is of no use to anyone without the corresponding `recovery transaction`.

In the Dapper client interface, the `backup key` is stored in the users "Recovery Kit" in [mini private key format](https://en.bitcoin.it/wiki/Mini_private_key_format).

### Device Keys

Administration and use of the wallet is controlled by what we refer to as `device keys`.  More than one `device key` can exist.  A `device key` needn't be the "creator" or "owner" of the wallet contract.

It is of note that a `device key` can also be a smart contract, which provides a way to provide additional functionality; for example: a dead man switch or enforcement of a daily ETH limit.

*It is recommended that the number of device keys is kept to a minimum to increase security and reduce attack surface*

*As these keys allow unrestrained value transfer from the wallet, it is highly recommended that `device keys` have a `cosigner` set to improve security and reduce risk and a multiple single points of failure scenario*

#### Device Key Capabilities

- Perform **value transfer** transactions
- Add another `device key`
- Remove another `device key`
- Adjust the `cosigner` on a `device key`
- Rotate the `backup key` and `recovery transaction`

#### Device Key Inabilities

- Perform a RECOVERY operation; this is restricted to the `recovery key` only.

#### Device Key Properties

An `device key`'s only property is an optional [`cosigner address`](#cosigner-address)

### Cosigner Address

Any `device key` can sign the outer transaction that allows you to perform value transactions, etc.  However, a `cosigner` address can be set per `device key` such that a second signature must be provided in addition to the one provided by the `device key`.

This design allows for on-chain (smart contract) or off-chain checks (ie. fraud detection) to be performed by a cosigning service.

The cosigning key can also be replaced or removed, allowing for full flexibility and fine grained control of permissions and authorization.

### Multi-Signature Implementation

The wallet achieves multi-signature capabilities by way of the `invoke()` method and its variants.  Performing all value transfers, administration of `device keys` and rotating the `backup key` and `recovery transaction` are required to be called through the `invoke()` method, thus allowing for a cosigning check on all aforementioned operations.  The `invoke()` methods variants are capable of receiving up to two signatures, in addition to the "free" signature provided by `msg.sender`.

### Recovery Operation

A RECOVERY operation is performed by submitting the `recovery transaction` to the blockchain network.  The effects of this transaction are as follows:

- Remove all existing device keys (scorched earth policy)
- Add the backup key as the only device key

This operation is intended to be executed in the scenario where all the users device keys are LOST, STOLEN or COMPROMISED.  The operation essentially “activates” the `backup key`, and as such the `backup key` is no longer considered a `backup key` but rather a full `device key`.

The user can then rotate the `backup key` and `recovery transaction` via their new `device key`.

For questions, inquiries or more please email support@meetdapper.com
