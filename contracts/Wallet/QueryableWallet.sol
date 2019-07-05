pragma solidity ^0.5.10;

import "./CoreWallet.sol";
import "../ERC165/ERC165Query.sol";


/// @title Queryable Wallet
/// @notice This contract represents an ERC165 queryable version of the full wallet
/// @dev NOTE: This contract is for testing purposes only!!
contract QueryableWallet is CoreWallet, ERC165Query {
    
    /// @notice A regular constructor that can be used if you wish to deploy a standalone instance of this
    ///  smart contract wallet. Useful if you anticipate that the lifetime gas savings of being able to call
    ///  this contract directly will outweigh the cost of deploying a complete copy of this contract.
    ///  Comment out this constructor and use the one above if you wish to save gas deployment costs by
    ///  using a clonable instance.
    /// @param _authorized the initial authorized address
    /// @param _cosigner the initial cosiging address for the `_authorized` address
    /// @param _recoveryAddress the initial recovery address for the wallet
    constructor (address _authorized, uint256 _cosigner, address _recoveryAddress) public {
        init(_authorized, _cosigner, _recoveryAddress);
    }
}