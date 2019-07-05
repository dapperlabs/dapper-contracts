pragma solidity ^0.5.10;

import "./CoreWallet.sol";


/// @title Cloneable Wallet
/// @notice This contract represents a complete but non working wallet.  
///  It is meant to be deployed and serve as the contract that you clone
///  in an EIP 1167 clone setup.
/// @dev See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1167.md
/// @dev Currently, we are seeing approximatley 933 gas overhead for using
///  the clone wallet; use `FullWallet` if you think users will overtake
///  the transaction threshold over the lifetime of the wallet.
contract CloneableWallet is CoreWallet {

    /// @dev An empty constructor that deploys a NON-FUNCTIONAL version
    ///  of `CoreWallet`
    constructor () public {
        initialized = true;
    }
}