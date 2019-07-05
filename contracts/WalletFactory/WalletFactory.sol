pragma solidity ^0.5.10;

import "../Wallet/CloneableWallet.sol";
import "../Ownership/HasNoEther.sol";
import "./CloneFactory.sol";
import "./FullWalletByteCode.sol";


/// @title WalletFactory
/// @dev A contract for creating wallets. 
contract WalletFactory is FullWalletByteCode, HasNoEther, CloneFactory {

    /// @dev Pointer to a pre-deployed instance of the Wallet contract. This
    ///  deployment contains all the Wallet code.
    address public cloneWalletAddress;

    /// @notice Emitted whenever a wallet is created
    /// @param wallet The address of the wallet created
    /// @param authorizedAddress The initial authorized address of the wallet
    /// @param full `true` if the deployed wallet was a full, self
    ///  contained wallet; `false` if the wallet is a clone wallet
    event WalletCreated(address wallet, address authorizedAddress, bool full);

    constructor(address _cloneWalletAddress) public {
        cloneWalletAddress = _cloneWalletAddress;
    }

    /// @notice Used to deploy a wallet clone
    /// @dev Reasonably cheap to run (~100K gas)
    /// @param _recoveryAddress the initial recovery address for the wallet
    /// @param _authorizedAddress an initial authorized address for the wallet
    /// @param _cosigner the cosigning address for the initial `_authorizedAddress`
    function deployCloneWallet(
        address _recoveryAddress,
        address _authorizedAddress,
        uint256 _cosigner
    )
        public 
    {
        // create the clone
        address payable clone = createClone(cloneWalletAddress);
        // init the clone
        CloneableWallet(clone).init(_authorizedAddress, _cosigner, _recoveryAddress);
        // emit event
        emit WalletCreated(clone, _authorizedAddress, false);
    }

    /// @notice Used to deploy a wallet clone
    /// @dev Reasonably cheap to run (~100K gas)
    /// @dev The clone does not require `onlyOwner` as we avoid front-running
    ///  attacks by hashing the salt combined with the call arguments and using
    ///  that as the salt we provide to `create2`. Given this constraint, a 
    ///  front-runner would need to use the same `_recoveryAddress`, `_authorizedAddress`,
    ///  and `_cosigner` parameters as the original deployer, so the original deployer
    ///  would have control of the wallet even if the transaction was front-run.
    /// @param _recoveryAddress the initial recovery address for the wallet
    /// @param _authorizedAddress an initial authorized address for the wallet
    /// @param _cosigner the cosigning address for the initial `_authorizedAddress`
    /// @param _salt the salt for the `create2` instruction
    function deployCloneWallet2(
        address _recoveryAddress,
        address _authorizedAddress,
        uint256 _cosigner,
        bytes32 _salt
    )
        public
    {
        // calculate our own salt based off of args
        bytes32 salt = keccak256(abi.encodePacked(_salt, _authorizedAddress, _cosigner, _recoveryAddress));
        // create the clone counterfactually
        address payable clone = createClone2(cloneWalletAddress, salt);
        // ensure we get an address
        require(clone != address(0), "wallet must have address");

        // check size
        uint256 size;
        // note this takes an additional 700 gas
        assembly {
            size := extcodesize(clone)
        }

        require(size > 0, "wallet must have code");

        // init the clone
        CloneableWallet(clone).init(_authorizedAddress, _cosigner, _recoveryAddress);
        // emit event
        emit WalletCreated(clone, _authorizedAddress, false);   
    }

    /// @notice Used to deploy a full wallet
    /// @dev This is potentially very gas intensive!
    /// @param _recoveryAddress The initial recovery address for the wallet
    /// @param _authorizedAddress An initial authorized address for the wallet
    /// @param _cosigner The cosigning address for the initial `_authorizedAddress`
    function deployFullWallet(
        address _recoveryAddress,
        address _authorizedAddress,
        uint256 _cosigner
    )
        public 
    {
        // Copy the bytecode of the full wallet to memory.
        bytes memory fullWallet = fullWalletBytecode;

        address full;
        assembly {
            // get start of wallet buffer
            let startPtr := add(fullWallet, 0x20)
            // get start of arguments
            let endPtr := sub(add(startPtr, mload(fullWallet)), 0x60)
            // copy constructor parameters to memory
            mstore(endPtr, _authorizedAddress)
            mstore(add(endPtr, 0x20), _cosigner)
            mstore(add(endPtr, 0x40), _recoveryAddress)
            // create the contract
            full := create(0, startPtr, mload(fullWallet))
        }
        
        // check address
        require(full != address(0), "wallet must have address");

        // check size
        uint256 size;
        // note this takes an additional 700 gas, 
        // which is a relatively small amount in this case
        assembly {
            size := extcodesize(full)
        }

        require(size > 0, "wallet must have code");

        emit WalletCreated(full, _authorizedAddress, true);
    }

    /// @notice Used to deploy a full wallet counterfactually
    /// @dev This is potentially very gas intensive!
    /// @dev As the arguments are appended to the end of the bytecode and
    ///  then included in the `create2` call, we are safe from front running
    ///  attacks and do not need to restrict the caller of this function.
    /// @param _recoveryAddress The initial recovery address for the wallet
    /// @param _authorizedAddress An initial authorized address for the wallet
    /// @param _cosigner The cosigning address for the initial `_authorizedAddress`
    /// @param _salt The salt for the `create2` instruction
    function deployFullWallet2(
        address _recoveryAddress,
        address _authorizedAddress,
        uint256 _cosigner,
        bytes32 _salt
    )
        public
    {
        // Note: Be sure to update this whenever the wallet bytecode changes!
        // Simply run `yarn run build` and then copy the `"bytecode"`
        // portion from the `build/contracts/FullWallet.json` file to here,
        // then append 64x3 0's.
        //
        // Note: By not passing in the code as an argument, we save 600,000 gas.
        // An alternative would be to use `extcodecopy`, but again we save
        // gas by not having to call `extcodecopy`.
        bytes memory fullWallet = fullWalletBytecode;

        address full;
        assembly {
            // get start of wallet buffer
            let startPtr := add(fullWallet, 0x20)
            // get start of arguments
            let endPtr := sub(add(startPtr, mload(fullWallet)), 0x60)
            // copy constructor parameters to memory
            mstore(endPtr, _authorizedAddress)
            mstore(add(endPtr, 0x20), _cosigner)
            mstore(add(endPtr, 0x40), _recoveryAddress)
            // create the contract using create2
            full := create2(0, startPtr, mload(fullWallet), _salt)
        }
        
        // check address
        require(full != address(0), "wallet must have address");

        // check size
        uint256 size;
        // note this takes an additional 700 gas, 
        // which is a relatively small amount in this case
        assembly {
            size := extcodesize(full)
        }

        require(size > 0, "wallet must have code");

        emit WalletCreated(full, _authorizedAddress, true);
    }
}
