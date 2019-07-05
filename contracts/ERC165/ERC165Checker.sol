pragma solidity ^0.5.10;

import "./ERC165Query.sol";

/// @title ERC165Checker
/// This contract makes sure we say we adhere to the right interfaces
contract ERC165Checker is ERC165Query {

    function checkInterfaces(address wallet, bytes4[] calldata interfaces) external view returns (bool) {
        for (uint i = 0; i < interfaces.length; i++) {
            if (!doesContractImplementInterface(wallet, interfaces[i])) {
                return false;
            }
        }
        return true;
    }
}

