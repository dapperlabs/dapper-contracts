pragma solidity ^0.5.10;


/// @title ERC165Query example
/// @notice see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-165.md 
contract ERC165Query {
    bytes4 public constant _INTERFACE_ID_INVALID = 0xffffffff;
    bytes4 public constant _INTERFACE_ID_ERC165 = 0x01ffc9a7;

    function doesContractImplementInterface(
        address _contract,
        bytes4 _interfaceId
    ) 
        public
        view
        returns (bool)
    {
        uint256 success;
        uint256 result;

        (success, result) = noThrowCall(_contract, _INTERFACE_ID_ERC165);
        if ((success == 0) || (result == 0)) {
            return false;
        }

        (success, result) = noThrowCall(_contract, _INTERFACE_ID_INVALID);
        if ((success == 0) || (result != 0)) {
            return false;
        }

        (success, result) = noThrowCall(_contract, _interfaceId);
        if ((success == 1) && (result == 1)) {
            return true;
        }
        return false;
    }

    function noThrowCall(
        address _contract,
        bytes4 _interfaceId
    )
        internal
        view
        returns (
            uint256 success,
            uint256 result
        ) 
    {
        bytes memory encodedParams = abi.encodeWithSelector(_INTERFACE_ID_ERC165, _interfaceId);

        // solhint-disable-next-line no-inline-assembly
        assembly {
            let encodedParams_data := add(0x20, encodedParams)
            let encodedParams_size := mload(encodedParams)

            let output := mload(0x40)    // Find empty storage location using "free memory pointer"
            mstore(output, 0x0)

            success := staticcall(
                30000,                   // 30k gas
                _contract,               // To addr
                encodedParams_data,
                encodedParams_size,
                output,
                0x20                     // Outputs are 32 bytes long
            )

            result := mload(output)      // Load the result
        }
    }
}