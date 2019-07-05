pragma solidity ^0.5.10;

contract ERC1271 {

    /// @dev bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant ERC1271_VALIDSIGNATURE = 0x1626ba7e;

    /// @dev Should return whether the signature provided is valid for the provided data
    /// @param hash 32-byte hash of the data that is signed
    /// @param _signature Signature byte array associated with _data
    ///  MUST return the bytes4 magic value 0x1626ba7e when function passes.
    ///  MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
    ///  MUST allow external calls
    function isValidSignature(
        bytes32 hash, 
        bytes calldata _signature)
        external
        view 
        returns (bytes4);
}