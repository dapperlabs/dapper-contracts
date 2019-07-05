const { bytecode } = require("../build/contracts/FullWallet.json");

const contract = `pragma solidity ^0.5.10;

/// @title FullWalletByteCode
/// @dev A contract containing the FullWallet bytecode, for use in deployment.
contract FullWalletByteCode {
    /// @notice This is the raw bytecode of the full wallet. It is encoded here as a raw byte
    ///  array to support deployment with CREATE2, as Solidity's 'new' constructor system does
    ///  not support CREATE2 yet.
    ///
    ///  NOTE: Be sure to update this whenever the wallet bytecode changes!
    ///  Simply run \`npm run build\` and then copy the \`"bytecode"\`
    ///  portion from the \`build/contracts/FullWallet.json\` file to here,
    ///  then append 64x3 0's.
    bytes constant fullWalletBytecode = hex'${bytecode.slice(2)}${"0".repeat(
  192
)}';
}
`;

// Print the contract source to STDOUT, can pipe this to a file.
console.log(contract);
