pragma solidity ^0.5.10;


/// @title ERC721ReceiverFinal
/// @notice Interface for any contract that wants to support safeTransfers from
///  ERC721 asset contracts.
///  @dev Note: this is the final interface as defined at http://erc721.org
contract ERC721ReceiverFinal {

    /// @dev Magic value to be returned upon successful reception of an NFT
    ///  Equals to `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`,
    ///  which can be also obtained as `ERC721ReceiverFinal(0).onERC721Received.selector`
    /// @dev see https://github.com/OpenZeppelin/openzeppelin-solidity/blob/v1.12.0/contracts/token/ERC721/ERC721Receiver.sol
    bytes4 internal constant ERC721_RECEIVED_FINAL = 0x150b7a02;

    /// @notice Handle the receipt of an NFT
    /// @dev The ERC721 smart contract calls this function on the recipient
    /// after a `safetransfer`. This function MAY throw to revert and reject the
    /// transfer. Return of other than the magic value MUST result in the
    /// transaction being reverted.
    /// Note: the contract address is always the message sender.
    /// @param _operator The address which called `safeTransferFrom` function
    /// @param _from The address which previously owned the token
    /// @param _tokenId The NFT identifier which is being transferred
    /// @param _data Additional data with no specified format
    /// @return `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`
    function onERC721Received(
        address _operator,
        address _from,
        uint256 _tokenId,
        bytes memory _data
    )
    public
        returns (bytes4);
}