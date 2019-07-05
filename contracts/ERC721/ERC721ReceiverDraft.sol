pragma solidity ^0.5.10;


/// @title ERC721ReceiverDraft
/// @dev Interface for any contract that wants to support safeTransfers from
///  ERC721 asset contracts.
/// @dev Note: this is the interface defined from 
///  https://github.com/ethereum/EIPs/commit/2bddd126def7c046e1e62408dc2b51bdd9e57f0f
///  to https://github.com/ethereum/EIPs/commit/27788131d5975daacbab607076f2ee04624f9dbb 
///  and is not the final interface.
///  Due to the extended period of time this revision was specified in the draft,
///  we are supporting both this and the newer (final) interface in order to be 
///  compatible with any ERC721 implementations that may have used this interface.
contract ERC721ReceiverDraft {

    /// @dev Magic value to be returned upon successful reception of an NFT
    ///  Equals to `bytes4(keccak256("onERC721Received(address,uint256,bytes)"))`,
    ///  which can be also obtained as `ERC721ReceiverDraft(0).onERC721Received.selector`
    /// @dev see https://github.com/ethereum/EIPs/commit/2bddd126def7c046e1e62408dc2b51bdd9e57f0f
    bytes4 internal constant ERC721_RECEIVED_DRAFT = 0xf0b9e5ba;

    /// @notice Handle the receipt of an NFT
    /// @dev The ERC721 smart contract calls this function on the recipient
    ///  after a `transfer`. This function MAY throw to revert and reject the
    ///  transfer. This function MUST use 50,000 gas or less. Return of other
    ///  than the magic value MUST result in the transaction being reverted.
    ///  Note: the contract address is always the message sender.
    /// @param _from The sending address 
    /// @param _tokenId The NFT identifier which is being transfered
    /// @param data Additional data with no specified format
    /// @return `bytes4(keccak256("onERC721Received(address,uint256,bytes)"))`
    ///  unless throwing
    function onERC721Received(address _from, uint256 _tokenId, bytes calldata data) external returns(bytes4);
}