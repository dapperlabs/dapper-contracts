pragma solidity ^0.5.10;

import "./ERC721ReceiverDraft.sol";
import "./ERC721ReceiverFinal.sol";

/// @title ERC721Receivable handles the reception of ERC721 tokens
///  See ERC721 specification
/// @author Christopher Scott
/// @dev These functions are public, and could be called by anyone, even in the case
///  where no NFTs have been transferred. Since it's not a reliable source of
///  truth about ERC721 tokens being transferred, we save the gas and don't
///  bother emitting a (potentially spurious) event as found in 
///  https://github.com/OpenZeppelin/openzeppelin-solidity/blob/5471fc808a17342d738853d7bf3e9e5ef3108074/contracts/mocks/ERC721ReceiverMock.sol
contract ERC721Receivable is ERC721ReceiverDraft, ERC721ReceiverFinal {

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
    function onERC721Received(address _from, uint256 _tokenId, bytes calldata data) external returns(bytes4) {
        _from;
        _tokenId;
        data;

        // emit ERC721Received(_operator, _from, _tokenId, _data, gasleft());

        return ERC721_RECEIVED_DRAFT;
    }

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
        returns(bytes4)
    {
        _operator;
        _from;
        _tokenId;
        _data;

        // emit ERC721Received(_operator, _from, _tokenId, _data, gasleft());

        return ERC721_RECEIVED_FINAL;
    }

}
