pragma solidity ^0.5.10;

import "openzeppelin-solidity/contracts/token/ERC721/ERC721Full.sol";

/**
 * @title ERC721TokenMock
 * This mock just provides a public mint and burn functions for testing purposes,
 * and a public setter for metadata URI
 */
contract ERC721TokenMock is ERC721Full {
    constructor(string memory name, string memory symbol) public
        ERC721Full(name, symbol)
    { }

    function mint(address _to, uint256 _tokenId) public {
        super._mint(_to, _tokenId);
    }

    function burn(uint256 _tokenId) public {
        super._burn(ownerOf(_tokenId), _tokenId);
    }

    function setTokenURI(uint256 _tokenId, string memory _uri) public {
        super._setTokenURI(_tokenId, _uri);
    }
}