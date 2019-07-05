pragma solidity ^0.5.10;

import "./Ownable.sol";


/// @title HasNoEther is for contracts that should not own Ether
contract HasNoEther is Ownable {

    /// @dev This contructor rejects incoming Ether
    constructor() public payable {
        require(msg.value == 0, "must not send Ether");
    }

    /// @dev Disallows direct send by default function not being `payable`
    function() external {}

    /// @dev Transfers all Ether held by this contract to the owner.
    function reclaimEther() external onlyOwner {
        msg.sender.transfer(address(this).balance); 
    }
}