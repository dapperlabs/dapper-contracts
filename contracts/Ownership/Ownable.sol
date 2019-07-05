pragma solidity ^0.5.10;


/// @title Ownable is for contracts that can be owned.
/// @dev The Ownable contract keeps track of an owner address,
///  and provides basic authorization functions.
contract Ownable {

    /// @dev the owner of the contract
    address public owner;

    /// @dev Fired when the owner to renounce ownership, leaving no one
    ///  as the owner.
    /// @param previousOwner The previous `owner` of this contract
    event OwnershipRenounced(address indexed previousOwner);
    
    /// @dev Fired when the owner to changes ownership
    /// @param previousOwner The previous `owner`
    /// @param newOwner The new `owner`
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @dev sets the `owner` to `msg.sender`
    constructor() public {
        owner = msg.sender;
    }

    /// @dev Throws if the `msg.sender` is not the current `owner`
    modifier onlyOwner() {
        require(msg.sender == owner, "must be owner");
        _;
    }

    /// @dev Allows the current `owner` to renounce ownership
    function renounceOwnership() external onlyOwner {
        emit OwnershipRenounced(owner);
        owner = address(0);
    }

    /// @dev Allows the current `owner` to transfer ownership
    /// @param _newOwner The new `owner`
    function transferOwnership(address _newOwner) external onlyOwner {
        _transferOwnership(_newOwner);
    }

    /// @dev Internal version of `transferOwnership`
    /// @param _newOwner The new `owner`
    function _transferOwnership(address _newOwner) internal {
        require(_newOwner != address(0), "cannot renounce ownership");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
}