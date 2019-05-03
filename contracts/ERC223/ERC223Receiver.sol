pragma solidity ^0.5.6;


/// @title ERC223Receiver ensures we are ERC223 compatible
/// @author Christopher Scott
contract ERC223Receiver {

    bytes4 public constant ERC223_ID = 0xc0ee0b8a;

    struct TKN {
        address sender;
        uint value;
        bytes data;
        bytes4 sig;
    }

    /// @notice tokenFallback is called from an ERC223 compatible contract
    /// @param _from the address from which the token was sent
    /// @param _value the amount of tokens sent
    /// @param _data the data sent with the transaction
    function tokenFallback(address _from, uint _value, bytes memory _data) public pure {
        _from;
        _value;
        _data;
    }
}