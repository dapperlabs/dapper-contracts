pragma solidity ^0.5.10;


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
    //   TKN memory tkn;
    //   tkn.sender = _from;
    //   tkn.value = _value;
    //   tkn.data = _data;
    //   uint32 u = uint32(_data[3]) + (uint32(_data[2]) << 8) + (uint32(_data[1]) << 16) + (uint32(_data[0]) << 24);
    //   tkn.sig = bytes4(u);
      
      /* tkn variable is analogue of msg variable of Ether transaction
      *  tkn.sender is person who initiated this token transaction   (analogue of msg.sender)
      *  tkn.value the number of tokens that were sent   (analogue of msg.value)
      *  tkn.data is data of token transaction   (analogue of msg.data)
      *  tkn.sig is 4 bytes signature of function
      *  if data of token transaction is a function execution
      */

    }
}