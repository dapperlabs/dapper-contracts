pragma solidity ^0.5.10;

//import "openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "../Ownership/Ownable.sol";


/// @notice this wallet does not throw on receipt of ETH
contract SimpleWallet is Ownable {

  /// @dev emit this event when someone sends you ETH
    /// @param from the address which sent you ether
    /// @param value the amount of ether sent
    event Deposited(address indexed from, uint value);

    /// @notice Gets called when a transaction is received without calling a method
    function() external payable {
        // length cannot be > 0 as we won't have enough gas
        require(msg.data.length == 0);
        // k + unindexedBytes * a + indexedTopics * b
        // k = 375, a = 8, b = 375
        // because we only index the first one, we should be under 2300 gas stipend
        // 375 + (32)*8 + (1)*375 = 1006
        // so we can afford this check
        if (msg.value > 0) {
            // Fire deposited event if we are receiving funds
            emit Deposited(msg.sender, msg.value);
        }
    }

    function transferOut(address payable target) external payable onlyOwner {
        target.transfer(msg.value);
    }

    function sendOut(address payable target) external payable onlyOwner {
        if (!target.send(msg.value)) {
            revert("send failed");
        }
    }
}