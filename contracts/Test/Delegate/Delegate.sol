pragma solidity ^0.5.10;

import "./SimpleInterface.sol";
import "./CompositeInterface.sol";

/// @title An example Delegate contract for testing delegate functionality.
contract Delegate is SimpleInterface, CompositeInterface {
    uint256 storedValue = 0;

    function doSomething() external returns (uint256) {
        return 42;
    }

    function doSomethingElse(uint256 _parameter) external returns (uint256) {
        return _parameter;
    }

    function doSomethingThatReverts() pure external {
        revert();
    }

    function doSomethingThatWritesToStorage() external {
        storedValue = storedValue + 1;
    }
}
