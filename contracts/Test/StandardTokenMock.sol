pragma solidity ^0.5.6;

import "openzeppelin-solidity/contracts/token/ERC20/ERC20.sol";

// mock class using StandardToken
contract StandardTokenMock is ERC20 {

    constructor(address initialAccount, uint256 initialBalance) public {
        _mint(initialAccount, initialBalance);
    }
}