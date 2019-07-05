pragma solidity ^0.5.10;

/// @notice this throws on its default (and only) payable function
contract ThrowOnPayable {
    //uint256 balance;

    function() external payable {

        // these three ways will all cause a revert

        // 1. just revert
        revert("revert");
        
        // 2.a. infinite loop
        /* `i` will have max a max value of 255 (initialized as uint8),
        * causing an infinite loop.
        */
        // for (var i = 0; i < 1000; i++) {
        //     balance++;
        // }

        // 2.b. infinite loop
        // while(true) {
        //     balance++;
        // }
    }
}