pragma solidity ^0.5.10;


/// @title aid development, should not be released into final version
contract Debuggable {
    event LogUint256(string label, uint256 value);
    event LogUint64(string label, uint64 b);
    event LogUint32(string label, uint32 b);
    event LogUint8(string label, uint8 b);
    event LogInt256(string label, int256 value);
    event LogAddress(string label, address addr);
    event LogBytes32(string label, bytes32 b);
    event LogBytes4(string label, bytes4 b);
    event LogBytes1(string label, bytes1 b);
    event LogBytes(string label, bytes b);
    event LogBool(string label, bool b);

    function timeNow() public view returns (uint256) {
        return now;
    }

    function logBytes(string memory s, bytes memory b) internal {
        emit LogBytes(s, b);
    }

    function logUint64(string memory s, uint64 x) internal {
        emit LogUint64(s, x);
    }

    function logBytes1(string memory s, bytes1 x) internal {
        emit LogBytes1(s, x);
    }
    
    function logUint32(string memory s, uint32 x) internal {
        emit LogUint32(s, x);
    }

    function logAddress(string memory s, address x) internal {
        emit LogAddress(s, x);
    }

    function logUint256(string memory s, uint256 x) internal {
        emit LogUint256(s, x);
    }

    function logInt256(string memory s, int256 x) internal {
        emit LogInt256(s, x);
    }

    function logBytes32(string memory s, bytes32 b) internal {
        emit LogBytes32(s, b);
    }

    function logBool(string memory s, bool b) internal {
        emit LogBool(s, b);
    }

    function logUint8(string memory s, uint8 i) internal {
        emit LogUint8(s, i);
    }
}
