// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract medics{
    struct report{
        string patientName;
        string doctorName;
        string diagnosis;
        string treatment;
        uint256 timestamp;
    }
    mapping(address => report[]) private reports;
    address public owner;
    
}