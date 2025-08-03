// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReportValidator {
    struct Report {
        bytes32 hash;
        string ipfsCID;
        uint256 timestamp;
    }

    mapping(address => Report[]) public reports;

    event ReportUploaded(address indexed uploader, bytes32 hash, string ipfsCID, uint256 timestamp);

    function uploadReport(bytes32 _hash, string memory _ipfsCID) public {
        reports[msg.sender].push(Report({
            hash: _hash,
            ipfsCID: _ipfsCID,
            timestamp: block.timestamp
        }));
        
        emit ReportUploaded(msg.sender, _hash, _ipfsCID, block.timestamp);
    }

    function getLatestReport(address user) public view returns (bytes32, string memory, uint256) {
        uint256 len = reports[user].length;
        require(len > 0, "No reports found.");
        Report memory latest = reports[user][len - 1];
        return (latest.hash, latest.ipfsCID, latest.timestamp);
    }

    function verifyReport(address user, uint256 index, bytes32 _hash) public view returns (bool) {
        return reports[user][index].hash == _hash;
    }
}
