// SPDX-License-Identifier: MIT

pragma solidity ^0.8.15;

import "./space-factory/ISpaceFactoryErrors.sol";
import "./space-factory/ISpaceFactoryEvents.sol";

import "../types.sol";

interface ISpaceFactory is ISpaceFactoryErrors, ISpaceFactoryEvents {
    function createSpace(
        address owner,
        uint32 votingDelay,
        uint32 minVotingDuration,
        uint32 maxVotingDuration,
        uint256 proposalThreshold,
        uint256 quorum,
        string calldata metadataUri,
        Strategy[] calldata votingStrategies,
        address[] calldata authenticators,
        address[] calldata executionStrategiesAddresses,
        bytes32 salt
    ) external;
}