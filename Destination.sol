// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./BridgeToken.sol";

contract Destination is AccessControl {
    bytes32 public constant WARDEN_ROLE = keccak256("WARDEN_ROLE");
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");

    mapping(address => address) public underlyingTokens; // Maps underlying asset to BridgeToken
    mapping(address => address) public wrappedTokens; // Maps BridgeToken to underlying asset
    address[] public tokens; // List of all created BridgeToken addresses

    event Creation(address indexed underlyingToken, address indexed wrappedToken);
    event Wrap(address indexed underlyingToken, address indexed wrappedToken, address indexed recipient, uint256 amount);
    event Unwrap(address indexed underlyingToken, address indexed wrappedToken, address sender, address indexed recipient, uint256 amount);

    constructor(address admin) {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(CREATOR_ROLE, admin);
        _setupRole(WARDEN_ROLE, admin);
    }

    function createToken(
        address underlying,
        string memory name,
        string memory symbol
    ) external onlyRole(CREATOR_ROLE) returns (address) {
        require(wrappedTokens[underlying] == address(0), "Token already registered");

        BridgeToken newToken = new BridgeToken(underlying, name, symbol, address(this));
        wrappedTokens[underlying] = address(newToken);
        underlyingTokens[address(newToken)] = underlying;
        tokens.push(address(newToken));

        emit Creation(underlying, address(newToken));
        return address(newToken);
    }

    function wrap(
        address underlying,
        address recipient,
        uint256 amount
    ) external onlyRole(WARDEN_ROLE) {
        address bridgeToken = wrappedTokens[underlying];
        require(bridgeToken != address(0), "Token not registered");

        BridgeToken(bridgeToken).mint(recipient, amount);
        emit Wrap(underlying, bridgeToken, recipient, amount);
    }

    function unwrap(
        address bridgeToken,
        address recipient,
        uint256 amount
    ) external {
        address underlying = underlyingTokens[bridgeToken];
        require(underlying != address(0), "Token not registered");
        require(BridgeToken(bridgeToken).balanceOf(msg.sender) >= amount, "Insufficient balance");

        BridgeToken(bridgeToken).burnFrom(msg.sender, amount);
        emit Unwrap(underlying, bridgeToken, msg.sender, recipient, amount);
    }
}
