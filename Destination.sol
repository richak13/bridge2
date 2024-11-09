// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./BridgeToken.sol";

contract Destination is AccessControl {
    bytes32 public constant WARDEN_ROLE = keccak256("WARDEN_ROLE");
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");

    mapping(address => address) public underlying_tokens; // Maps underlying asset to BridgeToken
    mapping(address => address) public wrapped_tokens; // Maps BridgeToken to underlying asset
    address[] public tokens; // List of all wrapped token addresses

    event Creation(address indexed underlying_token, address indexed wrapped_token);
    event Wrap(address indexed underlying_token, address indexed wrapped_token, address indexed to, uint256 amount);
    event Unwrap(address indexed underlying_token, address indexed wrapped_token, address frm, address indexed to, uint256 amount);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CREATOR_ROLE, admin);
        _grantRole(WARDEN_ROLE, admin);
    }

    function createToken(
        address _underlying_token,
        string memory name,
        string memory symbol
    ) public onlyRole(CREATOR_ROLE) returns (address) {
        require(underlying_tokens[_underlying_token] == address(0), "Token already created");

        // Deploy new BridgeToken
        BridgeToken bridgeToken = new BridgeToken(_underlying_token, name, symbol, address(this));
        address bridgeTokenAddress = address(bridgeToken);

        // Store mapping
        underlying_tokens[_underlying_token] = bridgeTokenAddress;
        wrapped_tokens[bridgeTokenAddress] = _underlying_token;
        tokens.push(bridgeTokenAddress);

        emit Creation(_underlying_token, bridgeTokenAddress);
        return bridgeTokenAddress;
    }

    function wrap(
        address _underlying_token,
        address _recipient,
        uint256 _amount
    ) public onlyRole(WARDEN_ROLE) {
        address bridgeTokenAddress = underlying_tokens[_underlying_token];
        require(bridgeTokenAddress != address(0), "Token not registered");

        // Mint BridgeToken to recipient
        BridgeToken(bridgeTokenAddress).mint(_recipient, _amount);
        emit Wrap(_underlying_token, bridgeTokenAddress, _recipient, _amount);
    }

    function unwrap(
        address _wrapped_token,
        address _recipient,
        uint256 _amount
    ) public {
        require(wrapped_tokens[_wrapped_token] != address(0), "Token not registered");

        // Burn BridgeTokens from sender
        BridgeToken(_wrapped_token).burnFrom(msg.sender, _amount);
        emit Unwrap(wrapped_tokens[_wrapped_token], _wrapped_token, msg.sender, _recipient, _amount);
    }
}
