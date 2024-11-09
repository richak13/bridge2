// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./BridgeToken.sol";

contract Destination is AccessControl {
    bytes32 public constant WARDEN_ROLE = keccak256("WARDEN_ROLE");
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");

    // Mappings for underlying to wrapped tokens and vice versa
    mapping(address => address) public underlying_tokens; // Maps underlying asset to BridgeToken
    mapping(address => address) public wrapped_tokens; // Maps BridgeToken to underlying asset
    address[] public tokens; // List of all wrapped token addresses

    // Events for tracking token creation, wrapping, and unwrapping
    event Creation(address indexed underlying_token, address indexed wrapped_token);
    event Wrap(address indexed underlying_token, address indexed wrapped_token, address indexed to, uint256 amount);
    event Unwrap(address indexed underlying_token, address indexed wrapped_token, address frm, address indexed to, uint256 amount);

    constructor(address admin) {
        // Grant roles to the contract administrator
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(CREATOR_ROLE, admin);
        _setupRole(WARDEN_ROLE, admin);
    }

    function createToken(
        address _underlying_token,
        string memory name,
        string memory symbol
    ) public onlyRole(CREATOR_ROLE) returns (address) {
        require(_underlying_token != address(0), "Invalid underlying token address");
        require(underlying_tokens[_underlying_token] == address(0), "Token already created");

        // Deploy a new instance of BridgeToken for the underlying asset with this contract as admin
        BridgeToken bridgeToken = new BridgeToken(_underlying_token, name, symbol, address(this));
        address bridgeTokenAddress = address(bridgeToken);

        // Register the token by updating mappings and the token list
        underlying_tokens[_underlying_token] = bridgeTokenAddress;
        wrapped_tokens[bridgeTokenAddress] = _underlying_token;
        tokens.push(bridgeTokenAddress);

        // Grant the Destination contract MINTER_ROLE on the new BridgeToken
        bridgeToken.grantRole(bridgeToken.MINTER_ROLE(), address(this));

        // Emit the Creation event with accurate parameters
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

        // Mint the correct amount of wrapped tokens for the recipient
        BridgeToken(bridgeTokenAddress).mint(_recipient, _amount);

        // Emit the Wrap event after minting
        emit Wrap(_underlying_token, bridgeTokenAddress, _recipient, _amount);
    }

    function unwrap(
        address _wrapped_token,
        address _recipient,
        uint256 _amount
    ) public {
        address underlyingToken = wrapped_tokens[_wrapped_token];
        require(underlyingToken != address(0), "Token not registered");

        // Ensure that the caller has a sufficient balance to unwrap
        require(BridgeToken(_wrapped_token).balanceOf(msg.sender) >= _amount, "Insufficient balance to unwrap");

        // Burn tokens from the sender's balance
        BridgeToken(_wrapped_token).burnFrom(msg.sender, _amount);

        // Emit the Unwrap event
        emit Unwrap(underlyingToken, _wrapped_token, msg.sender, _recipient, _amount);
    }
}
