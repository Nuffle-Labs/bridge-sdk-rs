# Bridge CLI

![Status](https://img.shields.io/badge/Status-Beta-blue)
![Stability](https://img.shields.io/badge/Stability-Pre--Release-yellow)

A command-line interface for interacting with the Omni Bridge protocol, enabling seamless cross-chain token transfers and management.

> [!IMPORTANT]  
> This CLI is in beta and approaching production readiness. While core functionality is stable, some features may still change. We recommend thorough testing before using in production environments.

## Features

- 🌉 Cross-chain token transfers and management
- 🌐 Network support for both Mainnet and Testnet
- ⚡ Fast and efficient command-line operations
- 🔧 Flexible configuration via CLI, environment variables, or config files

## Installation

```bash
# Clone the repository
git clone https://github.com/near/bridge-sdk-rs.git
cd bridge-sdk-rs

# Build the CLI
cargo build --release

# The binary will be available at
./target/release/bridge-cli
```

## Quick Start

Here are some practical examples to help you get started with common bridge operations.

### Example 1: Deploy an ERC20 Token to NEAR

This example shows how to deploy an existing ERC20 token from Ethereum to NEAR:

```bash
TBD
TBD
TBD
```

### Example 2: Transfer USDC from Ethereum to NEAR

This example demonstrates a complete flow of transferring USDC from Ethereum to NEAR:

```bash
# 1. Initialize the transfer on Ethereum
bridge-cli omni-connector evm-init-transfer \
    --chain eth \
    --token 0x123...789 \
    --amount 1000000 \
    --recipient alice.near \
    --fee 100 \
    --native-fee 10000 \
    --network testnet

# 2. Wait for the transaction to be confirmed, then finalize on NEAR
bridge-cli omni-connector near-fin-transfer-with-evm-proof \
    --chain eth \
    --tx-hash 0xabc...def \
    --storage-deposit-actions usdc.near:alice.near:0.1 \
    --network testnet
```

### Example 3: Transfer NEAR Tokens to Solana

This example shows how to transfer tokens from NEAR to Solana:

```bash
# 1. Initialize the transfer on NEAR
bridge-cli omni-connector near-init-transfer \
    --token wrap.near \
    --amount 5000000000000000000 \
    --recipient FGnBM4ZmNKk6kZwNYwwhbqGqvVEZx7KcGhsX4J3PY7Qy \
    --network testnet

# 2. Sign the transfer on NEAR
bridge-cli omni-connector near-sign-transfer \
    --origin-chain-id 1 \
    --origin-nonce 42 \
    --fee 100000000000000000 \
    --native-fee 10000000000000000 \
    --network testnet

# 3. Finalize the transfer on Solana
bridge-cli omni-connector solana-finalize-transfer \
    --tx-hash 8xPxz... \
    --sender-id alice.near \
    --solana-token So11111111111111111111111111111111111111112 \
    --network testnet
```

> [!NOTE]
> - Replace placeholder values (addresses, amounts, hashes) with actual values
> - Token amounts are specified in their smallest units (e.g., wei for ETH, yoctoNEAR for NEAR)
> - Always test with small amounts on testnet first
> - Ensure you have sufficient funds for gas fees and storage deposits

## Usage

The Bridge CLI supports various commands organized by connector type. Here's an overview of the main commands:

### Global Options

- `--network`: Specify the network (mainnet/testnet)

### Omni Connector Commands

The Omni Connector provides comprehensive cross-chain functionality for token transfers and management:

#### Token Management
```bash
# View token metadata
bridge-cli omni-connector log-metadata --token <TOKEN_ADDRESS>

# Deploy a token from another chain
bridge-cli omni-connector deploy-token \
    --chain <DESTINATION_CHAIN> \
    --source-chain <SOURCE_CHAIN> \
    --tx-hash <TX_HASH>

# Bind a token (for Wormhole-supported chains)
bridge-cli omni-connector bind-token --chain <CHAIN>
```

#### NEAR Operations
```bash
# Deposit storage for a token on NEAR
bridge-cli omni-connector near-storage-deposit \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT>

# Initialize a transfer from NEAR
bridge-cli omni-connector near-init-transfer \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT> \
    --recipient <RECIPIENT_ADDRESS>

# Sign a transfer on NEAR
bridge-cli omni-connector near-sign-transfer \
    --origin-chain-id <CHAIN_ID> \
    --origin-nonce <NONCE> \
    [--fee-recipient <ACCOUNT_ID>] \
    --fee <FEE_AMOUNT> \
    --native-fee <NATIVE_FEE_AMOUNT>

# Finalize a transfer on NEAR (using EVM proof)
bridge-cli omni-connector near-fin-transfer-with-evm-proof \
    --chain <SOURCE_CHAIN> \
    --tx-hash <TX_HASH> \
    --storage-deposit-actions <TOKEN1:ACCOUNT1:AMOUNT1,...>

# Finalize a transfer on NEAR (using VAA)
bridge-cli omni-connector near-fin-transfer-with-vaa \
    --chain <SOURCE_CHAIN> \
    --storage-deposit-actions <TOKEN1:ACCOUNT1:AMOUNT1,...> \
    --vaa <VAA_DATA>
```

#### EVM Chain Operations
```bash
# Initialize a transfer from EVM chain
bridge-cli omni-connector evm-init-transfer \
    --chain <EVM_CHAIN> \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT> \
    --recipient <NEAR_RECIPIENT> \
    --fee <FEE_AMOUNT> \
    --native-fee <NATIVE_FEE_AMOUNT>

# Finalize a transfer on EVM chain
bridge-cli omni-connector evm-fin-transfer \
    --chain <EVM_CHAIN> \
    --tx-hash <NEAR_TX_HASH>
```

#### Solana Operations
```bash
# Initialize Solana bridge
bridge-cli omni-connector solana-initialize \
    --program-keypair <KEYPAIR>

# Initialize a token transfer from Solana
bridge-cli omni-connector solana-init-transfer \
    --token <TOKEN_ADDRESS> \
    --amount <AMOUNT> \
    --recipient <RECIPIENT_ADDRESS>

# Initialize a SOL transfer
bridge-cli omni-connector solana-init-transfer-sol \
    --amount <AMOUNT> \
    --recipient <RECIPIENT_ADDRESS>

# Finalize a token transfer on Solana
bridge-cli omni-connector solana-finalize-transfer \
    --tx-hash <NEAR_TX_HASH> \
    [--sender-id <NEAR_SENDER_ID>] \
    --solana-token <TOKEN_ADDRESS>

# Finalize a SOL transfer
bridge-cli omni-connector solana-finalize-transfer-sol \
    --tx-hash <NEAR_TX_HASH> \
    [--sender-id <NEAR_SENDER_ID>]
```

### Fast Bridge Commands

Commands for optimized bridge operations:

```bash
# Fast bridge specific commands
bridge-cli fast-bridge [SUBCOMMAND]
```

## Configuration

The CLI can be configured in multiple ways (in order of precedence):

1. Command-line arguments
2. Environment variables
3. Configuration file
4. Default values

### Environment Variables

Key environment variables:

- `NEAR_ENV`: Set the NEAR network environment (mainnet/testnet)
- `NEAR_ACCOUNT_ID`: Your NEAR account ID
- `NEAR_PRIVATE_KEY`: Your NEAR account private key

### Configuration File

You can create a configuration file with your preferred settings. The CLI will look for it in the default location or you can specify it using the `--config` flag.

## Development Status

This CLI is under active development. Features and commands may be added, modified, or removed. Please report any issues or suggestions on our GitHub repository.


## License

This project is licensed under the terms specified in the [LICENSE](../LICENSE) file.
