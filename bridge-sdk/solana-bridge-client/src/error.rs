use solana_client::client_error::ClientError;

#[derive(thiserror::Error, Debug)]
pub enum SolanaClientError {
    #[error("Solana RPC error: {0}")]
    RpcError(#[from] ClientError),
}
