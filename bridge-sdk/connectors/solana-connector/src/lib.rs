#[macro_use]
extern crate derive_builder;

mod solana_connector;

pub use solana_connector::{SolanaConnector, SolanaConnectorBuilder};
