use std::str::FromStr;

use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_types::{near_events::Nep141LockerEvent, OmniAddress};
use solana_bridge_client::{DeployTokenData, DepositPayload, FinalizeDepositData, MetadataPayload, SolanaBridgeClient};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Builder, Default)]
pub struct SolanaConnector {
    solana_endpoint: Option<String>,
    solana_bridge_address: Option<String>,
    solana_keypair: Option<String>,
    near_endpoint: Option<String>,
    near_signer: Option<String>,
}


impl SolanaConnector {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn initialize(&self) -> Result<()> {
        let solana_client = SolanaBridgeClient::new(
            self.solana_endpoint()?.to_string(),
            self.solana_bridge_address()?.parse()?,
            Pubkey::from_str("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5")?,
        );
        solana_client.initialize(
            [19, 55, 243, 130, 164, 28, 152, 3, 170, 254, 187, 182, 135, 17, 208, 98, 216, 182, 238, 146, 2, 127, 83, 201, 149, 246, 138, 221, 29, 111, 186, 167, 150, 196, 102, 219, 89, 69, 115, 114, 185, 116, 6, 233, 154, 114, 222, 142, 167, 206, 157, 39, 177, 221, 224, 86, 146, 61, 226, 206, 55, 2, 119, 12],
            self.solana_keypair()?,
        )?;

        Ok(())
    }

    pub async fn deploy_token(&self, 
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<()> {
        let transfer_log = self
            .extract_transfer_log(transaction_hash, sender_id, "LogMetadataEvent")
            .await?;

        let solana_client = SolanaBridgeClient::new(
            self.solana_endpoint()?.to_string(),
            self.solana_bridge_address()?.parse()?,
            Pubkey::from_str("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5")?,
        );

        let Nep141LockerEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = serde_json::from_str(&transfer_log)?
        else {
            return Err("Unknown error".into());
        };
        
        let mut signature = signature.to_bytes();
        signature[64] -= 27; // Remove recovery_id modification in OmniTypes and add specifically when submitting to EVM chains

        let payload = DeployTokenData {
            metadata: MetadataPayload {
                token: metadata_payload.token,
                name: metadata_payload.name,
                symbol: metadata_payload.symbol,
                decimals: metadata_payload.decimals,
            },
            signature: signature.try_into().map_err(|_| "Invalid signature")?,
        };

        solana_client.deploy_token(payload, self.solana_keypair()?)?;

        Ok(())
    }

    async fn extract_transfer_log(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
        event_name: &str,
    ) -> Result<String> {
        let near_endpoint = self.near_endpoint()?;

        let sender_id = match sender_id {
            Some(id) => id,
            None => self.near_account_id()?,
        };
        let sign_tx = near_rpc_client::wait_for_tx_final_outcome(
            transaction_hash,
            sender_id,
            near_endpoint,
            30,
        )
        .await?;

        let transfer_log = sign_tx
            .receipts_outcome
            .iter()
            .find(|receipt| {
                !receipt.outcome.logs.is_empty() && receipt.outcome.logs[0].contains(event_name)
            })
            .ok_or("Unknown error".to_string())?
            .outcome
            .logs[0]
            .clone();

        Ok(transfer_log)
    }

    fn near_endpoint(&self) -> Result<&str> {
        Ok(self
            .near_endpoint
            .as_ref()
            .ok_or(
                "Near rpc endpoint is not set".to_string(),
            )?)
    }

    fn near_account_id(&self) -> Result<AccountId> {
        Ok(self.near_signer
            .as_ref()
            .ok_or("Near signer account id is not set".to_string())?
            .parse::<AccountId>()
            .map_err(|_| "Invalid near signer account id".to_string())?)
    }

    fn solana_endpoint(&self) -> Result<&str> {
        Ok(self
            .solana_endpoint
            .as_ref()
            .ok_or(
                "Solana rpc endpoint is not set".to_string(),
            )?)
    }

    fn solana_bridge_address(&self) -> Result<&str> {
        Ok(self
            .solana_bridge_address
            .as_ref()
            .ok_or(
                "Solana bridge address is not set".to_string(),
            )?)
    }

    fn solana_keypair(&self) -> Result<Keypair> {
        Ok(Keypair::from_base58_string(self
            .solana_keypair
            .as_ref()
            .ok_or("Solana keypair is not set".to_string())?))
    }
}
