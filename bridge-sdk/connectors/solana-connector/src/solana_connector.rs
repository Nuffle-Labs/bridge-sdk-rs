use near_primitives::{hash::CryptoHash, types::AccountId};
use omni_types::{near_events::Nep141LockerEvent, OmniAddress};
use solana_bridge_client::{
    DeployTokenData, DepositPayload, FinalizeDepositData, MetadataPayload, SolanaBridgeClient, TransferId,
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Builder, Default)]
pub struct SolanaConnector {
    solana_endpoint: Option<String>,
    solana_bridge_address: Option<String>,
    solana_wormhole_address: Option<String>,
    solana_keypair: Option<String>,
    near_endpoint: Option<String>,
    near_signer: Option<String>,
}

impl SolanaConnector {
    /// Creates an empty instance of the bridging client. Property values can be set separately depending on the required use case.
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn initialize(&self, program_keypair: Keypair) -> Result<Signature> {
        // Derived based on near bridge account id and derivation path (bridge-1)
        const DERIVED_NEAR_BRIDGE_ADDRESS: [u8; 64] = [
            19, 55, 243, 130, 164, 28, 152, 3, 170, 254, 187, 182, 135, 17, 208, 98, 216, 182,
            238, 146, 2, 127, 83, 201, 149, 246, 138, 221, 29, 111, 186, 167, 150, 196, 102, 219,
            89, 69, 115, 114, 185, 116, 6, 233, 154, 114, 222, 142, 167, 206, 157, 39, 177, 221,
            224, 86, 146, 61, 226, 206, 55, 2, 119, 12,
        ];
        let tx_id = self.solana_client()?.initialize(
            DERIVED_NEAR_BRIDGE_ADDRESS,
            program_keypair,
            self.solana_keypair()?,
        ).await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_id),
            "Sent initialize transaction"
        );

        Ok(tx_id)
    }

    pub async fn deploy_token(
        &self,
        transaction_hash: CryptoHash,
        sender_id: Option<AccountId>,
    ) -> Result<Signature> {
        let transfer_log = self
            .extract_transfer_log(transaction_hash, sender_id, "LogMetadataEvent")
            .await?;

        let Nep141LockerEvent::LogMetadataEvent {
            signature,
            metadata_payload,
        } = serde_json::from_str(&transfer_log)?
        else {
            return Err("Unknown error".into());
        };

        let mut signature = signature.to_bytes();
        signature[64] -= 27; // TODO: Remove recovery_id modification in OmniTypes and add it specifically when submitting to EVM chains

        let payload = DeployTokenData {
            metadata: MetadataPayload {
                token: metadata_payload.token,
                name: metadata_payload.name,
                symbol: metadata_payload.symbol,
                decimals: metadata_payload.decimals,
            },
            signature: signature.try_into().map_err(|_| "Invalid signature")?,
        };

        let tx_id = self
            .solana_client()?
            .deploy_token(payload, self.solana_keypair()?)
            .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_id),
            "Sent deploy token transaction"
        );

        Ok(tx_id)
    }

    pub async fn finalize_transfer(
        &self,
        transaction_hash: CryptoHash,
        solana_token: Pubkey, // TODO: retrieve from near contract
        sender_id: Option<AccountId>,
    ) -> Result<Signature> {
        let transfer_log = self
            .extract_transfer_log(transaction_hash, sender_id, "SignTransferEvent")
            .await?;

        let Nep141LockerEvent::SignTransferEvent {
            message_payload,
            signature,
        } = serde_json::from_str(&transfer_log)?
        else {
            return Err("Unknown error".into());
        };

        let mut signature = signature.to_bytes();
        signature[64] -= 27;

        let payload = FinalizeDepositData {
            payload: DepositPayload {
                destination_nonce: message_payload.destination_nonce.into(),
                transfer_id: TransferId {
                    origin_chain: 1,
                    origin_nonce: message_payload.transfer_id.origin_nonce,
                },
                token: "wrap.testnet".to_string(),
                amount: message_payload.amount.into(),
                recipient: match message_payload.recipient {
                    OmniAddress::Sol(addr) => Pubkey::new_from_array(addr.0),
                    _ => return Err("Invalid recipient".into()),
                },
                fee_recipient: message_payload.fee_recipient.map(|addr| addr.to_string()),
            },
            signature: signature
                .try_into()
                .map_err(|_| "Invalid signature")?,
        };

        let tx_id = self
            .solana_client()?
            .finalize_transfer(payload, solana_token, self.solana_keypair()?)
            .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_id),
            "Sent finalize transfer transaction"
        );

        Ok(tx_id)
    }

    pub async fn log_metadata(&self, token: Pubkey) -> Result<Signature> {
        let tx_id = self
            .solana_client()?
            .log_metadata(token, self.solana_keypair()?)
            .await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_id),
            "Sent register token transaction"
        );

        Ok(tx_id)
    }

    pub async fn init_transfer(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
    ) -> Result<Signature> {
        let tx_id = self.solana_client()?.init_transfer(
            token,
            amount,
            recipient,
            self.solana_keypair()?,
        ).await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_id),
            "Sent init transfer native transaction"
        );

        Ok(tx_id)
    }

    pub async fn init_transfer_sol(
        &self,
        amount: u128,
        recipient: String,
    ) -> Result<Signature> {
        let tx_id = self.solana_client()?.init_transfer_sol(
            amount,
            recipient,
            self.solana_keypair()?,
        ).await?;

        tracing::info!(
            tx_hash = format!("{:?}", tx_id),
            "Sent init transfer SOL transaction"
        );

        Ok(tx_id)
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

    fn solana_client(&self) -> Result<SolanaBridgeClient> {
        Ok(SolanaBridgeClient::new(
            self.solana_endpoint()?.to_string(),
            self.solana_bridge_address()?.parse()?,
            self.solana_wormhole_address()?.parse()?,
        ))
    }

    fn near_endpoint(&self) -> Result<&str> {
        Ok(self
            .near_endpoint
            .as_ref()
            .ok_or("Near rpc endpoint is not set".to_string())?)
    }

    fn near_account_id(&self) -> Result<AccountId> {
        Ok(self
            .near_signer
            .as_ref()
            .ok_or("Near signer account id is not set".to_string())?
            .parse::<AccountId>()
            .map_err(|_| "Invalid near signer account id".to_string())?)
    }

    fn solana_endpoint(&self) -> Result<&str> {
        Ok(self
            .solana_endpoint
            .as_ref()
            .ok_or("Solana rpc endpoint is not set".to_string())?)
    }

    fn solana_bridge_address(&self) -> Result<&str> {
        Ok(self
            .solana_bridge_address
            .as_ref()
            .ok_or("Solana bridge address is not set".to_string())?)
    }

    fn solana_wormhole_address(&self) -> Result<&str> {
        Ok(self
            .solana_wormhole_address
            .as_ref()
            .ok_or("Solana wormhole address is not set".to_string())?)
    }

    fn solana_keypair(&self) -> Result<Keypair> {
        Ok(Keypair::from_base58_string(
            self.solana_keypair
                .as_ref()
                .ok_or("Solana keypair is not set".to_string())?,
        ))
    }
}
