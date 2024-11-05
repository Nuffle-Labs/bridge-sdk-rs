use crate::{error::SolanaClientError, instructions::*};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_program, sysvar,
    transaction::Transaction,
};

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct MetadataPayload {
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct DeployTokenData {
    pub metadata: MetadataPayload,
    pub signature: [u8; 65],
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct DepositPayload {
    pub nonce: u128,
    pub token: String,
    pub amount: u128,
    pub recipient: Pubkey,
    pub fee_recipient: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct FinalizeDepositData {
    pub payload: DepositPayload,
    pub signature: [u8; 65],
}

#[derive(Clone, BorshDeserialize)]
pub struct WormholeSequence {
    pub sequence: u64,
}

pub struct SolanaBridgeClient {
    client: RpcClient,
    program_id: Pubkey,
    wormhole_core: Pubkey,
}

impl SolanaBridgeClient {
    pub fn new(endpoint_url: String, program_id: Pubkey, wormhole_core: Pubkey) -> Self {
        Self {
            client: RpcClient::new(endpoint_url),
            program_id,
            wormhole_core,
        }
    }

    pub async fn initialize(
        &self,
        derived_near_bridge_address: [u8; 64],
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], &self.program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence, wormhole_message)
            = self.get_wormhole_accounts().await?;

        let instruction_data = Initialize {
            admin: payer.pubkey(),
            derived_near_bridge_address,
        };

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
                AccountMeta::new(authority, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.wormhole_core, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer).await
    }

    pub async fn deploy_token(
        &self,
        data: DeployTokenData,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], &self.program_id);
        let (mint, _) = Pubkey::find_program_address(
            &[b"wrapped_mint", data.metadata.token.as_bytes()],
            &self.program_id,
        );

        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), mint.as_ref()],
            &metadata_program_id,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence, wormhole_message)
            = self.get_wormhole_accounts().await?;

        let instruction_data = DeployToken { data };

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(metadata, false),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(self.wormhole_core, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(metadata_program_id, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer).await
    }

    pub async  fn finalize_transfer(
        &self,
        data: FinalizeDepositData,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);

        const USED_NONCES_PER_ACCOUNT: u128 = 1024;
        let (used_nonces, _) = Pubkey::find_program_address(
            &[
                b"used_nonces",
                (data.payload.nonce / USED_NONCES_PER_ACCOUNT)
                    .to_le_bytes()
                    .as_ref(),
            ],
            &self.program_id,
        );
        let recipient = data.payload.recipient;
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], &self.program_id);
        let (mint, _) = Pubkey::find_program_address(
            &[b"wrapped_mint", data.payload.token.as_bytes()],
            &self.program_id,
        );
        let (token_account, _) = Pubkey::find_program_address(
            &[recipient.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
            &spl_associated_token_account::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence, wormhole_message)
            = self.get_wormhole_accounts().await?;

        let instruction_data = FinalizeDeposit {
            payload: DepositInstructionPayload {
                nonce: data.payload.nonce,
                token: data.payload.token,
                amount: data.payload.amount,
                fee_recipient: data.payload.fee_recipient,
            },
            signature: data.signature,
        };

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &instruction_data,
            vec![
                AccountMeta::new(config, false),
                AccountMeta::new(used_nonces, false),
                AccountMeta::new_readonly(recipient, false),
                AccountMeta::new(authority, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(token_account, false),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(self.wormhole_core, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_associated_token_account::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer).await
    }

    pub async fn register_token(
        &self,
        token: Pubkey,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], &self.program_id);
        let (vault, _) =
            Pubkey::find_program_address(&[b"vault", token.as_ref()], &self.program_id);

        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), token.as_ref()],
            &metadata_program_id,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence, wormhole_message)
            = self.get_wormhole_accounts().await?;

        let instruction_data = RegisterMint {
            override_name: String::new(),
            override_symbol: String::new(),
        };

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new_readonly(token, false),
                AccountMeta::new(self.program_id, false),
                AccountMeta::new(metadata, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(self.wormhole_core, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(spl_associated_token_account::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer).await
    }

    pub async fn init_transfer_native(
        &self,
        token: Pubkey,
        amount: u128,
        recipient: String,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], &self.program_id);

        let (from_token_account, _) = Pubkey::find_program_address(
            &[
                payer.pubkey().as_ref(),
                spl_token::ID.as_ref(),
                token.as_ref(),
            ],
            &spl_associated_token_account::ID,
        );
        let (vault, _) =
            Pubkey::find_program_address(&[b"vault", token.as_ref()], &self.program_id);

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence, wormhole_message)
            = self.get_wormhole_accounts().await?;

        let instruction_data = Send { amount, recipient };

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new_readonly(token, false),
                AccountMeta::new(from_token_account, false),
                AccountMeta::new(vault, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(self.wormhole_core, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer).await
    }
    
    pub async fn init_transfer_bridged(
        &self,
        near_token_id: String,
        amount: u128,
        recipient: String,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], &self.program_id);

        let (mint, _) = Pubkey::find_program_address(
            &[b"wrapped_mint", near_token_id.as_bytes()],
            &self.program_id,
        );

        let (from_token_account, _) = Pubkey::find_program_address(
            &[payer.pubkey().as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
            &spl_associated_token_account::ID,
        );

        let (wormhole_bridge, wormhole_fee_collector, wormhole_sequence, wormhole_message)
            = self.get_wormhole_accounts().await?;

        let instruction_data = Repay {
            token: near_token_id,
            amount,
            recipient,
        };

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(from_token_account, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(self.wormhole_core, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        );

        println!("instruction: {:?}", instruction);

        self.send_and_confirm_transaction(vec![instruction], payer).await
    }


    async fn get_wormhole_accounts(&self) -> Result<(Pubkey, Pubkey, Pubkey, Pubkey), SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let (wormhole_bridge, _) = Pubkey::find_program_address(&[b"Bridge"], &self.wormhole_core);
        let (wormhole_fee_collector, _) =
            Pubkey::find_program_address(&[b"fee_collector"], &self.wormhole_core);
        let (wormhole_sequence, _) =
            Pubkey::find_program_address(&[b"Sequence", config.as_ref()], &self.wormhole_core);
        

        let data = self.client.get_account_data(&wormhole_sequence).await?;
        let sequence = WormholeSequence::try_from_slice(&data[..8]) // Sequence can have 8 or 10 bytes but we don't care about 9 and 10
            .map_err(|_| {
                SolanaClientError::InvalidAccountData(format!(
                    "Invalid Wormhole sequence {:?}. Data {:?}",
                    wormhole_sequence, data
                ))
            })?;

        let next_sequence = sequence.sequence + 1;
        let (wormhole_message, _) = Pubkey::find_program_address(
            &[b"message", next_sequence.to_le_bytes().as_ref()],
            &self.program_id,
        );

        Ok((
            wormhole_bridge,
            wormhole_fee_collector,
            wormhole_sequence,
            wormhole_message,
        ))
    }

    async fn send_and_confirm_transaction(
        &self,
        instructions: Vec<Instruction>,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let recent_blockhash = self.client.get_latest_blockhash().await?;

        let transaction = Transaction::new_signed_with_payer(
            &instructions,
            Some(&payer.pubkey()),
            &[payer],
            recent_blockhash,
        );

        let signature = self.client.send_and_confirm_transaction(&transaction).await?;
        Ok(signature)
    }
}
