use crate::{error::SolanaClientError, instructions::*};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction}, pubkey::Pubkey, signature::{Keypair, Signature}, signer::Signer, system_program, sysvar, transaction::Transaction
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

pub struct SolanaBridgeClient {
    client: RpcClient,
    program_id: Pubkey,
    wormhole: Pubkey,
}

impl SolanaBridgeClient {
    pub fn new(endpoint_url: String, program_id: Pubkey, wormhole: Pubkey) -> Self {
        Self {
            client: RpcClient::new(endpoint_url),
            program_id,
            wormhole,
        }
    }

    pub fn initialize(
        &self,
        derived_near_bridge_address: [u8; 64],
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let (config, _) = Pubkey::find_program_address(
            &[b"config"],
            &self.program_id,
        );
        let (wormhole_bridge, _) = Pubkey::find_program_address(
            &[b"Bridge"],
            &self.wormhole,
        );
        let (wormhole_fee_collector, _) = Pubkey::find_program_address(
            &[b"fee_collector"],
            &self.wormhole,
        );
        let (wormhole_sequence, _) = Pubkey::find_program_address(
            &[b"Sequence", config.as_ref()],
            &self.wormhole,
        );
        let (wormhole_message, _) = Pubkey::find_program_address(
            &[b"message", 1u64.to_le_bytes().as_ref()],
            &self.program_id,
        );

        let instruction_data = Initialize {
            derived_near_bridge_address,
        };

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &instruction_data,
            vec![
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(wormhole_bridge, false),
                AccountMeta::new(wormhole_fee_collector, false),
                AccountMeta::new(wormhole_sequence, false),
                AccountMeta::new(wormhole_message, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.wormhole, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer)
    }

    pub fn deploy_token(
        &self,
        data: DeployTokenData,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();

        let (config, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let (authority, _) = Pubkey::find_program_address(&[b"authority"], &self.program_id);
        let (mint, _) = Pubkey::find_program_address(&[data.metadata.token.as_bytes()], &self.program_id);
        let (metadata, _) = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), mint.as_ref()],
            &metadata_program_id,
        );

        let (wormhole_bridge, _) = Pubkey::find_program_address(
            &[b"Bridge"],
            &self.wormhole,
        );
        let (wormhole_fee_collector, _) = Pubkey::find_program_address(
            &[b"fee_collector"],
            &self.wormhole,
        );
        let (wormhole_sequence, _) = Pubkey::find_program_address(
            &[b"Sequence", config.as_ref()],
            &self.wormhole,
        );
        let (wormhole_message, _) = Pubkey::find_program_address(
            &[b"message", 2u64.to_le_bytes().as_ref()],
            &self.program_id,
        );

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
                AccountMeta::new_readonly(self.wormhole, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(metadata_program_id, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer)
    }

    fn send_and_confirm_transaction(
        &self,
        instructions: Vec<Instruction>,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let recent_blockhash = self.client.get_latest_blockhash()?;

        let transaction = Transaction::new_signed_with_payer(
            &instructions,
            Some(&payer.pubkey()),
            &[payer],
            recent_blockhash,
        );

        let signature = self.client.send_and_confirm_transaction(&transaction)?;
        Ok(signature)
    }
}
