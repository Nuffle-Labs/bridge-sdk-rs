use crate::error::SolanaClientError;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_program,
    transaction::Transaction,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct MetadataPayload {
    token: String,
    name: String,
    symbol: String,
    decimals: u8,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct DeployTokenData {
    metadata: MetadataPayload,
    signature: [u8; 65],
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct DepositPayload {
    nonce: u128,
    token: String,
    amount: u128,
    recipient: Pubkey,
    fee_recipient: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct FinalizeDepositData {
    payload: DepositPayload,
    signature: [u8; 65],
}

pub struct SolanaBridgeClient {
    client: RpcClient,
    program_id: Pubkey,
}

impl SolanaBridgeClient {
    pub fn new(endpoint_url: String, program_id: Pubkey) -> Self {
        Self {
            client: RpcClient::new(endpoint_url),
            program_id,
        }
    }

    pub fn deploy_token(
        &self,
        data: DeployTokenData,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let metadata_program_id: Pubkey = mpl_token_metadata::ID.to_bytes().into();

        let config = Pubkey::find_program_address(&[b"config"], &self.program_id).0;
        let authority = Pubkey::find_program_address(&[b"authority"], &self.program_id).0;
        let mint =
            Pubkey::find_program_address(&[data.metadata.token.as_bytes()], &self.program_id).0;
        let metadata = Pubkey::find_program_address(
            &[b"metadata", metadata_program_id.as_ref(), mint.as_ref()],
            &metadata_program_id,
        )
        .0;

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &data,
            vec![
                AccountMeta::new_readonly(config, false),
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(metadata, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(metadata_program_id, false),
            ],
        );

        self.send_and_confirm_transaction(vec![instruction], payer)
    }

    pub fn finalize_deposit(
        &self,
        data: FinalizeDepositData,
        payer: Keypair,
    ) -> Result<Signature, SolanaClientError> {
        let config = Pubkey::find_program_address(&[b"config"], &self.program_id).0;
        let authority = Pubkey::find_program_address(&[b"authority"], &self.program_id).0;
        let mint =
            Pubkey::find_program_address(&[data.payload.token.as_bytes()], &self.program_id).0;
        let token_account = spl_associated_token_account::get_associated_token_address(
            &data.payload.recipient,
            &mint,
        );

        let instruction = Instruction::new_with_borsh(
            self.program_id,
            &data,
            vec![
                AccountMeta::new_readonly(config, false),
                AccountMeta::new_readonly(data.payload.recipient, false),
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(token_account, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(spl_associated_token_account::ID, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
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
