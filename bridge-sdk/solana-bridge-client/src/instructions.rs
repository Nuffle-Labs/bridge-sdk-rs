use borsh::BorshSerialize;
use solana_sdk::pubkey::Pubkey;
use crate::DeployTokenData;

pub struct Initialize {
    pub admin: Pubkey,
    pub derived_near_bridge_address: [u8; 64],
}

impl BorshSerialize for Initialize {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // TODO: Calculate discriminators based on instruction name
        writer.write_all(&[175, 175, 109, 31, 13, 152, 155, 237])?; 
        writer.write_all(&self.admin.to_bytes())?;
        writer.write_all(&self.derived_near_bridge_address)?;
        Ok(())
    }
}

pub struct DeployToken {
    pub data: DeployTokenData,
}

impl BorshSerialize for DeployToken {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[144, 104, 20, 192, 18, 112, 224, 140])?;
        self.data.serialize(writer)?;
        Ok(())
    }
}

#[derive(BorshSerialize)]
pub struct DepositInstructionPayload {
    pub nonce: u128,
    pub token: String,
    pub amount: u128,
    pub fee_recipient: Option<String>,
}

pub struct FinalizeDeposit {
    pub payload: DepositInstructionPayload,
    pub signature: [u8; 65],
}

impl BorshSerialize for FinalizeDeposit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[240, 178, 165, 14, 221, 29, 104, 47])?;
        self.payload.serialize(writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}
