use borsh::BorshSerialize;
use crate::DeployTokenData;

pub struct Initialize {
    pub derived_near_bridge_address: [u8; 64],
}

impl BorshSerialize for Initialize {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[175, 175, 109, 31, 13, 152, 155, 237])?;
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