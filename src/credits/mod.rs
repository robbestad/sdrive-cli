use crate::config::read_config;
use solana_client::rpc_client::RpcClient;
use solana_program::{program_error::ProgramError, program_pack::Sealed};
use solana_sdk::signature::Signer;
use solana_sdk::{pubkey::Pubkey, signature::read_keypair_file};
use std::str::FromStr;

impl Sealed for CreditsStatus {}

impl CreditsStatus {
    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        // Ensure there's enough data for both u64 values plus the program-reserved 8 bytes.
        if src.len() < 24 {
            // 8 bytes reserved + 16 bytes for our data
            return Err(ProgramError::InvalidAccountData);
        }

        // Adjust indices to skip the first 8 bytes.
        let credits = u64::from_le_bytes(
            src[8..16]
                .try_into()
                .expect("Invalid slice length for credits"),
        );
        let spent_credits = u64::from_le_bytes(
            src[16..24]
                .try_into()
                .expect("Invalid slice length for spent_credits"),
        );

        Ok(CreditsStatus {
            credits,
            spent_credits,
        })
    }
}

#[derive(Debug)]
struct CreditsStatus {
    credits: u64,       // credits deposited (including decimals)
    spent_credits: u64, // spent credits (including decimals)
}

fn find_pda(
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<(Pubkey, u8), Box<dyn std::error::Error>> {
    Ok(Pubkey::find_program_address(seeds, program_id))
}
pub async fn credits_status(config_path: String) -> Result<String, Box<dyn std::error::Error>> {
    let config = read_config(Some(config_path)).await?;
    let user_wallet = read_keypair_file(config.keypair_path.as_deref().unwrap_or(""))
        .expect("Unable to read keypair file");
    let public_key = user_wallet.pubkey();

    let program_id = Pubkey::from_str("CrEDtksrLBd3oJb8hvtGeGfkoq4SehUWqF2Jqhd93PTn")?;
    let credits_mint = Pubkey::from_str("4ptcYkUypE7sDH82oXaeykaAJunuB4yeDJeiLJwS2nQc")?;
    let seed1 = b"mfer";
    let seed2 = public_key.as_ref(); // user pubkey as bytes
    let seed3 = credits_mint.as_ref(); // CREDITS_MINT pubkey as bytes

    let (pda, _bump) = find_pda(&[seed1, seed2, seed3], &program_id)?;
    //println!("public_key base58: {}", public_key.to_string());
    //println!("pda base58: {}", pda.to_string());

    let rpc_client = RpcClient::new(config.rpc_url.as_deref().unwrap_or(""));
    let account_data = rpc_client.get_account_data(&pda).unwrap();

    match CreditsStatus::unpack_from_slice(&account_data) {
        Ok(status) => {
            let credits_decimal = status.credits as f64 / 10_f64.powi(8);
            let spent_credits_decimal = status.spent_credits as f64 / 10_f64.powi(8);
            println!(
                "Staked credits: {:.2}",
                credits_decimal - spent_credits_decimal
            ); // {:.2} formats the float to 2 decimal places
            Ok((credits_decimal - spent_credits_decimal).to_string())
        }
        Err(e) => {
            eprintln!("Error unpacking data: {:?}", e);
            Err(Box::new(e))
        }
    }
}
