use clap::Parser;

use sdrive::{
    cli::{Cli, Commands, ConfigSubcommands, CreditsSubcommands},
    config::{get_config_path, prompt_and_save_config},
    credits::credits_status,
    upload::process_upload,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Upload(args) => {
            let config_path = args.config_path.or_else(get_config_path);

            process_upload(
                args.path.clone(),
                args.path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .to_path_buf(),
                config_path.expect("Failed to provide config path"),
            )
            .await?;
        }
        Commands::Config { command } => match command {
            ConfigSubcommands::Create {
                config_path,
                rpc_url,
                sync_dir,
                api_key,
                user_guid,
                keypair_path,
            } => {
                prompt_and_save_config(
                    config_path,
                    rpc_url,
                    sync_dir,
                    api_key,
                    user_guid,
                    keypair_path,
                )
                .await?;
            }
        },
        Commands::Credits { command } => match command {
            CreditsSubcommands::Status { config_path } => {
                let config_path_option = config_path.or_else(get_config_path);
                credits_status(config_path_option.expect("REASON").to_string()).await?;
            }
            #[allow(unused_variables)]
            CreditsSubcommands::Stake {
                config_path,
                amount,
            } => {
                credits_status(config_path).await?;
            }
            #[allow(unused_variables)]
            CreditsSubcommands::Unstake {
                config_path,
                amount,
            } => {
                credits_status(config_path).await?;
            }
            #[allow(unused_variables)]
            CreditsSubcommands::Claim {
                config_path,
                amount,
            } => {
                credits_status(config_path).await?;
            }
        },
        _ => {
            // Handle other commands
        }
    }

    Ok(())
}
