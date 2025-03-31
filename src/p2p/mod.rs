use crate::DownloadArgsStruct;
use anyhow::Result;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh_blobs::net_protocol::Blobs;
use iroh_blobs::rpc::client::blobs::WrapOption;
use iroh_blobs::store::{ExportFormat, ExportMode};
use iroh_blobs::ticket::BlobTicket;
use iroh_blobs::util::SetTagOption;
use std::path::PathBuf;
use tokio::fs;
use tokio::time::{sleep, timeout, Duration};

pub async fn share_file(file_path: PathBuf, _config: &crate::config::Config) -> Result<String> {
    let endpoint = Endpoint::builder()
        .bind_addr_v4("0.0.0.0:0".parse().unwrap())
        .discovery_n0()
        .bind()
        .await?;

    let blobs = Blobs::memory().build(&endpoint);
    let router = Router::builder(endpoint.clone())
        .accept(iroh_blobs::ALPN, blobs.clone())
        .spawn()
        .await?;

    let blobs_client = blobs.client();
    let abs_path: PathBuf = std::fs::canonicalize(&file_path)?.into();
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();

    println!("Hashing file: {}", file_name);

    let in_place = true;
    let blob = blobs_client
        .add_from_path(abs_path, in_place, SetTagOption::Auto, WrapOption::NoWrap)
        .await?
        .finish()
        .await?;

    let node_id = router.endpoint().node_id();
    let ticket = BlobTicket::new(node_id.into(), blob.hash, blob.format)?;

    let share_link = ticket.to_string();
    println!("✅ File ready to share via Iroh: {}", share_link);
    println!(
        "📡 To download, run: sdrive download {} --output {}",
        share_link, file_name
    );
    println!("Press Ctrl+C to stop sharing...");

    tokio::signal::ctrl_c().await?;
    println!("👋 Shutting down Iroh node...");
    sleep(Duration::from_secs(2)).await;
    router.shutdown().await?;

    Ok(share_link)
}

pub async fn download_file_from_iroh(
    iroh_link: &str,
    args: &DownloadArgsStruct,
) -> Result<Vec<u8>> {
    let ticket: BlobTicket = iroh_link.parse()?;
    let node_addr = ticket.node_addr().clone();
    let hash = ticket.hash();

    let endpoint = Endpoint::builder()
        .bind_addr_v4("0.0.0.0:0".parse().unwrap())
        .discovery_n0()
        .bind()
        .await?;

    let blobs = Blobs::memory().build(&endpoint);
    let blobs_client = blobs.client();

    println!("Starting download from Iroh: {}", iroh_link);
    let _download = match timeout(
        Duration::from_secs(30),
        blobs_client.download(hash, node_addr),
    )
    .await
    {
        Ok(Ok(download)) => download,
        Ok(Err(e)) => return Err(anyhow::anyhow!("Download failed: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("Download timed out after 30 seconds")),
    }
    .await?;

    println!("Finished download.");

    // Bestem filnavn og utdatasti, og konverter til absolutt sti
    let file_name = if args.filename.is_empty() {
        format!("downloaded_{}", hash.to_string()) // Fallback hvis filnavn mangler
    } else {
        args.filename.clone()
    };
    let final_output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&file_name));
    let abs_output_path = std::path::absolute(&final_output_path)?;

    // Eksporter direkte til endelig absolutt plassering
    if let Some(parent) = abs_output_path.parent() {
        fs::create_dir_all(parent).await?;
    }
    blobs_client
        .export(
            hash,
            abs_output_path.clone(),
            ExportFormat::Blob,
            ExportMode::Copy,
        )
        .await?
        .finish()
        .await?;

    println!("✅ File downloaded to {}", abs_output_path.display());

    // Les data for returverdi
    let data = fs::read(&abs_output_path).await?;

    Ok(data)
}
