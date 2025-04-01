use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;
use uuid::Uuid;

// Her importeres nødvendige moduler fra iroh- og iroh_blobs-pakken
use iroh::{
    discovery::{dns::DnsDiscovery, pkarr::PkarrPublisher},
    Endpoint,
    RelayMode,
    SecretKey,
};
use iroh_blobs::{
    get::db::DownloadProgress,
    provider::CustomEventSender,
    store::{ExportMode, ImportMode, mem::Store},
    ticket::BlobTicket,
    BlobFormat, Hash,
};
use rand::Rng;
use crate::server::AppState;

// Denne strukturen representerer de nødvendige argumentene for sending.
#[derive(Debug)]
struct SendArgs {
    path: PathBuf,
}

impl SendArgs {
    fn new(path: String) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }
}

struct ShareInfo {
    path: String,
    start_time: u64,
    handle: JoinHandle<()>,
    router: Arc<iroh::protocol::Router>,
    blobs: Arc<iroh_blobs::net_protocol::Blobs<Store>>,
}

#[derive(Serialize)]
struct ShareInfoResponse {
    ticket: String,
    path: String,
    start_time: u64,
}

#[derive(Serialize)]
struct TicketResponse {
    ticket: String,
}

/// Applikasjonsstate for å holde oversikt over aktive delinger.
/// Hver deling identifiseres med en ticket (String) og tilknyttet en bakgrunnsoppgave.
#[derive(Clone)]
pub struct ActiveShares {
    active_shares: Arc<Mutex<HashMap<String, ShareInfo>>>,
}

impl ActiveShares {
    pub fn new() -> Self {
        Self {
            active_shares: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Deserialize)]
pub struct ShareRequest {
    path: String,
}

#[derive(Deserialize)]
pub struct StopRequest {
    ticket: String,
}

/// HTTP-endepunkt for POST /share.
/// Tar imot en JSON med sti, kaller start_sharing og returnerer ticketen.
pub async fn start_share_handler(
    state: web::Data<AppState>,
    req: web::Json<ShareRequest>,
) -> impl Responder {
    let path = req.path.clone();
    let args = SendArgs::new(path.clone());
    match start_sharing(args).await {
        Ok((ticket, router, blobs)) => {
            let start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            });

            let active_shares = state.active_shares.lock().await;
            let mut shares = active_shares.active_shares.lock().unwrap();
            shares.insert(
                ticket.clone().to_string(),
                ShareInfo {
                    path: path.clone(),
                    start_time,
                    handle,
                    router: Arc::new(router),
                    blobs: Arc::new(blobs),
                },
            );

            HttpResponse::Ok().json(TicketResponse { ticket: ticket.to_string() })
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Feil under deling: {:?}", e)),
    }
}

/// HTTP-endepunkt for GET /shares som lister alle aktive ticket-er.
pub async fn list_shares_handler(state: web::Data<AppState>) -> impl Responder {
    let active_shares = state.active_shares.lock().await;
    let shares = active_shares.active_shares.lock().unwrap();
    let share_info: Vec<ShareInfoResponse> = shares
        .iter()
        .map(|(ticket, info)| ShareInfoResponse {
            ticket: ticket.clone(),
            path: info.path.clone(),
            start_time: info.start_time,
        })
        .collect();
    HttpResponse::Ok().json(share_info)
}

/// HTTP-endepunkt for POST /share/stop som stopper en aktiv deling.
pub async fn stop_share_handler(
    state: web::Data<AppState>,
    req: web::Json<StopRequest>,
) -> impl Responder {
    let ticket = req.ticket.clone();
    let mut active_shares = state.active_shares.lock().await;
    let mut shares = active_shares.active_shares.lock().unwrap();
    if let Some(info) = shares.remove(&ticket) {
        info.handle.abort();
        // Stopp Iroh-noden
        info.router.shutdown().await;
        HttpResponse::Ok().body(format!("Deling med ticket {} stoppet", ticket))
    } else {
        HttpResponse::NotFound().body("Fant ingen aktiv deling med denne ticketen")
    }
}

/// Starter en ny deling av en fil via Iroh.
/// Dette er en asynkron funksjon som setter opp en Iroh-node og deler filen.
async fn start_sharing(args: SendArgs) -> Result<(String, iroh::protocol::Router, iroh_blobs::net_protocol::Blobs<Store>)> {
    let endpoint = Endpoint::builder()
        .bind_addr_v4("0.0.0.0:0".parse().unwrap())
        .discovery_n0()
        .bind()
        .await?;

    let blobs = iroh_blobs::net_protocol::Blobs::memory().build(&endpoint);
    let router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(iroh_blobs::ALPN, blobs.clone())
        .spawn()
        .await?;

    let blobs_client = blobs.client();
    let abs_path: PathBuf = std::fs::canonicalize(&args.path)?.into();
    let file_name = args.path.file_name().unwrap().to_string_lossy().to_string();

    println!("Hashing file: {}", file_name);

    let in_place = true;
    let blob = blobs_client
        .add_from_path(
            abs_path,
            in_place,
            iroh_blobs::util::SetTagOption::Auto,
            iroh_blobs::rpc::client::blobs::WrapOption::NoWrap,
        )
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

    Ok((share_link, router, blobs))
}
