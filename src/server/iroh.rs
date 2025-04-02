use actix_web::{web, HttpResponse, Responder};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;
use tokio::sync::Mutex as TokioMutex;

use iroh::Endpoint;
use iroh_blobs::{
    store::mem::Store,
    ticket::BlobTicket,
};
use crate::server::AppState;

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
    #[allow(dead_code)]
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

#[derive(Clone)]
pub struct ActiveShares {
    shares: Arc<TokioMutex<HashMap<String, ShareInfo>>>,
}

impl ActiveShares {
    pub fn new() -> Self {
        Self {
            shares: Arc::new(TokioMutex::new(HashMap::new())),
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
            let mut shares = active_shares.shares.lock().await;
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
    check_stale_blobs(&state.active_shares).await;
    cleanup_stale_blobs(&state.active_shares).await;
    let active_shares = state.active_shares.lock().await;
    let shares = active_shares.shares.lock().await;
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
    let active_shares = state.active_shares.lock().await;
    let mut shares = active_shares.shares.lock().await;
    if let Some(info) = shares.remove(&ticket) {
        info.handle.abort();
        // Stopp Iroh-noden
        let _ = info.router.shutdown().await;
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

pub async fn check_stale_blobs(active_shares: &Arc<TokioMutex<ActiveShares>>) -> Vec<String> {
    let mut stale = Vec::new();
    let shares = active_shares.lock().await;
    let inner_shares = shares.shares.lock().await;
    
    for (path, share) in inner_shares.iter() {
        if share.handle.is_finished() {
            stale.push(path.clone());
        }
    }
    println!("✅ Stale blobs: {:?}", stale);
    stale
}

pub async fn cleanup_stale_blobs(active_shares: &Arc<TokioMutex<ActiveShares>>) {
    let stale = check_stale_blobs(active_shares).await;
    let mut shares = active_shares.lock().await;
    let mut inner_shares = shares.shares.lock().await;
    println!("✅ Stale blobs: {:?}", stale);
    for path in stale {
        inner_shares.remove(&path);
    }
}
