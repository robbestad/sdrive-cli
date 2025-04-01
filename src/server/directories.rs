use actix_web::{web, HttpResponse};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::server::AppState;

#[derive(Serialize)]
pub struct Directory {
    pub path: String,
    pub name: String,
    pub parent_path: Option<String>,
    pub is_public: bool,
    pub modified: u64,
}

#[derive(Serialize)]
pub struct FileInDirectory {
    pub cid: String,
    pub filename: String,
    pub filepath: String,
    pub size: i64,
    pub modified: i64,
    pub is_directory: bool,
}

#[derive(serde::Deserialize)]
pub struct DirectoryQuery {
    pub path: String,
}

pub fn setup_directories_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS directories (
            path TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            parent_path TEXT,
            is_public BOOLEAN NOT NULL,
            modified INTEGER NOT NULL,
            FOREIGN KEY (parent_path) REFERENCES directories(path)
        )",
        [],
    )?;
    Ok(())
}

pub async fn list_directories_handler(
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let db_conn = state.db_conn.lock().await;
    let mut stmt = db_conn
        .prepare(
            "SELECT path, name, parent_path, is_public, modified FROM directories ORDER BY path",
        )
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let directories: Vec<Directory> = stmt
        .query_map([], |row| {
            Ok(Directory {
                path: row.get(0)?,
                name: row.get(1)?,
                parent_path: row.get(2)?,
                is_public: row.get(3)?,
                modified: row.get(4)?,
            })
        })
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(directories))
}

pub async fn update_directory(
    db_conn: &Arc<Mutex<Connection>>,
    path: &PathBuf,
    is_public: bool,
) -> Result<(), anyhow::Error> {
    let path_str = path.to_string_lossy().to_string();
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    
    let parent_path = path
        .parent()
        .map(|p| p.to_string_lossy().to_string());

    let modified = path
        .metadata()?
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let db_conn_guard = db_conn.lock().await;
    db_conn_guard.execute(
        "INSERT OR REPLACE INTO directories (path, name, parent_path, is_public, modified) VALUES (?, ?, ?, ?, ?)",
        params![path_str, name, parent_path, is_public, modified],
    )?;

    Ok(())
}

pub async fn list_files_in_directory_handler(
    query: web::Query<DirectoryQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let db_conn = state.db_conn.lock().await;
    let path_pattern = format!("{}%", query.path);
    
    let mut stmt = db_conn
        .prepare(
            "SELECT cid, filename, filepath, size, modified, is_directory 
             FROM pinned_files 
             WHERE filepath LIKE ? 
             AND filepath != ? 
             AND filepath NOT LIKE ? 
             ORDER BY filepath",
        )
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let files: Vec<FileInDirectory> = stmt
        .query_map(
            params![path_pattern, query.path, format!("{}/%", query.path)],
            |row| {
                Ok(FileInDirectory {
                    cid: row.get(0)?,
                    filename: row.get(1)?,
                    filepath: row.get(2)?,
                    size: row.get(3)?,
                    modified: row.get(4)?,
                    is_directory: row.get(5)?,
                })
            },
        )
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(files))
} 