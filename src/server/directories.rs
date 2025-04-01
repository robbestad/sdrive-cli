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

pub fn normalize_path(path: &str) -> String {
    let path = PathBuf::from(path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .to_string();

    // Finn posisjonen til /public eller /private
    if let Some(pos) = path.find("/public/") {
        format!("/data/sdrive/public{}", &path[pos + 7..])
    } else if let Some(pos) = path.find("/private/") {
        format!("/data/sdrive/private{}", &path[pos + 8..])
    } else if path.ends_with("/public") {
        "/data/sdrive/public".to_string()
    } else if path.ends_with("/private") {
        "/data/sdrive/private".to_string()
    } else if path == "/data/sdrive" {
        "/".to_string()
    } else {
        path
    }
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
                path: normalize_path(&row.get::<_, String>(0)?),
                name: row.get(1)?,
                parent_path: row.get::<_, Option<String>>(2)?.map(|p| normalize_path(&p)),
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
    is_public: bool
) -> Result<(), anyhow::Error> {
    let path_str = normalize_path(path.to_str().unwrap_or_default());
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    
    let parent_path = if path_str == "/data/sdrive/public" || path_str == "/data/sdrive/private" {
        Some("/".to_string())
    } else {
        path
            .parent()
            .map(|p| normalize_path(p.to_str().unwrap_or_default()))
    };

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

    tracing::trace!("✅ Updated directory in database: {}", path_str);
    Ok(())
}

pub async fn list_files_in_directory_handler(
    query: web::Query<DirectoryQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let db_conn = state.db_conn.lock().await;
    let normalized_path = normalize_path(&query.path);
    
    // Hvis stien er root (/), returner en feil
    if normalized_path == "/" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cannot list contents of root directory"
        })));
    }
    
    tracing::trace!("🔍 Searching for files in directory: {}", normalized_path);
    
    let sql = "SELECT cid, filename, filepath, size, modified, is_directory 
               FROM pinned_files 
               WHERE filepath LIKE ? || '/%' 
               AND filepath NOT LIKE ? || '/%/%' 
               AND is_directory = 0
               ORDER BY filename";
    
    tracing::trace!("📝 SQL Query: {}", sql);
    tracing::trace!("🔑 Parameters: pattern={}, subdir_pattern={}", 
        format!("{}%", normalized_path),
        format!("{}/%", normalized_path)
    );
    
    let mut stmt = db_conn
        .prepare(sql)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let pattern = format!("{}%", normalized_path);
    let subdir_pattern = format!("{}/%", normalized_path);
    let files: Vec<FileInDirectory> = stmt
        .query_map(params![pattern, subdir_pattern], |row| {
            Ok(FileInDirectory {
                cid: row.get(0)?,
                filename: row.get(1)?,
                filepath: normalize_path(&row.get::<_, String>(2)?),
                size: row.get(3)?,
                modified: row.get(4)?,
                is_directory: row.get(5)?,
            })
        })
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    tracing::trace!("📂 Found {} files in directory", files.len());
    for file in &files {
        tracing::trace!("   - {} ({})", file.filename, file.filepath);
    }
    
    Ok(HttpResponse::Ok().json(files))
} 