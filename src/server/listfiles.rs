use crate::server::AppState;
use actix_web::web;
use actix_web::HttpResponse;
use rusqlite::params;
use serde::Serialize;

#[derive(serde::Deserialize)]
pub struct ListFilesQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    filter: Option<String>,
}

#[derive(Serialize)]
struct FileEntry {
    cid: String,
    size: u64,
    modified: i64,
    filename: String,
    filepath: String,
    is_directory: bool,
}

fn map_row(row: &rusqlite::Row) -> Result<FileEntry, rusqlite::Error> {
    Ok(FileEntry {
        cid: row.get(0)?,
        filename: row.get(1)?,
        filepath: row.get(2)?,
        size: row.get(3)?,
        modified: row.get(4)?,
        is_directory: row.get(5)?,
    })
}
pub async fn list_files_handler(
    query: web::Query<ListFilesQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20);
    let offset = (page - 1) * page_size;

    let filter_pattern = query.filter.clone().unwrap_or_default();
    let db_conn = state.db_conn.lock().await;

    let mut stmt = if filter_pattern.is_empty() {
        db_conn.prepare("SELECT cid, filename, filepath, size, modified, is_directory FROM pinned_files LIMIT ? OFFSET ?")
    } else {
        db_conn.prepare("SELECT cid, filename, filepath, size, modified, is_directory FROM pinned_files WHERE filename LIKE ? LIMIT ? OFFSET ?")
    }.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let file_iter = if filter_pattern.is_empty() {
        stmt.query_map(params![page_size as i64, offset as i64], map_row)
    } else {
        let like_pattern = format!("%{}%", filter_pattern);
        stmt.query_map(
            params![like_pattern, page_size as i64, offset as i64],
            map_row,
        )
    }
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let mut files = Vec::new();
    for file in file_iter {
        files.push(file.map_err(|e| actix_web::error::ErrorInternalServerError(e))?);
    }

    Ok(HttpResponse::Ok().json(files))
}
