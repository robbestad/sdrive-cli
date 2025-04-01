use crate::server::AppState;
use actix_web::web;
use actix_web::HttpResponse;
use rusqlite::params;
use serde::Serialize;
use crate::server::directories::normalize_path;

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
    file_key: String,
    filepath: String,
    is_directory: bool,
}

fn map_row(row: &rusqlite::Row) -> Result<FileEntry, rusqlite::Error> {
    Ok(FileEntry {
        cid: row.get(0)?,
        filename: row.get(1)?,
        filepath: normalize_path(&row.get::<_, String>(2)?),
        file_key: row.get(3)?,
        size: row.get(4)?,
        modified: row.get(5)?,
        is_directory: row.get(6)?,
    })
}

pub async fn list_files_handler(
    query: web::Query<ListFilesQuery>,
    state: web::Data<AppState>
) -> Result<HttpResponse, actix_web::Error> {
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20);
    let offset = (page - 1) * page_size;

    let filter_pattern = query.filter.clone().unwrap_or_default();
    let db_conn = state.db_conn.lock().await;

    let mut stmt = if filter_pattern.is_empty() {
        db_conn.prepare("SELECT cid, filename, filepath, file_key, size, modified, is_directory FROM pinned_files LIMIT ? OFFSET ?")
    } else {
        db_conn.prepare("SELECT cid, filename, filepath, file_key, size, modified, is_directory FROM pinned_files WHERE filename LIKE ? LIMIT ? OFFSET ?")
    }.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let row_mapper = |row: &rusqlite::Row| map_row(row);
    let file_iter = if filter_pattern.is_empty() {
        stmt.query_map(params![page_size as i64, offset as i64], &row_mapper)
    } else {
        let like_pattern = format!("%{}%", filter_pattern);
        stmt.query_map(
            params![like_pattern, page_size as i64, offset as i64],
            &row_mapper,
        )
    }
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let mut files = Vec::new();
    for file in file_iter {
        files.push(file.map_err(|e| actix_web::error::ErrorInternalServerError(e))?);
    }

    Ok(HttpResponse::Ok().json(files))
}
