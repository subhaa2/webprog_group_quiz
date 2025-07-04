use actix_web::{get, post, patch, delete, web, HttpResponse, Responder};
use sqlx::SqlitePool;
use crate::models::{BugReport, NewBugReport, UpdateBugReport};

// Get all the listed bug reports
#[get("/bugs")]
pub async fn list_bugs(db: web::Data<SqlitePool>) -> impl Responder {
    let bugs = sqlx::query_as!(
        BugReport,
        r#"
        SELECT bug_id, developer_id, project_id, bug_description, bug_severity, report_time
        FROM bugreport
        "#
    )
    .fetch_all(db.get_ref())
    .await;

    match bugs {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// Get bug report by ID
#[get("/bugs/{id}")]
pub async fn get_bug(
    db: web::Data<SqlitePool>,
    path: web::Path<u64>,
) -> impl Responder {
    let bug_id = path.into_inner();

    let bug = sqlx::query_as!(
        BugReport,
        r#"
        SELECT bug_id, developer_id, project_id, bug_description, bug_severity, report_time
        FROM bugreport
        WHERE bug_id = ?
        "#,
        bug_id
    )
    .fetch_optional(db.get_ref())
    .await;

    match bug {
        Ok(Some(b)) => HttpResponse::Ok().json(b),
        Ok(None) => HttpResponse::NotFound().body("Bug not found"),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// Update bug report of the specified ID
#[patch("/bugs/{id}")]
pub async fn update_bug(
    db: web::Data<SqlitePool>,
    path: web::Path<u64>,
    updates: web::Json<UpdateBugReport>,
) -> impl Responder {
    let bug_id = path.into_inner();

    let bug = sqlx::query_as!(
        BugReport,
        r#"
        UPDATE bugreport
        SET
            developer_id = COALESCE(?, developer_id),
            bug_description = COALESCE(?, bug_description),
            bug_severity = COALESCE(?, bug_severity),
            report_time = COALESCE(?, report_time)
        WHERE bug_id = ?
        RETURNING bug_id, developer_id, project_id, bug_description, bug_severity, report_time
        "#,
        updates.developer_id,
        updates.bug_description.as_deref(),
        updates.bug_severity.as_deref(),
        updates.report_time.as_deref(),
        bug_id
    )
    .fetch_optional(db.get_ref())
    .await;

    match bug {
        Ok(Some(updated)) => HttpResponse::Ok().json(updated),
        Ok(None) => HttpResponse::NotFound().body("Bug not found"),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// Delete Bug report
#[delete("/bugs/{id}")]
pub async fn delete_bug(
    db: web::Data<SqlitePool>,
    path: web::Path<u64>,
) -> impl Responder {
    let bug_id = path.into_inner();

    let result = sqlx::query!("DELETE FROM bugreport WHERE bug_id = ?", bug_id)
        .execute(db.get_ref())
        .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => HttpResponse::Ok().body("Bug deleted"),
        Ok(_) => HttpResponse::NotFound().body("Bug not found"),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}