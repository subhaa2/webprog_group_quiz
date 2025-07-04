use actix_web::{get, post, patch, delete, web, HttpResponse, Responder, Error, HttpMessage};
use sqlx::SqlitePool;
use crate::models::{BugReport, NewBugReport, UpdateBugReport,RegisterRequest, LoginResponse,LoginRequest,Project,NewProject,Developer, BugAssignForm};
use crate::auth::{verify_password, create_jwt, hash_password,validate_jwt};
use std::collections::HashMap;
use std::sync::Mutex;
use crate::db;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use tera::{Tera, Context};
use crate::auth::Claims;
use crate::auth_middleware::validator;
use actix_web::dev::ServiceRequest;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/projects")
            .route(web::get().to(get_projects))
            .route(web::post().to(add_project).wrap(
                actix_web::middleware::Compat::new(
                    actix_web_httpauth::middleware::HttpAuthentication::bearer(admin_validator)
                )
            )
    )
    )
    .service(
        web::resource("/bugs/assign")
            .route(web::get().to(get_bug_assignment_form))
            .route(web::post().to(set_bug_assigment_form))
    )
    .service(
        web::resource("/bugs/{id}")
            .route(web::get().to(get_bug))
            .route(web::patch().to(update_bug))
            .route(web::delete().to(delete_bug))
    )
    .service(
        web::resource("/bugs")
            .route(web::get().to(list_bugs))
            .route(web::post().to(create_bug))
    )
    .service(register)
    .service(login);
}

async fn admin_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let token = credentials.token();
    match validate_jwt(token) {
        Ok(claims) if claims.role == "admin" => {
            req.extensions_mut().insert(claims);
            Ok(req)
        }
        Ok(_) => Err((actix_web::error::ErrorForbidden("Admin access required"), req)),
        Err(_) => Err((actix_web::error::ErrorUnauthorized("Invalid token"), req)),
    }
}

pub async fn create_bug(
    pool: web::Data<SqlitePool>,
    body: web::Json<NewBugReport>
) -> impl Responder {
    let result = sqlx::query(
        "INSERT INTO bugreport (project_id, bug_title, bug_description, bug_severity) VALUES (?, ?, ?, ?)"
    )
    .bind(&body.project_id)
    .bind(&body.bug_title)
    .bind(&body.bug_description)
    .bind(&body.bug_severity)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            HttpResponse::Ok().body(format!("New bug inserted with ID: {}", res.last_insert_rowid()))
        },
        Err(err) => {
            eprintln!("Insert Bug Error: {:?}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn get_projects(_pool: web::Data<SqlitePool>) -> impl Responder {
    let projects_result = sqlx::query_as::<_,Project>("SELECT project_id, project_name, project_description FROM projects where project_status = 'active'")
            .fetch_all(_pool.get_ref())
            .await;

    match projects_result {
        Ok(projects) => HttpResponse::Ok().json(projects),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to fetch projects")
        }
    }
}

async fn add_project(_pool: web::Data<SqlitePool>, _body: web::Json<NewProject>) -> impl Responder {
    let new_project_name = &_body.name;
    let new_project_descripton = &_body.description;

    let result = sqlx::query("INSERT INTO projects (project_name, project_description) VALUES (?, ?)")
            .bind(new_project_name)
            .bind(new_project_descripton)
            .execute(_pool.get_ref())
            .await;

        match result {
            Ok(res) => {
                HttpResponse::Ok().body("New Project Inserted to database.")
            }
            Err(err) => {
                eprintln!("Insert New Project Error: {:?}",err);
                HttpResponse::InternalServerError().finish()
            }
        }
    }

// Get all the listed bug reports
async fn list_bugs(db: web::Data<SqlitePool>) -> impl Responder {
    let bugs = sqlx::query_as!(
        BugReport,
        r#"
        SELECT bug_id, developer_id, project_id, bug_title, bug_description, bug_severity, report_time FROM bugreport
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
async fn get_bug(
    db: web::Data<SqlitePool>,
    path: web::Path<i64>,
) -> impl Responder {
    let bug_id = path.into_inner();

    let bug = sqlx::query_as!(
        BugReport,
        r#"
        SELECT bug_id, developer_id, project_id, bug_title, bug_description, bug_severity, report_time FROM bugreport
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
async fn update_bug(
    db: web::Data<SqlitePool>,
    path: web::Path<i64>,
    updates: web::Json<UpdateBugReport>,
) -> impl Responder {
    let bug_id = path.into_inner();

    let bug = sqlx::query_as::<_, BugReport>(
        r#"
        UPDATE bugreport
        SET
            developer_id = COALESCE(?, developer_id),
            bug_description = COALESCE(?, bug_description),
            bug_severity = COALESCE(?, bug_severity),
            report_time = COALESCE(?, report_time)
        WHERE bug_id = ?
        RETURNING bug_id, developer_id, project_id, bug_description, bug_severity, report_time
        "#
    )
    .bind(updates.developer_id)
    .bind(updates.bug_description.as_deref())
    .bind(updates.bug_severity.as_deref())
    .bind(updates.report_time.as_deref())
    .bind(bug_id)
    .fetch_optional(db.get_ref())
    .await;

    match bug {
        Ok(Some(updated)) => HttpResponse::Ok().json(updated),
        Ok(None) => HttpResponse::NotFound().body("Bug not found"),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// Delete Bug report
async fn delete_bug(
    db: web::Data<SqlitePool>,
    path: web::Path<i64>,
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

async fn set_bug_assigment_form( _pool: web::Data<SqlitePool>, form:web::Form<BugAssignForm>) -> impl Responder {
    let assignForm = UpdateBugReport{
        developer_id: Some(form.developer_id),
        bug_description:None,
        bug_severity:None,
        report_time:None,
    };

    update_bug(_pool, web::Path::from(form.bug_id), web::Json(assignForm),
    ).await
}

async fn get_bug_assignment_form(_pool: web::Data<SqlitePool>, tmpl: web::Data<Tera>) -> impl Responder {
    let bugs = sqlx::query_as!(BugReport, "SELECT bug_id, developer_id, project_id, bug_title, bug_description, bug_severity, report_time FROM bugreport")
        .fetch_all(_pool.get_ref())
        .await;

    let developers = sqlx::query_as!(Developer, "SELECT * FROM developers")
        .fetch_all(_pool.get_ref())
        .await;

    match (bugs, developers) {
        (Ok(bugs), Ok(devs)) => {
            let mut ctx = Context::new();
            ctx.insert("bugs", &bugs);
            ctx.insert("developers",&devs);
            tmpl.render("bug_assign_form.html", &ctx)
                .map(|html| HttpResponse::Ok().content_type("text/html").body(html))
                .unwrap_or_else(|e| {
                    eprint!("Template error: {}",e);
                    HttpResponse::InternalServerError().body("Template error")
                })
        }

        _ => HttpResponse::InternalServerError().body("Database load error"),
    }
}

#[post("/register")]
pub async fn register(
    db: web::Data<SqlitePool>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    // Hash the password
    let hashed_password = hash_password(&req.password);
    
    // Store user in database
    let result = sqlx::query!(
        r#"
        INSERT INTO developers (username, password_hash, role)
        VALUES (?, ?, ?)
        "#,
        req.username,
        hashed_password,
        "admin" // Default role
    )
    .execute(db.get_ref())
    .await;
    
    match result {
        Ok(_) => HttpResponse::Ok().json("Registration successful"),
        Err(e) => {
            if e.to_string().contains("UNIQUE constraint failed") {
                HttpResponse::BadRequest().json("Username already exists")
            } else {
                HttpResponse::InternalServerError().json("Registration failed")
            }
        }
    }
}

#[post("/login")]
pub async fn login(
    db: web::Data<sqlx::SqlitePool>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    // Get user from database
    let user = match sqlx::query!(
        r#"SELECT password_hash, role FROM developers WHERE username = ?"#,
        req.username
    )
    .fetch_optional(db.get_ref())
    .await {
        Ok(user) => user,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    match user {
        Some(user) => {
            if verify_password(&req.password, &user.password_hash) {
                match create_jwt(&req.username, &user.role) {
                    Ok(token) => HttpResponse::Ok().json(LoginResponse {
                        status: "success".to_string(),
                        token: Some(token),
                    }),
                    Err(_) => HttpResponse::InternalServerError().json("Failed to generate token"),
                }
            } else {
                HttpResponse::Unauthorized().json(LoginResponse {
                    status: "failure".to_string(),
                    token: None,
                })
            }
        }
        None => HttpResponse::Unauthorized().json(LoginResponse {
            status: "failure".to_string(),
            token: None,
        }),
    }
}