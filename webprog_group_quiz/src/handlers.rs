use actix_web::{get, post, patch, delete, web, HttpResponse, Responder, Error, HttpMessage};
use sqlx::SqlitePool;
use crate::models::{BugReport, NewBugReport, UpdateBugReport,RegisterRequest, LoginResponse,LoginRequest,Project,NewProject,Developer, BugAssignForm};
use std::collections::HashMap;
use std::sync::Mutex;
use crate::db;
use tera::Tera;
use tera::Context;
use actix_web::dev::ServiceRequest;
use crate::auth::{verify_password, hash_password, store_user_session};
use actix_session::Session;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/projects")
            .route(web::get().to(get_projects))
            .route(web::post().to(add_project)
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



pub async fn create_bug(
    pool: web::Data<SqlitePool>,
    body: web::Json<NewBugReport>
) -> impl Responder {
    let result = sqlx::query(
        "INSERT INTO bugreport (developer_id, project_id, bug_description, bug_severity) VALUES (?, ?, ?, ?)"
    )
    .bind(&body.developer_id)
    .bind(&body.project_id)
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
    let projects_result = sqlx::query_as::<_,Project>("SELECT project_id, project_name, project_description FROM projects")
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

async fn add_project(_pool: web::Data<SqlitePool>, _body: web::Json<NewProject>, session: Session,) -> impl Responder {
    let new_project_name = &_body.name;
    let new_project_descripton = &_body.description;

    if let Some(role) = session.get::<String>("role").unwrap_or(None) {
        if role != "admin" {
            return HttpResponse::Forbidden().body("Admin access only");
        }
    } else {
        return HttpResponse::Unauthorized().body("Please log in");
    }

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
    let bugs = sqlx::query_as!(BugReport, "SELECT * FROM bugreport")
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
    session: Session,
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
                // ✅ Store session data
                if let Err(e) = store_user_session(&session, &req.username, &user.role) {
                    return HttpResponse::InternalServerError().body("Session error");
                    println!("Session set: username={}, role={}", req.username, user.role);

                }

                HttpResponse::Ok().json(LoginResponse {
                    status: "success".to_string(),
                    message: Some("Login successful".to_string()),
                    
                })
            } else {
                HttpResponse::Unauthorized().json(LoginResponse {
                    status: "failure".to_string(),
                    message: Some("Login unsuccessful".to_string()),
                })
            }
        }
        None => HttpResponse::Unauthorized().json(LoginResponse {
            status: "failure".to_string(),
            message: Some("Login unsuccessful".to_string()),
        }),
    }
}

#[get("/logout")]
pub async fn logout(session: Session) -> impl Responder {
    session.purge();
    HttpResponse::Ok().body("You have been logged out.")
}

#[get("/whoami")]
pub async fn whoami(session: actix_session::Session) -> impl actix_web::Responder {
    if let Some(username) = session.get::<String>("username").unwrap_or(None) {
        format!("Logged in as: {}", username)
    } else {
        "Not logged in.".to_string()
    }
}
