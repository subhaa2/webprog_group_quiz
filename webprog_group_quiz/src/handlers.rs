use actix_web::{get, post, patch, delete, web, HttpResponse, Responder, Error, HttpMessage,HttpRequest};
use sqlx::SqlitePool;
use crate::models::{BugAssignForm, BugReport, CloseProjectForm, LoginRequest, LoginResponse, NewBugReport, NewProject, Project, RegisterRequest, UpdateBugReport, User};
use std::collections::HashMap;
use std::result;
use std::sync::Mutex;
use crate::db;
use tera::{Tera, Context};  
use actix_web::dev::ServiceRequest;
use crate::auth::{verify_password, hash_password, store_user_session};
use actix_session::Session;

//to check role
fn check_role(session: &Session, required_role: &str) -> bool {
    if let Ok(Some(role)) = session.get::<String>("role") {
        role == required_role || role == "admin"
    } else {
        false
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/projects")
            .route(web::get().to(get_projects))
            .route(web::post().to(add_project))
    )
    .service(
        web::resource("/projects/close")
            .route(web::get().to(get_close_project_form))
            .route(web::post().to(set_close_project_form))
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
        "INSERT INTO bugreport (project_id, bug_title, bug_description, bug_severity,assignee_id) VALUES (?, ?, ?, ?,?)"
    )
    .bind(&body.project_id)
    .bind(&body.bug_title)
    .bind(&body.bug_description)
    .bind(&body.bug_severity)
    .bind(&body.assignee_id)
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

async fn add_project(
    _pool: web::Data<SqlitePool>,
    _body: web::Json<NewProject>,
    session: Session,
) -> impl Responder {
    if !check_role(&session, "admin") {
        return HttpResponse::Forbidden().body("Admin access required");
    }

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

async fn get_close_project_form(_pool: web::Data<SqlitePool>, tmpl: web::Data<Tera>,) -> impl Responder{
    let result = sqlx::query_as!(Project,"SELECT project_id, project_name, project_description, project_status FROM projects WHERE project_status != 'closed'")
        .fetch_all(_pool.get_ref())
        .await;

    match result {
        Ok(projects) => {
            let mut ctx = tera::Context::new();
            ctx.insert("projects",&projects);

            tmpl.render("close_project_form.html", &ctx)
                .map(|html| HttpResponse::Ok().content_type("text/html").body(html))
                .unwrap_or_else(|e|{
                    eprint!("Template render error: {:?}",e);
                    HttpResponse::InternalServerError().body("Templated render error")
                })
        }
        Err(err) => {
            eprint!("Database error: {:?}",err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn set_close_project_form(_pool:web::Data<SqlitePool>,form:web::Form<CloseProjectForm>) -> impl Responder {
    let result = sqlx::query!("Update projects SET project_status = 'closed' WHERE project_id = ?",
                    form.project_id)
                    .execute(_pool.get_ref())
                    .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => {
            HttpResponse::Ok().body("Project successfully closed.")
        }
        Ok(_) => HttpResponse::NotFound().body("Project not found or already closed."),
        Err(err) => {
            eprintln!("Error closing project: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to close project.")
        }
    }
}

// Get all the listed bug reports
async fn list_bugs(db: web::Data<SqlitePool>) -> impl Responder {
    let bugs = sqlx::query_as!(
        BugReport,
        r#"
        SELECT bug_id, assignee_id, project_id, bug_title, bug_description, bug_severity, report_time FROM bugreport
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
        SELECT bug_id, assignee_id, project_id, bug_title, bug_description, bug_severity, report_time FROM bugreport
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
) -> HttpResponse {
    let bug_id = path.into_inner();

    let bug = sqlx::query_as::<_, BugReport>(
        r#"
        UPDATE bugreport
        SET
            assignee_id = COALESCE(?, assignee_id),
            bug_description = COALESCE(?, bug_description),
            bug_severity = COALESCE(?, bug_severity),
            report_time = COALESCE(?, report_time)
        WHERE bug_id = ?
        RETURNING bug_id, assignee_id, project_id, bug_title, bug_description, bug_severity, report_time
        "#
    )
    .bind(updates.assignee_id)
    .bind(updates.bug_description.as_deref())
    .bind(updates.bug_severity.as_deref())
    .bind(updates.report_time.as_deref())
    .bind(bug_id)
    .fetch_optional(db.get_ref())
    .await;

    match bug {
        Ok(Some(updated)) => HttpResponse::Ok().json(updated),
        Ok(None) => HttpResponse::NotFound().body("Bug not found"),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            HttpResponse::InternalServerError().finish()
        },
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

async fn set_bug_assigment_form(
    _pool: web::Data<SqlitePool>,
    form: web::Form<BugAssignForm>,
    session: Session,
) -> impl Responder {
    // Get current user's role
    let current_role = match session.get::<String>("role") {
        Ok(Some(role)) => role,
        _ => return HttpResponse::Unauthorized().body("Not logged in"),
    };

    // Check if assignee is a developer
    let assignee = sqlx::query_as!(
        User,
        "SELECT id, username, password_hash, role FROM users WHERE id = ?",
        form.assignee_id
    )
    .fetch_optional(_pool.get_ref())
    .await;

    match assignee {
        Ok(Some(user)) => {
            // QA can't assign to themselves or other QAs
            if current_role == "qa" {
                if user.role == "qa" {
                    return HttpResponse::Forbidden().body("QA cannot assign bugs to other QAs");
                }
                if let Ok(Some(current_user_id)) = session.get::<i64>("user_id") {
                    if form.assignee_id == current_user_id {
                        return HttpResponse::Forbidden().body("QA cannot assign bugs to themselves");
                    }
                }
            }

            // Only allow assigning to developers
            if user.role != "developer" {
                return HttpResponse::Forbidden().body("Can only assign bugs to developers");
            }
        }
        Ok(None) => return HttpResponse::NotFound().body("Assignee not found"),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    }

    // Proceed with assignment
    let assign_form = UpdateBugReport {
        assignee_id: Some(form.assignee_id),
        bug_description: None,
        bug_severity: None,
        report_time: None,
    };

    // Await the update_bug response and return it directly
    update_bug(_pool, web::Path::from(form.bug_id), web::Json(assign_form)).await
}


async fn get_bug_assignment_form(
    _pool: web::Data<SqlitePool>,
    tmpl: web::Data<Tera>,
    session: Session,
) -> impl Responder {
    let bugs = sqlx::query_as!(BugReport, "SELECT bug_id, assignee_id, project_id, bug_title, bug_description, bug_severity, report_time FROM bugreport")
        .fetch_all(_pool.get_ref())
        .await;
    let users = sqlx::query_as!(User, "SELECT * FROM users")
        .fetch_all(_pool.get_ref())
        .await;
    match (bugs, users) {
        (Ok(bugs), Ok(users)) => {
            let mut ctx = Context::new();
            ctx.insert("bugs", &bugs);
            ctx.insert("users", &users);
            let current_user_role = session.get::<String>("role").unwrap_or(None).unwrap_or_default();
            let current_user_id = session.get::<i64>("user_id").unwrap_or(None).unwrap_or_default();
            ctx.insert("current_user_role", &current_user_role);
            ctx.insert("current_user_id", &current_user_id);
            tmpl.render("bug_assign_form.html", &ctx)
                .map(|html| HttpResponse::Ok().content_type("text/html").body(html))
                .unwrap_or_else(|e| {
                    eprint!("Template error: {}", e);
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
    let hashed_password = hash_password(&req.password);

    // Check if any users exist
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(db.get_ref())
        .await
        .unwrap_or((0,));

    let role = if user_count.0 == 0 {
        "admin".to_string()
    } else {
        match req.role.as_deref() {
            Some("qa") => "qa".to_string(),
            _ => "developer".to_string(), // default to developer if not specified or invalid
        }
    };

    let result = sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        "#,
        req.username,
        hashed_password,
        role
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
    let user = match sqlx::query_as!(
        User,
        r#"SELECT id, username, password_hash, role FROM users WHERE username = ?"#,
        req.username
    )
    .fetch_optional(db.get_ref())
    .await {
        Ok(user) => user,
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    match user {
        Some(user) => {
            if verify_password(&req.password, &user.password_hash) {
                session.insert("username", &user.username).unwrap();
                session.insert("role", &user.role).unwrap();
                session.insert("user_id", user.id).unwrap();

                HttpResponse::Ok().json(LoginResponse {
                    status: "success".to_string(),
                    message: Some("Login successful".to_string()),
                })
            } else {
                HttpResponse::Unauthorized().json(LoginResponse {
                    status: "failure".to_string(),
                    message: Some("Invalid credentials".to_string()),
                })
            }
        }
        None => HttpResponse::Unauthorized().json(LoginResponse {
            status: "failure".to_string(),
            message: Some("User not found".to_string()),
        }),
    }
}

#[get("/login")]
pub async fn login_page(tmpl: web::Data<tera::Tera>) -> impl Responder {
    let ctx = tera::Context::new();
    match tmpl.render("login.html", &ctx){
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html")
            .body(html),
        Err(err) => {
            eprint!("Template render error: {:?}",err);
            HttpResponse::InternalServerError().body("Template error")
        }
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
