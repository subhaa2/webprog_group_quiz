use actix_web::{App, HttpServer, web};
use dotenvy::dotenv;
use tera::Tera;
use sqlx::sqlite::SqlitePool;
use actix_session::config::CookieContentSecurity;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;

mod auth;
mod auth_middleware;
mod db;
mod handlers;
mod models;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let tera = Tera::new("templates/**/*").unwrap();
    let db_pool = db::init_db().await;

    println!("Server running at http://127.0.0.1:8080");

    let secret_key = Key::generate();
    HttpServer::new(move || {
        
        App::new()
            .app_data(web::Data::new(tera.clone()))
            .app_data(web::Data::new(db_pool.clone()))
            .wrap(SessionMiddleware::new(
            CookieSessionStore::default(),
            secret_key.clone(),
            ))
            .service(
                web::scope("/api")
                    .configure(handlers::config)
            )
            .service(
                web::scope("")
                    .service(handlers::register)
                    .service(handlers::login)
                    .service(handlers::whoami)
            )

    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}