use actix_web::{App, HttpServer, web};
use actix_web_httpauth::middleware::HttpAuthentication;
use dotenvy::dotenv;
use tera::Tera;
use sqlx::sqlite::SqlitePool;

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

    HttpServer::new(move || {
        let auth = HttpAuthentication::bearer(auth_middleware::validator);
        
        App::new()
            .app_data(web::Data::new(tera.clone()))
            .app_data(web::Data::new(db_pool.clone()))
            .service(
                web::scope("/api")
                    .configure(handlers::config)
                    .wrap(auth)
            )
            .service(
                web::scope("")
                    .service(handlers::register)
                    .service(handlers::login)
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}