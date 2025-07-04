use sqlx::{Pool, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;

pub async fn init_db() -> Pool<Sqlite> {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("DB connection failed")
}