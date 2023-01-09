mod routes;
mod structs;

use structs::Args;

use clap::Parser;
use log::{debug, info};

use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::PgConnection;

use actix_web::{cookie::Key, middleware::Logger, web, App, HttpServer};

use actix_identity::IdentityMiddleware;
use actix_session::storage::RedisActorSessionStore;
use actix_session::SessionMiddleware;

use utoipa::OpenApi;

use std::env;
use std::fs;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub fn create_db_pool() -> DbPool {
    let default_postgres_host = String::from("localhost:5433");
    let default_postgres_port = String::from("5432");
    let default_postgres_pw_path = String::from("/run/secrets/postgres_password");

    let password_path = env::var("POSTGRES_PASSWORD_PATH").unwrap_or(default_postgres_pw_path);
    let password = fs::read_to_string(password_path).expect("cannot read password file!");

    let database_url = format!(
        "postgres://dvbdump:{}@{}:{}/dvbdump",
        password,
        env::var("POSTGRES_HOST").unwrap_or(default_postgres_host),
        env::var("POSTGRES_PORT").unwrap_or(default_postgres_port)
    );

    debug!("Connecting to postgres database {}", &database_url);
    let manager = ConnectionManager::<PgConnection>::new(database_url);

    Pool::new(manager).expect("Failed to create pool.")
}

pub fn get_redis_uri() -> String {
    let default_redis_port = "6379".to_string();
    let default_redis_host = "127.0.0.1".to_string();

    format!(
        "{}:{}",
        std::env::var("REDIS_HOST").unwrap_or(default_redis_host),
        std::env::var("REDIS_PORT").unwrap_or(default_redis_port)
    )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let args = Args::parse();

    if args.swagger {
        println!("{}", routes::ApiDoc::openapi().to_pretty_json().unwrap());
        return Ok(());
    }

    info!("Starting Data Collection Server ... ");
    let host = args.host.as_str();
    let port = args.port;
    debug!("Listening on: {}:{}", host, port);

    let connection_pool = web::Data::new(create_db_pool());
    let secret_key = Key::generate();
    HttpServer::new(move || {
        App::new()
            .wrap(IdentityMiddleware::default())
            .wrap(Logger::default())
            .wrap(SessionMiddleware::new(
                RedisActorSessionStore::new(get_redis_uri()),
                secret_key.clone(),
            ))
            .app_data(connection_pool.clone())
            .route(
                "/auth/register",
                web::post().to(routes::user::user_register),
            )
            .route("/auth/login", web::post().to(routes::auth::user_login))
            .route("/auth/logout", web::post().to(routes::auth::user_logout))
            .route("/auth", web::get().to(routes::auth::auth_info))
            .route("/user", web::get().to(routes::user::user_list))
            .route("/user/{id}", web::put().to(routes::user::user_update))
            .route("/user/{id}", web::delete().to(routes::user::user_delete))
            .route("/user/{id}", web::get().to(routes::user::user_info))
            .route("/region", web::post().to(routes::region::region_create))
            .route("/region", web::get().to(routes::region::region_list))
            .route("/region/{id}", web::put().to(routes::region::region_update))
            .route("/region/{id}", web::get().to(routes::region::region_info))
            .route(
                "/region/{id}",
                web::delete().to(routes::region::region_delete),
            )
            .route("/station", web::post().to(routes::station::station_create))
            .route("/station", web::get().to(routes::station::station_list))
            .route(
                "/station/{id}",
                web::get().to(routes::station::station_info),
            )
            .route(
                "/station/{id}",
                web::delete().to(routes::station::station_delete),
            )
            .route(
                "/station/{id}",
                web::put().to(routes::station::station_update),
            )
            .route(
                "/station/{id}/approve",
                web::post().to(routes::station::station_approve),
            )
    })
    .bind((host, port))?
    .run()
    .await
}
