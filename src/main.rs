#[deny(missing_docs)]
mod routes;
mod structs;

use actix_identity::config::LogoutBehaviour;
use structs::Args;

use clap::Parser;
use log::{debug, info};

use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::PgConnection;

use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::storage::RedisActorSessionStore;
use actix_session::{config::BrowserSession, SessionMiddleware};
use actix_web::{cookie::Key, middleware::Logger, web, App, HttpServer};
use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};

use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use std::env;
use std::fs;
use std::time::Duration;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub fn create_db_pool() -> DbPool {
    let default_postgres_host = String::from("localhost");
    let default_postgres_port = String::from("5432");
    let default_postgres_user = String::from("datacare");
    let default_postgres_database = String::from("tlms");
    let default_postgres_pw_path = String::from("/run/secrets/postgres_password");

    let password_path =
        env::var("DATACARE_POSTGRES_PASSWORD_PATH").unwrap_or(default_postgres_pw_path);
    let password = fs::read_to_string(password_path)
        .map_err(|e| eprintln!("While trying to read password file: {:?}", e))
        .expect("cannot read password file!");

    let database_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        env::var("DATACARE_POSTGRES_USER").unwrap_or(default_postgres_user),
        password,
        env::var("DATACARE_POSTGRES_HOST").unwrap_or(default_postgres_host),
        env::var("DATACARE_POSTGRES_PORT").unwrap_or(default_postgres_port),
        env::var("DATACARE_POSTGRES_DATABASE").unwrap_or(default_postgres_database)
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
        std::env::var("DATACARE_REDIS_HOST").unwrap_or(default_redis_host),
        std::env::var("DATACARE_REDIS_PORT").unwrap_or(default_redis_port)
    )
}

pub fn get_prometheus() -> PrometheusMetrics {
    PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .build()
        .expect("Failed to create prometheus metric endpoint")
}

pub fn get_domain() -> Option<String> {
    std::env::var("DATACARE_COOKIE_DOMAIN").ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let args = Args::parse();

    if args.swagger {
        println!("{}", routes::ApiDoc::openapi().to_pretty_json().unwrap());
        return Ok(());
    }

    // 3 days with no interaction and the cookie is invalidated
    const COOKIE_VALID_TIME: u64 = 60 * 60 * 24 * 3;

    info!("Starting Data Collection Server ... ");
    let host = args.host.as_str();
    let port = args.port;

    debug!("Listening on: {}:{}", host, port);
    let connection_pool = web::Data::new(create_db_pool());
    let secret_key = Key::generate();
    let prometheus = get_prometheus();

    HttpServer::new(move || {
        // TODO: this needs to be configured
        let cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .allow_any_origin();

        App::new()
            .wrap(cors)
            .wrap(prometheus.clone())
            .wrap(
                IdentityMiddleware::builder()
                    .logout_behaviour(LogoutBehaviour::PurgeSession)
                    .visit_deadline(Some(Duration::from_secs(COOKIE_VALID_TIME)))
                    .build(),
            )
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(
                    RedisActorSessionStore::new(get_redis_uri()),
                    secret_key.clone(),
                )
                .cookie_domain(get_domain())
                .cookie_secure(true)
                .session_lifecycle(BrowserSession::default())
                .build(),
            )
            .app_data(connection_pool.clone())
            .service(
                web::scope("/v1")
                    .service(routes::auth::auth_info)
                    .service(routes::auth::user_login)
                    .service(routes::auth::user_logout)
                    .service(routes::user::user_register)
                    .service(routes::user::user_list)
                    .service(routes::user::user_update)
                    .service(routes::user::user_delete)
                    .service(routes::user::user_info)
                    .service(routes::user::user_get_roles)
                    .service(routes::user::user_set_roles)
                    .service(routes::region::region_list)
                    .service(routes::region::region_create)
                    .service(routes::region::region_info)
                    .service(routes::region::region_delete)
                    .service(routes::region::region_update)
                    .service(routes::region::region_list_reporting_point_v1)
                    .service(routes::region::region_list_reporting_point_v2)
                    .service(routes::region::region_get_reporting_point)
                    .service(routes::station::station_list)
                    .service(routes::station::station_info)
                    .service(routes::station::station_create)
                    .service(routes::station::station_update)
                    .service(routes::station::station_delete)
                    .service(routes::station::station_approve)
                    .service(routes::trekkie::trekkie_run_list)
                    .service(routes::trekkie::trekkie_run_info)
                    .service(routes::trekkie::trekkie_run_delete)
                    .service(routes::trekkie::trekkie_run_update)
                    .service(routes::trekkie::correlate::trekkie_correlate_get)
                    .service(routes::trekkie::correlate::correlate_run)
                    .service(routes::organization::orga_list)
                    .service(routes::organization::orga_create)
                    .service(routes::organization::organization_info)
                    .service(routes::organization::organization_delete)
                    .service(routes::organization::organization_update)
                    .service(routes::correlate::correlate_all)
                    .service(routes::correlate::update_all_transmission_locations),
            )
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-doc/openapi.json", routes::ApiDoc::openapi()),
            )
    })
    .bind((host, port))?
    .run()
    .await
}
