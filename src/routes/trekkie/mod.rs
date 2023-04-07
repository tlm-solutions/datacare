pub mod correlate;
pub mod utils;

use crate::{
    routes::auth::fetch_user,
    routes::{ListRequest, ListResponse, ServerError},
    DbPool,
};
use tlms::trekkie::TrekkieRun;
use tlms::{locations::gps::GpsPoint, schema::trekkie_runs::dsl::trekkie_runs};

use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};

use chrono::NaiveDateTime;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// edits a region
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct EditTrekkieRuns {
    pub start_time: NaiveDateTime,
    pub end_time: NaiveDateTime,
    pub line: i32,
    pub run: i32,
    pub region: i32,
}

/// struct for sending out very smol gps point in json
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct MiniGPS {
    pub lat: f64,
    pub lon: f64,
    pub time: NaiveDateTime,
}

/// gps detail information
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct TrekkieRunInfo {
    /// trekkie run
    #[serde(flatten)]
    pub trekkie_run: TrekkieRun,

    /// list of gps points
    pub gps: Vec<MiniGPS>,
}

/// will return a list of all trekkie_runs
#[utoipa::path(
    get,
    path = "/trekkie",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Trekkie Run identifier")
    ),
    request_body(
        content = Option<ListRequest>,
        description = "information for pageination of trekkie runs",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "list of trekkie runs", body = Vec<TrekkieRun>),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn trekkie_run_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    optional_params: Option<web::Form<ListRequest>>,
) -> Result<web::Json<ListResponse<TrekkieRun>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // fetch user session
    let session_user = fetch_user(identity, &mut database_connection)?;

    // gets the query parameters out of the request
    let query_params: ListRequest = match optional_params {
        Some(request) => request.into_inner(),
        None => ListRequest::default(),
    };

    if session_user.is_admin() {
        let count: i64 = match trekkie_runs.count().get_result(&mut database_connection) {
            Ok(result) => result,
            Err(e) => {
                error!("database error {:?}", e);
                return Err(ServerError::InternalError);
            }
        };

        match trekkie_runs
            .limit(query_params.limit)
            .offset(query_params.offset)
            .order(tlms::schema::trekkie_runs::line)
            .load::<TrekkieRun>(&mut database_connection)
        {
            Ok(trekkie_list) => Ok(web::Json(ListResponse {
                count,
                elements: trekkie_list,
            })),
            Err(e) => {
                error!("database error while listing trekkie_runs {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    } else {
        let count: i64 = match trekkie_runs
            .filter(owner.eq(session_user.user.id))
            .count()
            .get_result(&mut database_connection)
        {
            Ok(result) => result,
            Err(e) => {
                error!("database error {:?}", e);
                return Err(ServerError::InternalError);
            }
        };

        use tlms::schema::trekkie_runs::dsl::owner;
        match trekkie_runs
            .filter(owner.eq(session_user.user.id))
            .limit(query_params.limit)
            .offset(query_params.offset)
            .order(tlms::schema::trekkie_runs::line)
            .load::<TrekkieRun>(&mut database_connection)
        {
            Ok(trekkie_list) => Ok(web::Json(ListResponse {
                count,
                elements: trekkie_list,
            })),
            Err(e) => {
                error!("database error while listing trekkie_runs {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    }
}

/// Will overwrite a trekkie list with the new data on success it will return the updated
/// trekkie_runs .
#[utoipa::path(
    put,
    path = "/trekkie/{id}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Trekkie Run identifier")
    ),
    request_body(
        content = EditTrekkieRuns,
        description = "Overwritting start / end times, line and run.",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "successfully edited trekkie run", body = TrekkieRun),
        (status = 400, description = "invalid input data"),
        (status = 403, description = "User doesn't have correct permissions"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn trekkie_run_update(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
    request: web::Json<EditTrekkieRuns>,
) -> Result<web::Json<TrekkieRun>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let user_session = fetch_user(identity, &mut database_connection)?;

    if !user_session.is_admin() {
        return Err(ServerError::Forbidden);
    }

    warn!("updating trekkie runs {:?}", &request);

    use tlms::schema::trekkie_runs::{end_time, id as trekkie_id, line, run, start_time};

    // TODO add checks
    // - start earlier then end
    // - start newer then prev start
    // - end older then prev end
    //

    match diesel::update(trekkie_runs.filter(trekkie_id.eq(path.0)))
        .set((
            start_time.eq(request.start_time),
            end_time.eq(request.end_time),
            line.eq(request.line),
            run.eq(request.run),
        ))
        .get_result::<TrekkieRun>(&mut database_connection)
    {
        Ok(return_trekkie_run) => Ok(web::Json(return_trekkie_run)),
        Err(e) => {
            error!("cannot update trekkie run because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Will delete requested trekkie run
#[utoipa::path(
    delete,
    path = "/trekkie/{id}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Trekkie Run identifier")
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "successfully deleted trekkie run"),
        (status = 400, description = "invalid input data"),
        (status = 403, description = "User doesn't have correct permissions"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn trekkie_run_delete(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let user_session = fetch_user(identity, &mut database_connection)?;

    if !user_session.is_admin() {
        return Err(ServerError::Forbidden);
    }

    use tlms::schema::trekkie_runs::id as trekkie_id;

    match diesel::delete(trekkie_runs.filter(trekkie_id.eq(path.0)))
        .get_result::<TrekkieRun>(&mut database_connection)
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => {
            error!("cannot delete trekkie run because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Will return information about the trekkie run like the list of gps positions
#[utoipa::path(
    get,
    path = "/trekkie/{id}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Trekkie Run identifier")
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "successfully return trekkie run information"),
        (status = 400, description = "invalid input data"),
        (status = 403, description = "User doesn't have correct permissions"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn trekkie_run_info(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
) -> Result<web::Json<TrekkieRunInfo>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let user_session = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::gps_points::dsl::gps_points;
    use tlms::schema::gps_points::trekkie_run as trekkie_id_gps;
    use tlms::schema::trekkie_runs::id as trekkie_id;

    let trekkie_run = match trekkie_runs
        .filter(trekkie_id.eq(path.0))
        .first::<TrekkieRun>(&mut database_connection)
    {
        Ok(trekkie_run) => trekkie_run,
        Err(e) => {
            error!("database error while listing trekkie_runs {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    if !(user_session.is_admin() || trekkie_run.owner == user_session.user.id) {
        return Err(ServerError::Forbidden);
    }

    let gps = match gps_points
        .filter(trekkie_id_gps.eq(path.0))
        .load::<GpsPoint>(&mut database_connection)
    {
        Ok(points) => points
            .iter()
            .map(|x| MiniGPS {
                lat: x.lat,
                lon: x.lon,
                time: x.timestamp,
            })
            .collect(),
        Err(e) => {
            error!("database error while listing trekkie_runs {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    Ok(web::Json(TrekkieRunInfo { trekkie_run, gps }))
}
