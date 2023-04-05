use crate::{
    routes::auth::fetch_user, routes::trekkie::utils::correlate_single_run, routes::ServerError,
    DbPool,
};
use tlms::{
    locations::TransmissionLocationRaw,
    schema::r09_transmission_locations_raw::dsl::r09_transmission_locations_raw,
    trekkie::TrekkieRun,
};

use actix_identity::Identity;
use actix_web::{web, HttpRequest};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};
use serde::{Deserialize, Serialize};

use log::{error, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

/// Model to correlate runs for given user. If get_result is true, the stops.json also returned
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct CorrelationRequest {
    /// Optional value for the corr_window
    pub corr_window: i64,
}

/// Response to explicit correlate request
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct CorrelateResponse {
    pub success: bool,
    pub new_raw_transmission_locations: i64,
}

/// will return a list of all trekkie_runs
#[utoipa::path(
    get,
    path = "/trekkie/{id}/correlate",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Trekkie Run identifier")
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "returning list of correlated telegram positions", body = Vec<TransmissionLocationRaw>),
        (status = 403, description = "User doesn't have correct permissions"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn trekkie_correlate_get(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
) -> Result<web::Json<Vec<TransmissionLocationRaw>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // fetch user session
    let session_user = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::trekkie_runs::dsl::trekkie_runs;
    use tlms::schema::trekkie_runs::id;
    //use tlms::schema::r09_transmission_locations_raw::dsl::r09_transmission_locations_raw;
    use tlms::schema::r09_transmission_locations_raw::trekkie_run;

    let associated_run = match trekkie_runs
        .filter(id.eq(path.0))
        .first::<TrekkieRun>(&mut database_connection)
    {
        Ok(result) => result,
        Err(e) => {
            error!("database error {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    if !(session_user.is_admin() || associated_run.owner == session_user.user.id) {
        return Err(ServerError::Forbidden);
    }

    match r09_transmission_locations_raw
        .filter(trekkie_run.eq(path.0))
        .load::<TransmissionLocationRaw>(&mut database_connection)
    {
        Ok(points_list) => Ok(web::Json(points_list)),
        Err(e) => {
            error!("database error while listing trekkie_runs {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Private function that does the dirty correlation work.
#[utoipa::path(
    post,
    path = "/trekkie/{id}/correlate",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Trekkie Run identifier")
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "Correlation Successful", body = CorrelateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Interal Error"),
        (status = 501, description = "Not Implemented"),
    ),
)]
pub async fn correlate_run(
    pool: web::Data<DbPool>,
    user: Identity,
    _req: HttpRequest,
    path: web::Path<(Uuid,)>,
    corr_request: web::Json<Option<CorrelationRequest>>,
) -> Result<web::Json<CorrelateResponse>, ServerError> {
    // get connection from the pool
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // Get the user and privileges
    let req_user = fetch_user(user, &mut database_connection)?;

    use tlms::schema::trekkie_runs::dsl::trekkie_runs;
    use tlms::schema::trekkie_runs::id as run_id;
    let run: TrekkieRun = match trekkie_runs
        .filter(run_id.eq(path.0))
        .first(&mut database_connection)
    {
        Ok(r) => r,
        Err(e) => {
            error!("While trying to query for run {}: {e}", path.0);
            return Err(ServerError::InternalError);
        }
    };

    if run.owner != req_user.user.id && !req_user.is_admin() {
        warn!(
            "naughty boy: user {} tried to access run owned by {}!",
            req_user.user.id, run.owner
        );
        return Err(ServerError::Forbidden);
    }

    if run.correlated {
        info!(
            "User {usr} requested to correlate trekkie run {r}, which is already correlated.",
            usr = req_user.user.id,
            r = run.id
        );
        warn!("Run already correlated. Correlation step skipped.");

        return Ok(web::Json(CorrelateResponse {
            success: true,
            new_raw_transmission_locations: 0,
        }));
    }

    let corr_window = match corr_request.into_inner() {
        Some(x) => x.corr_window,
        None => lofi::correlate::DEFAULT_CORRELATION_WINDOW,
    };

    // corrrelate
    let locs = match correlate_single_run(run, &pool, corr_window).await {
        Ok(l) => l,
        Err(e) => {
            error!("while trying to correlate run: {e}");
            return Err(e);
        }
    };

    // Insert raw transmission locations into the DB
    use tlms::schema::r09_transmission_locations_raw::dsl::r09_transmission_locations_raw;
    let updated_rows = match diesel::insert_into(r09_transmission_locations_raw)
        .values(&locs)
        .execute(&mut database_connection)
    {
        Ok(r) => r,
        Err(_) => return Err(ServerError::InternalError),
    };

    // Update correlated flag in the trekkie_runs db
    use tlms::schema::trekkie_runs::correlated as trekkie_corr_flag;
    match diesel::update(trekkie_runs)
        .filter(run_id.eq(path.0))
        .set(trekkie_corr_flag.eq(true))
        .execute(&mut database_connection)
    {
        Ok(ok) => ok,
        Err(e) => {
            error!("while trying to set `correlated` flag in trekkie_runs: {e:?}");
            return Err(ServerError::InternalError);
        }
    };

    Ok(web::Json(CorrelateResponse {
        success: true,
        new_raw_transmission_locations: updated_rows as i64,
    }))
}
