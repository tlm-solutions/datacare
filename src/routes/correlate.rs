use std::collections::HashMap;

use crate::routes::auth::fetch_user;
use crate::routes::trekkie::utils::correlate_single_run;
use crate::routes::ServerError;
use crate::DbPool;

use diesel::upsert::on_constraint;
use tlms::locations::{
    InsertTransmissionLocation, InsertTransmissionLocationRaw, TransmissionLocationRaw,
};
use tlms::trekkie::TrekkieRun;

use actix_identity::Identity;
use actix_web::post;
use actix_web::{web, HttpRequest};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt;
use log::error;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Model to correlate runs for given user. If get_result is true, the stops.json also returned
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct CorrelatePlease {
    /// ID of run to correlate
    pub run_id: Uuid,
    /// Optional value for the corr_window
    pub corr_window: Option<i64>,
}

/// Response to explicit correlate request
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct CorrelateResponse {
    pub success: bool,
    pub new_raw_transmission_locations: i64,
}

/// Request to correlate all runs
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct CorrelateAllRequest {
    /// optional correlation window
    pub corr_window: Option<i64>,
    /// if this flag is set, even already correlated trekkie runs are re-correlated again. Useful
    /// on lofi logic updates.
    pub ignore_correlated_flag: bool,
}

/// Request to correlate all runs
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct UpdateAllRequest {
    /// if this flag is set old correlated positions are thrown away
    pub delete_old: bool,
}

/// Request to update all transmission locations
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct UpdateAllLocationsResponse {
    /// amount of upserted positions
    rows_affected: usize,
}

/// This endpoint takes all the transmission_locaions_raw, and dedupes them into the transmission
/// locations. If location exists, updates it, if not: inserts it. Needless to say: this is
/// extremely expensive endpoint, so requires admin privelege.
#[utoipa::path(
    post,
    path = "/locations/update_all",
    responses(
        (status = 200, description = "Correlation Successful", body = UpdateAllLocationsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Interal Error"),
        (status = 501, description = "Not Implemented"),
    ),
)]
#[post("/locations/update_all")]
pub async fn update_all_transmission_locations(
    pool: web::Data<DbPool>,
    user: Identity,
    _req: HttpRequest,
    update_request: web::Json<UpdateAllRequest>,
) -> Result<web::Json<UpdateAllLocationsResponse>, ServerError> {
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

    if !req_user.is_admin() {
        error!(
            "User {usr} is not admin, and requested to update all positions!",
            usr = req_user.user.id
        );
        return Err(ServerError::Forbidden);
    }

    // Load the raw runs wholesale
    use tlms::schema::r09_transmission_locations_raw::dsl::r09_transmission_locations_raw;
    let raw_locs: Vec<TransmissionLocationRaw> =
        match r09_transmission_locations_raw.load(&mut database_connection) {
            Ok(l) => l,
            Err(e) => {
                error!("while trying to fetch r09_transmission_locations_raw: {e}");
                return Err(ServerError::InternalError);
            }
        };

    // group the locations by region/location
    let mut raw_loc_groups: HashMap<(i64, i32), Vec<TransmissionLocationRaw>> = HashMap::new();
    for i in raw_locs {
        raw_loc_groups
            .entry((i.region, i.reporting_point))
            .or_insert(Vec::new())
            .push(i);
    }

    // convert raw locations to deduped ones
    let ins_deduped_locs: Vec<InsertTransmissionLocation> = raw_loc_groups
        .values()
        .map(|v| InsertTransmissionLocation::try_from_raw(v.clone()))
        .filter_map(|res| {
            res.map_err(|_e| {
                error!("Error while deduping raw locations into production ones!");
            })
            .ok()
        })
        .collect();

    // upsert the deduped locations
    use diesel::pg::upsert::excluded;
    use tlms::schema::r09_transmission_locations::dsl::r09_transmission_locations;
    use tlms::schema::r09_transmission_locations::lat;
    use tlms::schema::r09_transmission_locations::lon;

    if update_request.delete_old {
        match diesel::delete(r09_transmission_locations).execute(&mut database_connection) {
            Ok(_) => {}
            Err(e) => {
                error!("while trying to delete transmission locations: {e}");
                return Err(ServerError::InternalError);
            }
        };
    }

    let rows_affected = match diesel::insert_into(r09_transmission_locations)
        .values(&ins_deduped_locs)
        .on_conflict(on_constraint(
            tlms::locations::REGION_POSITION_UNIQUE_CONSTRAINT,
        ))
        .do_update()
        .set((lat.eq(excluded(lat)), lon.eq(excluded(lon))))
        .execute(&mut database_connection)
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("While trying to upsert into r09_transmission_locations: {e}");
            return Err(ServerError::InternalError);
        }
    };

    Ok(web::Json(UpdateAllLocationsResponse { rows_affected }))
}

/// This endpoint correlates all the runs. If appropriate flag is set, ignores "correlated" flag,
/// and correlates **everything**.
#[utoipa::path(
    post,
    path = "/run/correlate_all",
    responses(
        (status = 200, description = "Correlation Successful", body = CorrelateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Interal Error"),
        (status = 501, description = "Not Implemented"),
    ),
)]
#[post("/run/correlate_all")]
pub async fn correlate_all(
    pool: web::Data<DbPool>,
    user: Identity,
    _req: HttpRequest,
    corr_request: web::Json<CorrelateAllRequest>,
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
    if !req_user.is_admin() {
        error!(
            "User {usr} is not admin, and requested to update all positions!",
            usr = req_user.user.id
        );
        return Err(ServerError::Forbidden);
    }

    // get the trekkie runs
    use tlms::schema::trekkie_runs::correlated as trekkie_corr;
    use tlms::schema::trekkie_runs::dsl::trekkie_runs;
    let trekkie_db_result = if corr_request.ignore_correlated_flag {
        // get all the runs
        trekkie_runs.load::<TrekkieRun>(&mut database_connection)
    } else {
        // get only uncorrelated runs
        trekkie_runs
            .filter(trekkie_corr.eq(false))
            .load::<TrekkieRun>(&mut database_connection)
    };

    let trekkie_loaded_runs: Vec<TrekkieRun> = match trekkie_db_result {
        Ok(val) => val,
        Err(e) => {
            error!("While trying to get trekkie runs: {e}");
            return Err(ServerError::InternalError);
        }
    };

    let corr_window = match corr_request.corr_window {
        Some(x) => x,
        None => lofi::correlate::DEFAULT_CORRELATION_WINDOW,
    };

    let correlated_results = trekkie_loaded_runs
        .iter()
        .map(|r| correlate_single_run(r.clone(), &pool, corr_window))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    let insert_locs: Vec<InsertTransmissionLocationRaw> = correlated_results
        .into_iter()
        .filter_map(|res| {
            res.map_err(|e| {
                error!("Error while correlating a run: {e}!");
            })
            .ok()
        })
        .flatten()
        .collect();

    // if we ignoring correlate flag, we can safely delete all raw locations
    use tlms::schema::r09_transmission_locations_raw::dsl::r09_transmission_locations_raw;

    if corr_request.ignore_correlated_flag {
        match diesel::delete(r09_transmission_locations_raw).execute(&mut database_connection) {
            Ok(_) => {}
            Err(e) => {
                error!("while trying to delete raw transmission locations: {e}");
                return Err(ServerError::InternalError);
            }
        };
    }

    // and here we can happily insert resulting locations
    let affected_rows = match diesel::insert_into(r09_transmission_locations_raw)
        .values(&insert_locs)
        .execute(&mut database_connection)
    {
        Ok(r) => r,
        Err(e) => {
            error!("while trying to insert raw transmission postions: {e}");
            return Err(ServerError::InternalError);
        }
    };

    Ok(web::Json(CorrelateResponse {
        success: true,
        new_raw_transmission_locations: affected_rows as i64,
    }))
}
