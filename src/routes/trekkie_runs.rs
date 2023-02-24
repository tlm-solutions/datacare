use crate::{
    routes::auth::fetch_user,
    routes::{ListRequest, ListResponse, ServerError},
    DbPool,
};
use tlms::schema::trekkie_runs::dsl::trekkie_runs;
use tlms::trekkie::TrekkieRun;

use actix_identity::Identity;
use actix_web::{web, HttpRequest};
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
    pub id: Uuid,
    pub start_time: NaiveDateTime,
    pub end_time: NaiveDateTime,
    pub line: i32,
    pub run: i32,
    pub region: i32,
}

/// will return a list of all trekkie_runs
#[utoipa::path(
    get,
    path = "/trekkie",
    responses(
        (status = 200, description = "list of trekkie runs", body = Vec<TrekkieRun>),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn trekkie_run_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    optional_params: Option<web::Form<ListRequest>>,
) -> Result<web::Json<ListResponse<TrekkieRun>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // gets the query parameters out of the request
    let query_params: ListRequest = match optional_params {
        Some(request) => request.into_inner(),
        None => ListRequest::default(),
    };

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
}

/// Will overwrite a trekkie list with the new data on success it will return the updated
/// trekkie_runs .
#[utoipa::path(
    put,
    path = "/trekkie/{id}",
    responses(
        (status = 200, description = "successfully edited trekkie run", body = TrekkieRun),
        (status = 400, description = "invalid input data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn trekkie_run_update(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(i64,)>,
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
        return Err(ServerError::Unauthorized);
    }

    warn!("updating trekkie runs {:?}", &request);

    use tlms::schema::trekkie_runs::{end_time, id as trekkie_id, line, run, start_time};

    match diesel::update(trekkie_runs.filter(trekkie_id.eq(path.0)))
        .set((
            start_time.eq(request.start_time.clone()),
            end_time.eq(request.end_time.clone()),
            line.eq(request.line.clone()),
            run.eq(request.run.clone()),
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
