use crate::{
    routes::auth::fetch_user,
    routes::{ListRequest, ListResponse, ServerError},
    DbPool,
};
use tlms::{
    trekkie::TrekkieRun,
    locations::{TransmissionLocation, TransmissionLocationRaw}, 
    schema::{r09_transmission_locations::dsl::r09_transmission_locations,
            r09_transmission_locations_raw::dsl::r09_transmission_locations_raw},
};

use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};

use log::{error, warn};
use utoipa::ToSchema;
use uuid::Uuid;

/// will return a list of all trekkie_runs
#[utoipa::path(
    get,
    path = "/trekkie/{id}/correlate",
    responses(
        (status = 200, description = "returning list of correlated telegram positions", body = Vec<TransmissionLocationRaw>),
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

    let associated_run = match trekkie_runs.filter(id.eq(path.0)).first::<TrekkieRun>(&mut database_connection) {
        Ok(result) => result,
        Err(e) => {
            error!("database error {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    if !(session_user.is_admin() ||  associated_run.owner == session_user.user.id) {
        return Err(ServerError::Forbidden);
    }


    match r09_transmission_locations_raw
            .filter(trekkie_run.eq(path.0))
            .load::<TransmissionLocationRaw>(&mut database_connection)
        {
            Ok(points_List) => Ok(web::Json(points_List)),
            Err(e) => {
                error!("database error while listing trekkie_runs {:?}", e);
                Err(ServerError::InternalError)
            }
     }
} 

