use crate::{routes::user::fetch_user, routes::ServerError, DbPool};
use dump_dvb::management::{InsertRegion, Region};

use actix_identity::Identity;
use actix_web::{web, HttpRequest};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};
use log::{error, warn};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// returnes the id of the newly created region
#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegionCreationResponse {
    pub id: usize,
}

/// holds all the necessary information that are required to create a new region
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateRegionRequest {
    pub name: String,
    pub transport_company: String,
    pub regional_company: Option<String>,
    pub frequency: Option<i64>,
    pub r09_type: Option<i32>,
    pub encoding: Option<i32>,
}

/// edits a region
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct EditRegionRequest {
    pub id: i64,
    pub name: String,
    pub transport_company: String,
    pub regional_company: Option<String>,
    pub frequency: Option<i64>,
    pub r09_type: Option<i32>,
    pub encoding: Option<i32>,
}

/// will create a region if the currently authenticated user is an admin
#[utoipa::path(
    post,
    path = "/region/create",
    responses(
        (status = 200, description = "region was successfully created", body = crate::routes::RegionCreationResponse),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn region_create(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    request: web::Json<CreateRegionRequest>,
) -> Result<web::Json<RegionCreationResponse>, ServerError> {
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

    use dump_dvb::schema::regions::dsl::regions;

    match diesel::insert_into(regions)
        .values(&InsertRegion {
            id: None,
            name: request.name.clone(),
            transport_company: request.transport_company.clone(),
            regional_company: request.regional_company.clone(),
            frequency: request.frequency,
            r09_type: request.r09_type,
            encoding: request.encoding,
        })
        .execute(&mut database_connection)
    {
        Err(e) => {
            error!("while trying to insert region {:?}", e);
            Err(ServerError::BadClientData)
        }
        Ok(value) => Ok(web::Json(RegionCreationResponse { id: value })),
    }
}

/// will return a list of all regions
#[utoipa::path(
    get,
    path = "/region/list",
    responses(
        (status = 200, description = "list of regions", body = Vec<Region>),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn region_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
) -> Result<web::Json<Vec<Region>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use dump_dvb::schema::regions::dsl::regions;

    match regions.load::<Region>(&mut database_connection) {
        Ok(region_list) => Ok(web::Json(region_list)),
        Err(_) => Err(ServerError::BadClientData),
    }
}

/// will overwritte the specified region
#[utoipa::path(
    put,
    path = "/region/update",
    responses(
        (status = 200, description = "successfully edited region", body = Region),
        (status = 400, description = "invalid input data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn region_update(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    request: web::Json<EditRegionRequest>,
) -> Result<web::Json<Region>, ServerError> {
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

    warn!("updating region {:?}", &request);

    use dump_dvb::schema::regions::dsl::regions;
    use dump_dvb::schema::regions::{
        encoding, frequency, id, name, r09_type, regional_company, transport_company,
    };

    match diesel::update(regions.filter(id.eq(request.id)))
        .set((
            name.eq(request.name.clone()),
            transport_company.eq(request.transport_company.clone()),
            regional_company.eq(request.regional_company.clone()),
            frequency.eq(request.frequency),
            r09_type.eq(request.r09_type),
            encoding.eq(request.encoding),
        ))
        .get_result::<Region>(&mut database_connection)
    {
        Ok(return_region) => Ok(web::Json(return_region)),
        Err(e) => {
            error!("cannot deactivate user because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}
