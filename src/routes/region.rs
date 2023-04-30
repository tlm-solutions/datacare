use crate::{
    routes::auth::fetch_user,
    routes::{ListRequest, ListResponse, ServerError, Stats},
    DbPool,
};

use tlms::locations::region::{InsertRegion, Region};
use tlms::locations::{TransmissionLocation, TransmissionLocationRaw};
use tlms::management::Station;
use tlms::schema::regions::dsl::regions;
use tlms::telegrams::r09::R09Type;

use actix_identity::Identity;
use actix_web::{delete, get, post, put};
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};

use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Response with the id of the newly created region
#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegionCreationResponse {
    pub id: usize,
}

/// Request to create a new region
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateRegionRequest {
    /// Region name
    pub name: String,
    /// Transport company operating in the greater area (e.g. VVO)
    pub transport_company: String,
    /// The direct operator of the transport (e.g. DVB)
    pub regional_company: Option<String>,
    /// R09 Frequency in the region
    pub frequency: Option<i64>,
    /// Specific R09 type used in the region
    pub r09_type: Option<R09Type>,
    /// Physical layer encoding used in the region (e.g. VDV420, NEMO)
    pub encoding: Option<i32>,
    /// lat of region
    pub lat: f64,
    /// lon of region
    pub lon: f64,
    /// zoom level
    pub zoom: f64,
    /// in the station is work in progress or not
    pub work_in_progress: bool,
}

/// Request to edit a region
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct EditRegionRequest {
    pub name: String,
    pub transport_company: String,
    pub regional_company: Option<String>,
    pub frequency: Option<i64>,
    pub r09_type: Option<R09Type>,
    pub encoding: Option<i32>,
    /// lat of region
    pub lat: f64,
    /// lon of region
    pub lon: f64,
    /// zoom level
    pub zoom: f64,
    /// in the station is work in progress or not
    pub work_in_progress: bool,
}

/// Returns verbose information about the region
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct RegionInfoStruct {
    #[serde(flatten)]
    pub region: Region,
    #[serde(flatten)]
    pub stats: Stats,
}

/// Creates a region, requires "admin" privilege
#[utoipa::path(
    post,
    path = "/region",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
    ),
    request_body(
        content = CreateRegionRequest,
        description = "holding old the data for a region",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin"])
    ),
    responses(
        (status = 200, description = "region was successfully created", body = RegionCreationResponse),
        (status = 400, description = "given data is malformed"),
        (status = 403, description = "user doesn't have admin role"),
        (status = 500, description = "postgres pool error"),
    ),
)]
#[post("/region")]
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

    // get currently logged in user
    let user_session = fetch_user(identity, &mut database_connection)?;

    if !user_session.is_admin() {
        return Err(ServerError::Forbidden);
    }

    match diesel::insert_into(regions)
        .values(&InsertRegion {
            id: None,
            name: request.name.clone(),
            transport_company: request.transport_company.clone(),
            regional_company: request.regional_company.clone(),
            frequency: request.frequency,
            r09_type: request.r09_type.clone(),
            encoding: request.encoding,
            deactivated: false,
            lat: request.lat,
            lon: request.lon,
            zoom: request.zoom,
            work_in_progress: request.work_in_progress,
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
    path = "/region",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
    ),
    request_body(
        content = Option<ListRequest>,
        description = "Pagination options",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "list of regions", body = Vec<Region>),
        (status = 500, description = "postgres pool error"),
    ),
)]
#[get("/region")]
pub async fn region_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    optional_params: Option<web::Query<ListRequest>>,
) -> Result<web::Json<ListResponse<Region>>, ServerError> {
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

    // counts the region so pageination knows how much more to fetch
    let count: i64 = match regions.count().get_result(&mut database_connection) {
        Ok(result) => result,
        Err(e) => {
            error!("database error {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // just SELECT * FROM regions LIMIT limit OFFSET offset ORDER BY name DESC;
    match regions
        .limit(query_params.limit)
        .offset(query_params.offset)
        .order(tlms::schema::regions::name)
        .load::<Region>(&mut database_connection)
    {
        Ok(region_list) => Ok(web::Json(ListResponse {
            count,
            elements: region_list,
        })),
        Err(e) => {
            error!("database error while listing regions {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Overwrites the region with supplied data. On success returns the updated region.
#[utoipa::path(
    put,
    path = "/region/{id}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = i64, Path, description = "Identitier of the region")
    ),
    request_body(
        content = EditRegionRequest,
        description = "Data with which the region will be overwritten",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin"])
    ),
    responses(
        (status = 200, description = "region successfully updated", body = Region),
        (status = 400, description = "given data is malformed"),
        (status = 403, description = "user doesn't have admin role"),
        (status = 500, description = "postgres pool error"),
    ),
)]
#[put("/region/{id}")]
pub async fn region_update(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(i64,)>,
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
        return Err(ServerError::Forbidden);
    }

    warn!("updating region {:?}", &request);

    use tlms::schema::regions::{
        encoding, frequency, id, lat, lon, name, r09_type, regional_company, transport_company,
        work_in_progress, zoom,
    };

    match diesel::update(regions.filter(id.eq(path.0)))
        .set((
            name.eq(request.name.clone()),
            transport_company.eq(request.transport_company.clone()),
            regional_company.eq(request.regional_company.clone()),
            frequency.eq(request.frequency),
            r09_type.eq(request.r09_type.clone()),
            encoding.eq(request.encoding),
            lat.eq(request.lat),
            lon.eq(request.lon),
            zoom.eq(request.zoom),
            work_in_progress.eq(request.work_in_progress),
        ))
        .get_result::<Region>(&mut database_connection)
    {
        Ok(return_region) => Ok(web::Json(return_region)),
        Err(e) => {
            error!("cannot update regions because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// This endpoint fetches verbose information about a region, like which stations are in the
/// region, and some core metrics. Metrics include how many telegrams are received in the region
/// and receiving rates for different time intervals.
///
/// the returned JSON looks something like this:
///
///´´´json
///{
///      "region_data": { <region_struct> },
///      "stations": [ {...} ],
///      "stats": {
///          "telegram_count": 1000,
///          "last_month_receive_rate": 5.312,
///          "last_day_receive_rate": 2.3,
///      }
///}
///´´´
#[utoipa::path(
    get,
    path = "/region/{id}",
    params(
        ("id" = i64, Path, description = "Identitier of the region")
    ),
    responses(
        (status = 200, description = "Region information returned successfully", body = RegionInfoStruct),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[get("/region/{id}")]
pub async fn region_info(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    path: web::Path<(i64,)>,
) -> Result<web::Json<RegionInfoStruct>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // if the region doesn't exist we can directly dispose of the request
    use tlms::schema::regions::id;
    let region_struct: Region = match regions
        .filter(id.eq(path.0))
        .first::<Region>(&mut database_connection)
    {
        Ok(found_region) => found_region,
        Err(e) => {
            debug!("error encountered while querying region: {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    Ok(web::Json(RegionInfoStruct {
        region: region_struct,
        stats: Stats {
            telegram_count: 1000,
            last_day_receive_rate: (10000_f32 / 86400f32),
            last_month_receive_rate: (1000_f32 / 2592000f32),
        },
    }))
}

/// Deactivates or deletes the specified region
#[utoipa::path(
    delete,
    path = "/region/{id}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = i64, Path, description = "Identitier of the region")
    ),
    security(
        ("user_roles" = ["admin"])
    ),
    responses(
        (status = 200, description = "Region successfully deleted or deactivated"),
        (status = 403, description = "Unauthorized"),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[delete("/region/{id}")]
pub async fn region_delete(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(i64,)>,
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

    // queriering stations if we find any with that region
    // we deactivate otherwise we can savely delete
    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::region as station_region;

    // TODO: exists ist currently completely broken fix with a later diesel release
    // check if there are any station with this region
    let exists = match stations
        .filter(station_region.eq(path.0))
        .load::<Station>(&mut database_connection)
    {
        Ok(rows) => !rows.is_empty(),
        Err(e) => {
            error!(
                "error while checking if region is savely deleteable {:?}",
                e
            );
            return Err(ServerError::InternalError);
        }
    };

    debug!("admin is removing station permanently: {}", exists);

    use tlms::schema::regions::{deactivated, id};

    // if there was a never a station with this region we can savely delete it otherwise
    // we just deactivate this region
    if exists {
        match diesel::update(regions.filter(id.eq(path.0)))
            .set((deactivated.eq(true),))
            .get_result::<Region>(&mut database_connection)
        {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot deactivate region because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    } else {
        match diesel::delete(regions.filter(id.eq(path.0))).execute(&mut database_connection) {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot delete region because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    }
}

// tiny helper function for listing reporting points in a region.
pub async fn region_list_reporting_point_help(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    path: web::Path<(i64,)>,
) -> Result<web::Json<Vec<TransmissionLocation>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::r09_transmission_locations::dsl::r09_transmission_locations;
    use tlms::schema::r09_transmission_locations::region as r09_transmission_locations_region;

    match r09_transmission_locations
        .filter(r09_transmission_locations_region.eq(path.0))
        .load::<TransmissionLocation>(&mut database_connection)
    {
        Ok(reporting_points_list) => Ok(web::Json(reporting_points_list)),
        Err(e) => {
            error!(
                "database error while listing correlated reporting points {:?}",
                e
            );
            Err(ServerError::InternalError)
        }
    }
}

/// Queries alls available reporting points for a given region
///
/// alias for backwarts compatibility use /region/{id}/reporting_point instead.
#[utoipa::path(
    get,
    path = "/region/{id}/reporting_points",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = i64, Path, description = "Identifier of the region")
    ),
    responses(
        (status = 200, description = "Reporting points successfully queried", body = Vec<TransmissionLocation>),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[get("/region/{id}/reporting_points")]
pub async fn region_list_reporting_point_v1(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<(i64,)>,
) -> Result<web::Json<Vec<TransmissionLocation>>, ServerError> {
    region_list_reporting_point_help(pool, req, path).await
}

/// Queries alls available reporting points for a given region
#[utoipa::path(
    get,
    path = "/region/{id}/reporting_point",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = i64, Path, description = "Identifier of the region")
    ),
    responses(
        (status = 200, description = "Reporting points successfully queried", body = Vec<TransmissionLocation>),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[get("/region/{id}/reporting_point")]
pub async fn region_list_reporting_point_v2(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<(i64,)>,
) -> Result<web::Json<Vec<TransmissionLocation>>, ServerError> {
    region_list_reporting_point_help(pool, req, path).await
}

/// Returns all the different points that are correlated for this reporting point.
/// This endpoint is mainly used to find incorrect data that leads to vaulty correlated points.
#[utoipa::path(
    get,
    path = "/region/{id}/reporting_point/{rid}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = i64, Path, description = "Identifier of the region"),
        ("rid" = i32, Path, description = "Identifier of the reporting point")
    ),
    responses(
        (status = 200, description = "All the different correlated points for this reporting point.", body = Vec<TransmissionLocation>),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[get("/region/{id}/reporting_point/{rid}")]
pub async fn region_get_reporting_point(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    path: web::Path<(i64, i32)>,
) -> Result<web::Json<Vec<TransmissionLocationRaw>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::r09_transmission_locations_raw::dsl::r09_transmission_locations_raw;
    use tlms::schema::r09_transmission_locations_raw::region as r09_transmission_locations_raw_region;
    use tlms::schema::r09_transmission_locations_raw::reporting_point as r09_transmission_locations_raw_reporting_point;

    match r09_transmission_locations_raw
        .filter(r09_transmission_locations_raw_region.eq(path.0))
        .filter(r09_transmission_locations_raw_reporting_point.eq(path.1))
        .load::<TransmissionLocationRaw>(&mut database_connection)
    {
        Ok(reporting_point_list) => Ok(web::Json(reporting_point_list)),
        Err(e) => {
            error!(
                "database error while listing correlated reporting points {:?}",
                e
            );
            Err(ServerError::InternalError)
        }
    }
}
