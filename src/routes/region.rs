use crate::{
    routes::auth::fetch_user, routes::ListRequest, routes::ListResponse, routes::ServerError,
    DbPool,
};
use tlms::management::{InsertRegion, Region, Station};
use tlms::schema::regions::dsl::regions;

use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::dsl::IntervalDsl;
use diesel::query_dsl::RunQueryDsl;
use diesel::BoolExpressionMethods;
use diesel::{ExpressionMethods, QueryDsl};

use log::{debug, error, warn};
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
    pub name: String,
    pub transport_company: String,
    pub regional_company: Option<String>,
    pub frequency: Option<i64>,
    pub r09_type: Option<i32>,
    pub encoding: Option<i32>,
}

/// Stats about the regions
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct Stats {
    pub telegram_count: i64,
    pub last_day_receive_rate: f32,
    pub last_month_receive_rate: f32,
}

/// returns a lot more detailled information
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct RegionInfoStruct {
    pub region: Region,
    pub stats: Stats,
    pub stations: Vec<Station>,
}

/// will create a region if the currently authenticated user is an admin
#[utoipa::path(
    post,
    path = "/region",
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

    // get currently logged in user
    let user_session = fetch_user(identity, &mut database_connection)?;

    if !user_session.is_admin() {
        return Err(ServerError::Unauthorized);
    }

    match diesel::insert_into(regions)
        .values(&InsertRegion {
            id: None,
            name: request.name.clone(),
            transport_company: request.transport_company.clone(),
            regional_company: request.regional_company.clone(),
            frequency: request.frequency,
            r09_type: request.r09_type,
            encoding: request.encoding,
            deactivated: false,
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
    responses(
        (status = 200, description = "list of regions", body = Vec<Region>),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn region_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    optional_params: Option<web::Form<ListRequest>>,
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

    let count: i64 = match regions.count().get_result(&mut database_connection) {
        Ok(result) => result,
        Err(e) => {
            error!("database error {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // just SELECT * FROM regions;
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

/// Will overwrite a region with the new data on success it will return the updated region.
#[utoipa::path(
    put,
    path = "/region/{id}",
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
        return Err(ServerError::Unauthorized);
    }

    warn!("updating region {:?}", &request);

    use tlms::schema::regions::{
        encoding, frequency, id, name, r09_type, regional_company, transport_company,
    };

    match diesel::update(regions.filter(id.eq(path.0)))
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

/// This endpoint will fetch significantly more information about a region like
/// which stations are inside the region and some core metrics like how many telegrams
/// are received globally and rates for different time intervals.
///
/// the returned json will look something like this:
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
    responses(
        (status = 200, description = "will return more detailled information about a region"),
        (status = 400, description = "user suplied an unkown region id"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn region_info(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
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
            return Err(ServerError::BadClientData);
        }
    };

    let user_session = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::{owner, public, region as station_region};

    // if the currently logged in user is an admin we return all stations in this region
    // otherwise just the stations that are public or belong to this user.
    let found_stations = if user_session.is_admin() {
        match stations
            .filter(station_region.eq(path.0))
            .load::<Station>(&mut database_connection)
        {
            Ok(all_station) => all_station,
            Err(e) => {
                error!("error while fetching the config {:?}", e);
                return Err(ServerError::InternalError);
            }
        }
    } else {
        match stations
            .filter(station_region.eq(path.0))
            .filter(public.eq(true).or(owner.eq(user_session.id)))
            .load::<Station>(&mut database_connection)
        {
            Ok(all_station) => all_station,
            Err(e) => {
                error!("error while fetching the config {:?}", e);
                return Err(ServerError::InternalError);
            }
        }
    };

    use diesel::dsl::now;
    use tlms::schema::r09_telegrams::dsl::r09_telegrams;
    use tlms::schema::r09_telegrams::{id as telegram_id, region as telegram_region, time};

    // counts telegram from this regions over different time intervals
    let telegram_count_last_day = match r09_telegrams
        .filter(telegram_region.eq(path.0))
        .filter(time.lt(now - 1_i32.days()))
        .select(diesel::dsl::count(telegram_id))
        .first::<i64>(&mut database_connection)
    {
        Ok(telegram_count) => telegram_count,
        Err(e) => {
            error!("error while fetching the config {:?}", e);
            return Err(ServerError::InternalError);
        }
    };
    let telegram_count_last_month = match r09_telegrams
        .filter(telegram_region.eq(path.0))
        .filter(time.lt(now - 30_i32.days()))
        .select(diesel::dsl::count(telegram_id))
        .first::<i64>(&mut database_connection)
    {
        Ok(telegram_count) => telegram_count,
        Err(e) => {
            error!("error while fetching the config {:?}", e);
            return Err(ServerError::InternalError);
        }
    };
    let telegram_count_global = match r09_telegrams
        .filter(telegram_region.eq(path.0))
        .select(diesel::dsl::count(telegram_id))
        .first::<i64>(&mut database_connection)
    {
        Ok(telegram_count) => telegram_count,
        Err(e) => {
            error!("error while fetching the config {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    Ok(web::Json(RegionInfoStruct {
        region: region_struct,
        stats: Stats {
            telegram_count: telegram_count_global,
            last_day_receive_rate: (telegram_count_last_day as f32 / 86400f32),
            last_month_receive_rate: (telegram_count_last_month as f32 / 2592000f32),
        },
        stations: found_stations,
    }))
}

/// will overwritte or delete the specified region
#[utoipa::path(
    delete,
    path = "/region/{id}",
    responses(
        (status = 200, description = "successfully edited region", body = Region),
        (status = 400, description = "invalid input data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
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
        return Err(ServerError::Unauthorized);
    }

    // queriering stations if we find any with that region
    // we deactivate otherwise we can savely delete
    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::region as station_region;

    //use diesel::{select, dsl::exists};
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
                error!("cannot deactivate user because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    } else {
        match diesel::delete(regions.filter(id.eq(path.0))).execute(&mut database_connection) {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot deactivate user because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    }
}
