use crate::{routes::user::fetch_user, routes::ServerError, DbPool};
use tlms::management::{Station, Region};

use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::BoolExpressionMethods;
use diesel::{ExpressionMethods, QueryDsl};

use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use rand::{Rng, distributions::Alphanumeric};

/// holds all the necessary information that are required to create a new region
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateStationRequest {
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub region: i64,
    pub owner: Uuid,
    pub public: bool,
    pub radio: Option<i32>,
    pub architecture: Option<i32>,
    pub device: Option<i32>,
    pub elevation: Option<f64>,
    pub antenna: Option<i32>,
    pub telegram_decoder_version: Option<String>,
    pub notes: Option<String>
}


/// holds all the necessary information that are required to create a new region
#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdateStationRequest {
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub public: bool,
    pub radio: Option<i32>,
    pub architecture: Option<i32>,
    pub device: Option<i32>,
    pub elevation: Option<f64>,
    pub antenna: Option<i32>,
    pub telegram_decoder_version: Option<String>,
    pub notes: Option<String>
}


#[derive(Serialize, Deserialize, ToSchema)]
pub struct SearchStationRequest {
    pub owner: Option<Uuid>,
    pub region: Option<i64>
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ForceDeleteRequest {
    pub force: bool
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ApproveStationRequest {
    pub approve: bool
}

/// will create a station with the owner of the currently authenticated user
#[utoipa::path(
    post,
    path = "/station",
    responses(
        (status = 200, description = "station was successfully created", body = Station),
        (status = 400, description = "invalid user data", body = Station),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn station_create(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    request: web::Json<CreateStationRequest>,
) -> Result<web::Json<Station>, ServerError> {
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

    // if the region doesn't exist we can directly dispose of the request
    use tlms::schema::regions::dsl::regions;
    use tlms::schema::regions::id;
    match regions
        .filter(id.eq(request.region))
        .first::<Region>(&mut database_connection)
    {
        Ok(_) => {},
        Err(e) => {
            debug!("error while querying region, probably not region with this id {:?}", e);
            return Err(ServerError::BadClientData);
        }
    };

    // generate token 32 base64
    let random_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

    use tlms::schema::stations::dsl::stations;

    let new_station = Station {
        id: Uuid::new_v4(),
        token: Some(random_token),
        name: request.name.clone(),
        lat: request.lat,
        lon: request.lon,
        region: request.region,
        owner: user_session.id,
        approved: false,
        deactivated: false,
        public: false,
        radio: request.radio,
        architecture: request.architecture,
        device: request.device,
        elevation: request.elevation,
        antenna: request.antenna,
        telegram_decoder_version: request.telegram_decoder_version.clone(),
        notes: request.notes.clone()
    };

    match diesel::insert_into(stations)
        .values(&new_station)
        .execute(&mut database_connection)
    {
        Err(e) => {
            error!("while trying to insert station {:?}", e);
            Err(ServerError::BadClientData)
        }
        Ok(_) => Ok(web::Json(new_station)),
    }
}

/// will return a list of stations applied with the filter and user permissions
#[utoipa::path(
    get,
    path = "/station",
    responses(
        (status = 200, description = "list of stations was successfully returned", body = Vec<Station>),
        (status = 400, description = "invalid user data", body = Station),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn station_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
) -> Result<web::Json<Vec<Station>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // get currently logged in user
    let user_session = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::{public, owner};
    
    if user_session.is_admin() {
        match stations
            .load::<Station>(&mut database_connection) {
            Ok(station_list) => Ok(web::Json(station_list)),
            Err(e) => {
                error!("error while querying database for stations {:?}", e);
                return Err(ServerError::BadClientData);
            }
        }
    } else {
        match stations
            .filter(public.eq(true).or(owner.eq(user_session.id)))
            .load::<Station>(&mut database_connection)
        {
            Ok(all_station) => Ok(web::Json(all_station)),
            Err(e) => {
                error!("error while fetching the config {:?}", e);
                return Err(ServerError::InternalError);
            }
        }
    }
}


/// will return a list of stations applied with the filter and user permissions
#[utoipa::path(
    put,
    path = "/station/{id}",
    responses(
        (status = 200, description = "station got successfully updated", body = Station),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn station_update(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
    request: web::Json<UpdateStationRequest>,
) -> Result<web::Json<Station>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // get currently logged in user
    let user_session = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::{id, name, lat, lon, public, architecture, device, elevation, antenna, telegram_decoder_version, notes};
    
    //use diesel::{select, dsl::exists};
    // TODO: exists ist currently completely broken fix with a later diesel release
    // check if there are any station with this region
    let relevant_station = match stations
        .filter(id.eq(path.0))
        .limit(1)
        .first::<Station>(&mut database_connection)
    {
        Ok(possible_station) => possible_station,
        Err(e) => {
            error!("error while checking if region is savely deleteable {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    if !user_session.is_admin() && user_session.id != relevant_station.owner {
        return Err(ServerError::Unauthorized);
    }

    // if there was a never a station with this region we can savely delete it otherwise
    // we just deactivate this region
    match diesel::update(stations.filter(id.eq(path.0)))
        .set((
            name.eq(request.name.clone()),
            lat.eq(request.lat),
            lon.eq(request.lon),
            public.eq(request.public),
            architecture.eq(request.architecture),
            device.eq(request.device),
            elevation.eq(request.elevation),
            antenna.eq(request.antenna),
            telegram_decoder_version.eq(request.telegram_decoder_version.clone()),
            notes.eq(request.notes.clone())
        ))
        .get_result::<Station>(&mut database_connection)
    {
        Ok(result) => Ok(web::Json(result)),
        Err(e) => {
            error!("cannot deactivate user because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// will try to delete a station if this is not possible we will deactivate it.
#[utoipa::path(
    delete,
    path = "/station/{id}",
    responses(
        (status = 200, description = "station got successfully deleted"),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn station_delete(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
    request: Option<web::Json<ForceDeleteRequest>>,
) -> Result<HttpResponse, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // get currently logged in user
    let user_session = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::{id, deactivated};
    
    //use diesel::{select, dsl::exists};
    // TODO: exists ist currently completely broken fix with a later diesel release
    // check if there are any station with this region
    let relevant_station = match stations
        .filter(id.eq(path.0))
        .limit(1)
        .first::<Station>(&mut database_connection)
    {
        Ok(possible_station) => possible_station,
        Err(e) => {
            error!("error while checking if region is savely deleteable {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    warn!("trying to deleting station! : {}", relevant_station.id);

    if user_session.is_admin() && request.is_some() && request.unwrap().force {
        match diesel::delete(stations.filter(id.eq(path.0))).execute(&mut database_connection) {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot deactivate user because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    } else if (user_session.id == relevant_station.owner) || user_session.is_admin() {
        match diesel::update(stations.filter(id.eq(path.0)))
            .set((
                deactivated.eq(true),
            ))
            .get_result::<Station>(&mut database_connection)
        {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot deactivate user because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    } else {
        return Err(ServerError::Unauthorized);
    }
}

/// will return information about the requested station
#[utoipa::path(
    get,
    path = "/station/{id}",
    responses(
        (status = 200, description = "station information successfully returned"),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn station_info(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
) -> Result<web::Json<Station>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // get currently logged in user
    let user_session = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::id;

    let relevant_station = match stations
        .filter(id.eq(path.0))
        .limit(1)
        .first::<Station>(&mut database_connection)
    {
        Ok(possible_station) => possible_station,
        Err(e) => {
            error!("error while checking if region is savely deleteable {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    if user_session.is_admin() || relevant_station.owner == user_session.id {
        return Ok(web::Json(relevant_station));
    } else {
        return Err(ServerError::Unauthorized);
    }
}


/// will approve a station
#[utoipa::path(
    post,
    path = "/station/{id}/approve",
    responses(
        (status = 200, description = "station was successfully approved"),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn station_approve(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
    request: web::Json<ApproveStationRequest>,
) -> Result<HttpResponse, ServerError> {
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

    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::{id, approved};

    match diesel::update(stations.filter(id.eq(path.0)))
        .set((approved.eq(request.approve),))
        .get_result::<Station>(&mut database_connection) {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => {
            error!("cannot deactivate user because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

