use crate::{
    routes::auth::fetch_user,
    routes::{ListRequest, ListResponse, ServerError, Stats},
    DbPool,
};
use tlms::locations::region::Region;
use tlms::management::user::Role;
use tlms::management::Station;
use tlms::schema::stations::dsl::stations;

use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};

use log::{debug, error, warn};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// holds all the necessary information that are required to create a new station
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
    pub notes: Option<String>,
    pub organization: Uuid,
}

/// holds all the necessary information that are required to update information about
/// at station
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
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SearchStationRequest {
    pub owner: Option<Uuid>,
    pub region: Option<i64>,
}

/// forces deletion of a station
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ForceDeleteRequest {
    pub force: bool,
}

/// containes the value for approved that should be set
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ApproveStationRequest {
    pub approve: bool,
}

/// containes the value for approved that should be set
#[derive(Serialize, Deserialize, ToSchema)]
pub struct StationInfoResponse {
    #[serde(flatten)]
    pub station: Station,

    #[serde(flatten)]
    pub stats: Stats,
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

    if !user_session.allowed(&request.organization, &Role::CreateCompanyStations) {
        return Err(ServerError::Forbidden);
    }

    // if the region doesn't exist we can directly dispose of the request
    use tlms::schema::regions::dsl::regions;
    use tlms::schema::regions::id;
    match regions
        .filter(id.eq(request.region))
        .first::<Region>(&mut database_connection)
    {
        Ok(_) => {}
        Err(e) => {
            debug!(
                "error while querying region, probably not region with this id {:?}",
                e
            );
            return Err(ServerError::BadClientData);
        }
    };

    // generate token 32 base64
    let random_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let new_station = Station {
        id: Uuid::new_v4(),
        token: Some(random_token),
        name: request.name.clone(),
        lat: request.lat,
        lon: request.lon,
        region: request.region,
        owner: user_session.user.id,
        approved: false,
        deactivated: false,
        public: request.public,
        radio: request.radio,
        architecture: request.architecture,
        device: request.device,
        elevation: request.elevation,
        antenna: request.antenna,
        telegram_decoder_version: request.telegram_decoder_version.clone(),
        notes: request.notes.clone(),
        organization: request.organization,
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
    optional_params: Option<web::Form<ListRequest>>,
) -> Result<web::Json<ListResponse<Station>>, ServerError> {
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

    let count: i64 = match stations.count().get_result(&mut database_connection) {
        Ok(result) => result,
        Err(e) => {
            error!("database error {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    match stations
        .limit(query_params.limit)
        .offset(query_params.offset)
        .order(tlms::schema::stations::name)
        .load::<Station>(&mut database_connection)
    {
        Ok(station_list) => Ok(web::Json(ListResponse {
            count,
            elements: station_list,
        })),
        Err(e) => {
            error!("error while querying database for stations {:?}", e);
            Err(ServerError::BadClientData)
        }
    }
}

/// will edit a station
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

    use tlms::schema::stations::{
        antenna, architecture, device, elevation, id, lat, lon, name, notes, public,
        telegram_decoder_version,
    };

    let relevant_station = match stations
        .filter(id.eq(path.0))
        .first::<Station>(&mut database_connection)
    {
        Ok(possible_station) => possible_station,
        Err(e) => {
            error!("error while searching for mentioned station {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // there multiple combinations that would allow a user to edit this station
    // 1.) being admin
    // 2.) being maintainer and having the EditMaintainedStation role
    // 3.) having the EditCompanyStation Role
    if !(user_session.is_admin()
        || (user_session.user.id == relevant_station.owner
            && user_session.has_role(
                &relevant_station.organization,
                &Role::EditMaintainedStations,
            ))
        || (user_session.has_role(&relevant_station.organization, &Role::EditCompanyStations)))
    {
        return Err(ServerError::Forbidden);
    }

    // updating stations
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
            notes.eq(request.notes.clone()),
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

    use tlms::schema::stations::{deactivated, id};

    let relevant_station = match stations
        .filter(id.eq(path.0))
        .first::<Station>(&mut database_connection)
    {
        Ok(possible_station) => possible_station,
        Err(e) => {
            error!("error while searching for mentioned station {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // there multiple combinations that would allow a user to edit this station
    // 1.) being admin
    // 2.) being maintainer and having the EditMaintainedStation role
    // 3.) having the EditCompanyStation Role
    if !(user_session.is_admin()
        || (user_session.user.id == relevant_station.owner
            && user_session.has_role(
                &relevant_station.organization,
                &Role::DeleteMaintainedStations,
            ))
        || (user_session.has_role(&relevant_station.organization, &Role::DeleteCompanyStations)))
    {
        return Err(ServerError::Forbidden);
    }

    warn!("trying to delete station! : {}", relevant_station.id);

    // TODO: check this
    if user_session.is_admin() && request.is_some() && request.unwrap().force {
        match diesel::delete(stations.filter(id.eq(path.0))).execute(&mut database_connection) {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot deactivate user because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    } else {
        match diesel::update(stations.filter(id.eq(path.0)))
            .set((deactivated.eq(true),))
            .get_result::<Station>(&mut database_connection)
        {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot deactivate user because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
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
    path: web::Path<(Uuid,)>,
) -> Result<web::Json<StationInfoResponse>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::stations::id;

    let relevant_station = match stations
        .filter(id.eq(path.0))
        .first::<Station>(&mut database_connection)
    {
        Ok(possible_station) => possible_station,
        Err(e) => {
            error!("error while searching for mentioned station {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let stats = Stats {
        telegram_count: 100213231,
        last_day_receive_rate: 81322.512,
        last_month_receive_rate: 123212.231,
    };

    Ok(web::Json(StationInfoResponse {
        station: relevant_station,
        stats,
    }))
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

    let relevant_station = match stations
        .filter(id.eq(path.0))
        .first::<Station>(&mut database_connection)
    {
        Ok(possible_station) => possible_station,
        Err(e) => {
            error!("error while searching for mentioned station {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    if !(user_session.is_admin()
        || user_session.has_role(&relevant_station.organization, &Role::ApproveStations))
    {
        return Err(ServerError::Forbidden);
    }

    use tlms::schema::stations::{approved, id};

    match diesel::update(stations.filter(id.eq(path.0)))
        .set((approved.eq(request.approve),))
        .get_result::<Station>(&mut database_connection)
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => {
            error!("cannot deactivate user because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}
