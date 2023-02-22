pub mod auth;
pub mod region;
pub mod station;
pub mod user;

use actix_web::{
    error,
    http::{header::ContentType, StatusCode},
    HttpResponse,
};

use derive_more::{Display, Error};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// let the user specify offset and limit for querying the database
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct ListRequest {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

/// returns the user how many entries were found
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct ListResponse<T> {
    pub count: i64,
    pub elements: Vec<T>,
}

#[derive(Debug, Display, Error)]
pub enum ServerError {
    #[display(fmt = "internal error")]
    InternalError,

    #[display(fmt = "bad request")]
    BadClientData,

    #[display(fmt = "unauthorized")]
    Unauthorized,
}

impl error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            ServerError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ServerError::BadClientData => StatusCode::BAD_REQUEST,
            ServerError::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DeactivateRequest {
    pub id: Uuid,
    pub deactivated: bool,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::user_login,
        auth::user_logout,
        auth::auth_info,
        user::user_register,
        user::user_update,
        user::user_delete,
        user::user_info,
        user::user_list,
        region::region_create,
        region::region_update,
        region::region_list,
        region::region_info,
        region::region_delete,
        station::station_create,
        station::station_list,
        station::station_info,
        station::station_update,
        station::station_delete,
        station::station_approve
    ),
    components(schemas(
        ListRequest,
        ListResponse<tlms::management::Region>,
        ListResponse<tlms::management::Station>,
        auth::LoginRequest,
        user::RegisterUserRequest,
        user::ModifyUserRequest,
        user::UuidRequest,
        user::ResponseLogin,
        user::CreateUserResponse,
        region::RegionCreationResponse,
        region::CreateRegionRequest,
        region::EditRegionRequest,
        region::Stats,
        region::RegionInfoStruct,
        station::CreateStationRequest,
        station::UpdateStationRequest,
        station::SearchStationRequest,
        station::ForceDeleteRequest,
        station::ApproveStationRequest
    ))
)]
pub struct ApiDoc;
