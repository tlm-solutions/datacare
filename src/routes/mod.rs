pub mod region;
//mod station;
pub mod user;

use actix_web::{
    error,
    http::{header::ContentType, StatusCode},
    HttpResponse,
};

use derive_more::{Display, Error};
use serde::{Deserialize, Serialize};
use utoipa::OpenApi;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct IdentifierRequest {
    pub id: i32,
}

#[derive(Serialize)]
pub struct ServiceResponse {
    success: bool,
    message: Option<String>,
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
        user::user_login,
        user::user_register,
        user::user_logout,
        user::user_update,
        user::user_delete,
        user::user_info,
        user::user_list,
        region::region_create,
        region::region_update,
        region::region_list,
        region::region_info,
        region::region_delete
    ),
    components(schemas(
        user::RegisterUserRequest,
        user::LoginRequest,
        user::ModifyUserRequest,
        user::UuidRequest,
        user::ResponseLogin,
        user::CreateUserResponse,
        region::RegionCreationResponse,
        region::CreateRegionRequest,
        region::EditRegionRequest,
        region::Stats,
        region::RegionInfoStruct
    ))
)]
pub struct ApiDoc;
