use crate::{routes::ServerError, DbPool};
use tlms::management::user::{verify_password, Role, User};
use tlms::schema::users::dsl::users;

use actix_identity::Identity;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, PgConnection, QueryDsl};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// request for logging into a user
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct UuidRequest {
    pub id: Uuid,
}

#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct UuidResponse {
    pub id: Uuid,
    pub success: bool,
}

/// data returned after logging in
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct ResponseLogin {
    pub success: bool,
    pub id: Uuid,
    pub admin: bool,
    pub name: Option<String>,
}

/// takes a cookie and returnes the corresponging user struct
pub fn fetch_user(
    user: Identity,
    database_connection: &mut PgConnection,
) -> Result<User, ServerError> {
    use tlms::schema::users::id;

    // user uuid from currently authenticat
    let user_id: Uuid = match user.id() {
        Ok(found_id) => match Uuid::parse_str(&found_id) {
            Ok(parsed_uuid) => parsed_uuid,
            Err(e) => {
                error!("problem with decoding id from cookie {:?}", e);
                return Err(ServerError::BadClientData);
            }
        },
        Err(e) => {
            error!("problem with fetching id from cookie {:?}", e);
            return Err(ServerError::BadClientData);
        }
    };

    // user struct from currently authenticated user
    match users
        .filter(id.eq(user_id))
        .first::<User>(database_connection)
    {
        Ok(found_user) => Ok(found_user),
        Err(_) => Err(ServerError::BadClientData),
    }
}

/// This endpoint takes an email address and a password if they are both valid
/// 200 (Success) is returned together with a session cookie.
#[utoipa::path(
    post,
    path = "/auth/login",
    responses(
        (status = 200, description = "user was successfully authenticated", body = crate::routes::UserCreation),
        (status = 500, description = "postgres pool error"),
        (status = 400, description = "invalid user data")
    ),
)]
pub async fn user_login(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    request: web::Json<LoginRequest>,
) -> Result<web::Json<ResponseLogin>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::users::email;

    match users
        .filter(email.eq(request.email.clone()))
        .first::<User>(&mut database_connection)
    {
        Ok(user) => {
            if verify_password(&request.password, &user.password) {
                match Identity::login(&req.extensions(), user.id.to_string()) {
                    Ok(_) => {}
                    Err(e) => {
                        error!(
                            "cannot create session maybe the redis is not running. {:?}",
                            e
                        );
                        return Err(ServerError::InternalError);
                    }
                };

                Ok(web::Json(ResponseLogin {
                    id: user.id,
                    success: true,
                    name: user.name.clone(),
                    admin: (Role::from(user.role) == Role::Administrator),
                }))
            } else {
                debug!("Password does not match");
                Err(ServerError::BadClientData)
            }
        }
        Err(e) => {
            error!("Err: {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// removes the current session and therefore logging out the user
#[utoipa::path(
    get,
    path = "/auth/logout",
    responses(
        (status = 200, description = "returnes old measurements"),

    ),
)]
pub async fn user_logout(user: Identity, _req: HttpRequest) -> Result<HttpResponse, ServerError> {
    user.logout();
    Ok(HttpResponse::Ok().finish())
}
