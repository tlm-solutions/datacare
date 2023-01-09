use crate::{
    routes::{auth::fetch_user, ServerError},
    DbPool,
};
use tlms::management::user::{hash_password, Role, User};
use tlms::schema::users::dsl::users;

use actix_identity::Identity;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};
use log::{error, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// request for registering a new user
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct RegisterUserRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

/// request for logging into a user
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// modifing a user
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct ModifyUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub role: Option<i32>,
    pub email_setting: Option<i32>,
    pub deactivated: Option<bool>,
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

#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct CreateUserResponse {
    pub success: bool,
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: i32,
    pub email_setting: i32,
    pub deactivated: bool,
}

/// This endpoint if registrating a new users
/// it needs a valid email address a user name and password which is at least 8
/// characters long
#[utoipa::path(
    post,
    path = "/user",
    responses(
       (status = 200, description = "user was successfully created", body = crate::routes::UserCreation),
        (status = 500, description = "postgres pool error"),
        (status = 400, description = "invalid user data"),
    ),
)]
pub async fn user_register(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    request: web::Json<RegisterUserRequest>,
) -> Result<web::Json<CreateUserResponse>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::users::email;

    match diesel::dsl::select(diesel::dsl::exists(
        users.filter(email.eq(request.email.clone())),
    ))
    .get_result(&mut database_connection)
    {
        Ok(email_exists) => {
            if email_exists {
                return Err(ServerError::BadClientData);
            }
        }
        Err(e) => {
            error!("Err: {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let email_regex = Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap();

    if !email_regex.is_match(&request.email)
        || request.name.is_empty()
        || request.password.len() < 8
    {
        return Err(ServerError::BadClientData);
    }

    let password_hash = match hash_password(&request.password) {
        Some(hashed_password) => hashed_password,
        None => {
            warn!("User did not supply hashable password");
            return Err(ServerError::BadClientData);
        }
    };

    let user = User {
        id: Uuid::new_v4(),
        name: Some(request.name.clone()),
        email: Some(request.email.clone()),
        password: password_hash,
        role: Role::User.as_int(),
        deactivated: false,
        email_setting: Some(0),
    };

    if let Err(e) = diesel::insert_into(users)
        .values(&user)
        .execute(&mut database_connection)
    {
        error!("while trying to insert user {:?}", e);
        return Err(ServerError::BadClientData);
    };

    match Identity::login(&req.extensions(), user.id.to_string()) {
        Ok(_) => {}
        Err(e) => {
            error!(
                "cannot create session maybe the redis is not running. {:?}",
                e
            );
            return Err(ServerError::BadClientData);
        }
    };

    Ok(web::Json(CreateUserResponse {
        success: true,
        id: user.id,
        name: request.name.clone(),
        email: request.email.clone(),
        role: Role::User.as_int(),
        deactivated: false,
        email_setting: 0,
    }))
}

/// we can not really delete a user we mark the user as deactivated which strips
/// him of every priviliges and function
#[utoipa::path(
    delete,
    path = "/user/{id}",
    responses(
        (status = 200, description = "successfully deleted user"),
        (status = 500, description = "postgres pool error"),
        (status = 400, description = "invalid user id")
    ),
)]
pub async fn user_delete(
    pool: web::Data<DbPool>,
    identity: Identity,
    path: web::Path<(Uuid,)>,
    _req: HttpRequest,
) -> Result<HttpResponse, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    if !session_user.is_admin() {
        return Err(ServerError::Unauthorized);
    }

    use tlms::schema::users::{deactivated, id};

    match diesel::update(users.filter(id.eq(path.0)))
        .set((deactivated.eq(true),))
        .get_result::<User>(&mut database_connection)
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => {
            error!("cannot deactivate user because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Update on of the following user properties (name, email, role, deactivated)
/// Only Admins or the user in question can modify attributes.
#[utoipa::path(
    put,
    path = "/user/{id}",
    responses(
        (status = 200, description = "successfully updated user data"),
        (status = 500, description = "postgres pool error"),
        (status = 400, description = "invalid user id")
    ),
)]
pub async fn user_update(
    pool: web::Data<DbPool>,
    identity: Identity,
    _req: HttpRequest,
    path: web::Path<(Uuid,)>,
    request: web::Json<ModifyUserRequest>,
) -> Result<HttpResponse, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::users::{deactivated, email, id, name, role};

    // user which should be modified
    let user = match users
        .filter(id.eq(path.0))
        .first::<User>(&mut database_connection)
    {
        Ok(found_user) => found_user,
        Err(_) => return Err(ServerError::BadClientData),
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    // TODO: can be simplified
    // current user is admin he can do what ever he wants
    if !session_user.is_admin() {
        // its fine if the user tries to modify him self or an administrator modifies other user
        if path.0 != session_user.id {
            return Err(ServerError::Unauthorized);
        }

        // user shouldn't be able to modify his own role
        if request.role.is_some() {
            return Err(ServerError::Unauthorized);
        }
    }

    // checking if the supplied role number is valid
    if Role::from(request.role.unwrap()) == Role::Unknown {
        return Err(ServerError::BadClientData);
    }

    let user_name = user.name.clone().map_or_else(
        || request.name.clone(),
        |value| Some(request.name.clone().unwrap_or(value)),
    );
    let user_email = user.name.clone().map_or_else(
        || request.email.clone(),
        |value| Some(request.email.clone().unwrap_or(value)),
    );

    match diesel::update(users.filter(id.eq(path.0)))
        .set((
            name.eq(user_name),
            email.eq(user_email),
            role.eq(request.role.unwrap_or(user.role)),
            deactivated.eq(request.deactivated.unwrap_or(user.deactivated)),
        ))
        .get_result::<User>(&mut database_connection)
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(error) => {
            error!("error occured while trying to update user {:?}", error);
            Err(ServerError::InternalError)
        }
    }
}

/// Returns information about the currently authenticated user
#[utoipa::path(
    get,
    path = "/user/{id}",
    responses(
        (status = 200, description = "returning user information"),
        (status = 500, description = "postgres pool error"),
        (status = 400, description = "invalid user id")
    ),
)]
pub async fn user_info(
    pool: web::Data<DbPool>,
    identity: Identity,
    _req: HttpRequest,
    path: web::Path<(Uuid,)>,
    request: Option<web::Json<UuidRequest>>,
) -> Result<web::Json<User>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    let interesting_user_id = match request {
        Some(found_request) => {
            if session_user.is_admin() || session_user.id == found_request.id {
                found_request.id
            } else {
                return Err(ServerError::Unauthorized);
            }
        }
        None => session_user.id,
    };

    use tlms::schema::users::id;

    // fetching interesting user
    let user = match users
        .filter(id.eq(interesting_user_id))
        .first::<User>(&mut database_connection)
    {
        Ok(found_user) => found_user,
        Err(_) => return Err(ServerError::BadClientData),
    };

    Ok(web::Json(user))
}

/// Returns list of users
#[utoipa::path(
    get,
    path = "/user",
    responses(
        (status = 200, description = "returning a list of public users"),
        (status = 500, description = "postgres pool error"),
        (status = 400, description = "invalid user id")
    ),
)]
pub async fn user_list(
    pool: web::Data<DbPool>,
    identity: Identity,
    _req: HttpRequest,
) -> Result<web::Json<Vec<User>>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    if !session_user.is_admin() {
        return Err(ServerError::Unauthorized);
    }

    // fetching interesting user
    let users_list = match users.load::<User>(&mut database_connection) {
        Ok(found_user) => found_user,
        Err(_) => return Err(ServerError::BadClientData),
    };

    Ok(web::Json(users_list))
}
