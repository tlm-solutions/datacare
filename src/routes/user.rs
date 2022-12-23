use crate::{routes::ServerError, DbPool};
use dump_dvb::management::user::{
    Role, User, hash_password, verify_password
};

use actix_web::{web, HttpResponse, HttpRequest, HttpMessage};
use actix_identity::Identity;
use diesel::query_dsl::RunQueryDsl;
use diesel::{QueryDsl, ExpressionMethods, PgConnection};
use utoipa::ToSchema;
use log::{error, debug, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
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
    pub id: Uuid,
    pub name: Option<String>,
    pub email: Option<String>,
    pub role: Option<Role>,
    pub email_setting: Option<i32>,
    pub deactivated: Option<bool>
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

/// takes a cookie and returnes the corresponging user struct
pub fn fetch_user(user: Identity, database_connection: &mut PgConnection) -> Result<User, ServerError> {
    use dump_dvb::schema::users::dsl::users;
    use dump_dvb::schema::users::id;

    // user uuid from currently authenticat
    let user_id: Uuid = match user.id() {
        Ok(found_id) => match Uuid::parse_str(&found_id) {
            Ok(parsed_uuid) => parsed_uuid,
            Err(e) => {
                error!("problem with decoding id from cookie {:?}", e);
                return Err(ServerError::BadClientData)
            }
        },
        Err(e) => {
            error!("problem with fetching id from cookie {:?}", e);
            return Err(ServerError::BadClientData)
        }
    };

    // user struct from currently authenticated user
    match users.filter(id.eq(user_id)).first::<User>(database_connection) {
        Ok(found_user) => Ok(found_user),
        Err(_) => Err(ServerError::BadClientData)
    }
}


/// This endpoint if registrating a new users
/// it needs a valid email address a user name and password which is at least 8 
/// characters long
#[utoipa::path(
    post,
    path = "/user/register",
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
    ) ->  Result<web::Json<CreateUserResponse>, ServerError> {

    let mut database_connection = match pool.get() {
         Ok(conn) => conn,
         Err(e) => {
             error!("cannot get connection from connection pool {:?}", e);
             return Err(ServerError::InternalError);
         }
    };

    use dump_dvb::schema::users::dsl::users;
    use dump_dvb::schema::users::email;

    match diesel::dsl::select(diesel::dsl::exists(users.filter(email.eq(request.email.clone()))))
            .get_result(&mut database_connection) {
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

    if !email_regex.is_match(&request.email) || request.name.is_empty() || request.password.len() < 8 {
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
        password: password_hash.clone(),
        role: Role::User.as_int(),
        deactivated: false,
        email_setting: Some(0),
    };

    match diesel::insert_into(users)
        .values(&user)
        .execute(&mut database_connection) {
        Err(e) => {
            error!("while trying to insert trekkie user {:?}", e);
            return Err(ServerError::BadClientData);
        }
        _ => {}
    };

    match Identity::login(&req.extensions(), user.id.to_string().into()) {
        Ok(_) => {}
        Err(e) => {
            error!("cannot create session maybe the redis is not running. {:?}", e);
            return Err(ServerError::BadClientData);
        }
    };

    Ok(web::Json(CreateUserResponse {
        success: true,
        id: user.id.clone(),
        name: request.name.clone(),
        email: request.email.clone(),
        role: Role::User.as_int(),
        deactivated: false,
        email_setting: 0,
    }))
}

/// This endpoint takes an email address and a password if they are both valid 
/// 200 (Success) is returned together with a session cookie.
#[utoipa::path(
    post,
    path = "/user/login",
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
    ) ->  Result<web::Json<ResponseLogin>, ServerError> {

    let mut database_connection = match pool.get() {
         Ok(conn) => conn,
         Err(e) => {
             error!("cannot get connection from connection pool {:?}", e);
             return Err(ServerError::InternalError);
         }
    };

    use dump_dvb::schema::users::dsl::users;
    use dump_dvb::schema::users::email;

    match users.filter(email.eq(request.email.clone())).first::<User>(&mut database_connection) {
        Ok(user) => {
            if verify_password(&request.password, &user.password) {
                match Identity::login(&req.extensions(), user.id.to_string().into()) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("cannot create session maybe the redis is not running. {:?}", e);
                        return Err(ServerError::InternalError);
                    }
                };

                return Ok(web::Json(ResponseLogin {
                    id: user.id,
                    success: true,
                    name: user.name.clone(),
                    admin: (Role::from(user.role) == Role::Administrator),
                }));
            } else {
                debug!("Password does not match");
                return Err(ServerError::BadClientData);
            }
        }
        Err(e) => {
            error!("Err: {:?}", e);
            return Err(ServerError::InternalError);
        }
    };
}

/// removes the current session and therefore logging out the user
#[utoipa::path(
    get,
    path = "/user/logout",
    responses(
        (status = 200, description = "returnes old measurements"),

    ),
)]
pub async fn user_logout(
    user: Identity,
    _req: HttpRequest,
) ->  Result<HttpResponse, ServerError> {
    user.logout();
    Ok(HttpResponse::Ok().finish())
}

/// we can not really delete a user we mark the user as deactivated which strips 
/// him of every priviliges and function
#[utoipa::path(
    delete,
    path = "/user/delete",
    responses(
        (status = 200, description = "successfully deleted user"),
        (status = 500, description = "postgres pool error"),
        (status = 400, description = "invalid user id")
    ),
)]
pub async fn user_delete(
    pool: web::Data<DbPool>,
    identity: Identity,
    _req: HttpRequest,
    request: web::Json<UuidRequest>,
) ->  Result<HttpResponse, ServerError> {
    let mut database_connection = match pool.get() {
         Ok(conn) => conn,
         Err(e) => {
             error!("cannot get connection from connection pool {:?}", e);
             return Err(ServerError::InternalError);
         }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    if Role::from(session_user.role) != Role::Administrator {
        return Err(ServerError::Unauthorized);
    }

    use dump_dvb::schema::users::dsl::users;
    use dump_dvb::schema::users::{deactivated, id};

    match diesel::update(users.filter(id.eq(request.id)))
        .set((
            deactivated.eq(true),
        ))
        .get_result::<User>(&mut database_connection) {
        Ok(_) => {
            return Ok(HttpResponse::Ok().finish());
        },
        Err(e) => {
            error!("cannot deactivate user because of {:?}", e);
            return Err(ServerError::InternalError);
        }
    }
}

/// Update on of the following user properties (name, email, role, deactivated)
/// Only Admins or the user in question can modify attributes.
#[utoipa::path(
    put,
    path = "/user/update",
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
    request: web::Json<ModifyUserRequest>,
) ->  Result<HttpResponse, ServerError> {
    let mut database_connection = match pool.get() {
         Ok(conn) => conn,
         Err(e) => {
             error!("cannot get connection from connection pool {:?}", e);
             return Err(ServerError::InternalError);
         }
    };

    use dump_dvb::schema::users::dsl::users;
    use dump_dvb::schema::users::{deactivated, email, id, name, role};

    // user which should be modified
    let user = match users.filter(id.eq(request.id)).first::<User>(&mut database_connection) {
        Ok(found_user) => found_user,
        Err(_) => {
            return Err(ServerError::BadClientData)
        }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    // TODO: can be simplified
    // current user is admin he can do what ever he wants
    if Role::from(session_user.role) != Role::Administrator {
        // its fine if the user tries to modify him self or an administrator modifies other user
        if request.id != session_user.id {
            return Err(ServerError::Unauthorized);
        }

        // user shouldn't be able to modify his own role
        if request.role.is_some() {
            return Err(ServerError::Unauthorized);
        }
    }

    let user_name = user.name.clone().map_or_else(||{request.name.clone()}, |value| {Some(request.name.clone().unwrap_or(value))});
    let user_email = user.name.clone().map_or_else(||{request.email.clone()}, |value| {Some(request.email.clone().unwrap_or(value))});

    match diesel::update(users.filter(id.eq(request.id)))
        .set((
            name.eq(user_name),
            email.eq(user_email),
            role.eq(request.role.clone().map(|value| {value.as_int()}).unwrap_or(user.role)),
            deactivated.eq(request.deactivated.unwrap_or(user.deactivated)),
        ))
        .get_result::<User>(&mut database_connection) {
        Ok(_) => {
            Ok(HttpResponse::Ok().finish())
        },
        Err(error) => {
            error!("error occured while trying to update user {:?}", error);
            Err(ServerError::InternalError)
        }
    }
}

/// Returns information about the currently authenticated user
#[utoipa::path(
    get,
    path = "/user/info",
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
    request: web::Json<Option<UuidRequest>>,
) ->  Result<web::Json<User>, ServerError> {
    let mut database_connection = match pool.get() {
         Ok(conn) => conn,
         Err(e) => {
             error!("cannot get connection from connection pool {:?}", e);
             return Err(ServerError::InternalError);
         }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    let interesting_user_id = match &*request {
        Some(found_request) => {
            if Role::from(session_user.role) == Role::Administrator || session_user.id == found_request.id {
                found_request.id
            } else {
                return Err(ServerError::Unauthorized);
            }
        }
        None => session_user.id
    };

    use dump_dvb::schema::users::dsl::users;
    use dump_dvb::schema::users::id;
    

    // fetching interesting user
    let user = match users.filter(id.eq(interesting_user_id)).first::<User>(&mut database_connection) {
        Ok(found_user) => found_user,
        Err(_) => {
            return Err(ServerError::BadClientData)
        }
    };

    Ok(web::Json(user))
}


/// Returns information about the currently authenticated user
#[utoipa::path(
    get,
    path = "/user/list",
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
) ->  Result<web::Json<Vec<User>>, ServerError> {
    let mut database_connection = match pool.get() {
         Ok(conn) => conn,
         Err(e) => {
             error!("cannot get connection from connection pool {:?}", e);
             return Err(ServerError::InternalError);
         }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;
    
    if Role::from(session_user.role) != Role::Administrator {
        return Err(ServerError::Unauthorized);
    }

    use dump_dvb::schema::users::dsl::users;

    // fetching interesting user
    let users_list = match users.load::<User>(&mut database_connection) {
        Ok(found_user) => found_user,
        Err(_) => {
            return Err(ServerError::BadClientData)
        }
    };

    Ok(web::Json(users_list))
}

