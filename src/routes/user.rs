use crate::{
    routes::{auth::fetch_user, ListRequest, ListResponse, ServerError},
    DbPool,
};
use tlms::management::user::{hash_password, OrgUsersRelation, Role, User};
use tlms::schema::users::dsl::users;

use actix_identity::Identity;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};
use log::{error, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use utoipa::ToSchema;
use uuid::Uuid;

/// Request to register a new user
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct RegisterUserRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

/// Request to modify a user
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct ModifyUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_setting: Option<i32>,
    pub deactivated: Option<bool>,
}

/// Response after successful user creation
#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct CreateUserResponse {
    pub success: bool,
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub email_setting: i32,
    pub deactivated: bool,
}

#[derive(Deserialize, Serialize, ToSchema, Debug)]
pub struct SetOfRoles {
    pub roles: HashSet<Role>,
}

/// This endpoint registers a new user. Requirements to the submitted data:
///
/// - email: needs to be a valid email address
/// - password: needs to be at least 8 characters long
#[utoipa::path(
    post,
    path = "/user",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
    ),
    request_body(
        content = RegisterUserRequest,
        description = "Basic user information like username, password and email",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "User successfully registered", body = CreateUserResponse),
        (status = 400, description = "Invalid data"),
        (status = 500, description = "Postgres pool error"),
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
        deactivated: false,
        email_setting: Some(0),
        admin: false,
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
        deactivated: false,
        email_setting: 0,
    }))
}

/// Deactivates a user, strips him of all permissions
#[utoipa::path(
    delete,
    path = "/user/{id}",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "user ID")
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "Successfully deactivated user"),
        (status = 403, description = "Unauthorized"),
        (status = 500, description = "Postgres pool error"),
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

    // user can delete a account
    // 1.) The User making the request is admin
    // 2.) The user wants to delete its own account
    if !(session_user.is_admin() || session_user.user.id == path.0) {
        return Err(ServerError::Forbidden);
    }

    use tlms::schema::users::{deactivated, id};

    //TODO: remove roles
    //TODO: add force deletion
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

/// Updates the user. Following user properties can be updated:
///
/// - name
/// - email
/// - deactivated
///
/// Only Admins or the user in question can modify attributes.
#[utoipa::path(
    put,
    path = "/user/{id}",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "user ID")
    ),
    request_body(
        content = ModifyUserRequest,
        description = "Field to update for the specified user",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin", "user"])
    ),
    responses(
        (status = 200, description = "Successfully updated user data"),
        (status = 400, description = "Invalid user id"),
        (status = 403, description = "User doesn't have admin role or is this user"),
        (status = 500, description = "Postgres pool error"),
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

    use tlms::schema::users::{deactivated, email, id, name};

    // user which should be modified
    let user = match users
        .filter(id.eq(path.0))
        .first::<User>(&mut database_connection)
    {
        Ok(found_user) => found_user,
        Err(e) => {
            error!("database error while updating user {:?}", e);
            return Err(ServerError::BadClientData);
        }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    // the user can update its account when
    // 1.) The User is admin
    // 2.) The User wants to edit its own data
    if !(session_user.is_admin() || session_user.user.id == path.0) {
        return Err(ServerError::Forbidden);
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

/// Returns information about the specified user
#[utoipa::path(
    get,
    path = "/user/{id}",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "user ID")
    ),
    responses(
        (status = 200, description = "User information successfully returned", body = User),
        (status = 500, description = "Postgres pool error"),
        (status = 400, description = "Invalid user id")
    ),
)]
pub async fn user_info(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    path: web::Path<(Uuid,)>,
) -> Result<web::Json<User>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::schema::users::id;

    // fetching interesting user
    let user = match users
        .filter(id.eq(path.0))
        .first::<User>(&mut database_connection)
    {
        Ok(found_user) => found_user,
        Err(e) => {
            error!("while fetching user from database {:?}", e);
            return Err(ServerError::BadClientData);
        }
    };

    Ok(web::Json(user))
}

/// Returns list of users
#[utoipa::path(
    get,
    path = "/user",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
    ),
    request_body(
        content = Option<ListRequest>,
        description = "Pagination options",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "User list successfully returned", body = ListResponse<User>),
        (status = 500, description = "Postgres pool error"),
    ),
)]
pub async fn user_list(
    pool: web::Data<DbPool>,
    optional_params: Option<web::Form<ListRequest>>,
    _req: HttpRequest,
) -> Result<web::Json<ListResponse<User>>, ServerError> {
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

    let count: i64 = match users.count().get_result(&mut database_connection) {
        Ok(result) => result,
        Err(e) => {
            error!("database error while counting users {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // fetching interesting user
    match users
        .limit(query_params.limit)
        .offset(query_params.offset)
        .order(tlms::schema::users::name)
        .load::<User>(&mut database_connection)
    {
        Ok(user_list) => Ok(web::Json(ListResponse {
            count,
            elements: user_list,
        })),
        Err(e) => {
            error!("error while listing users {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Returns a list of roles of the user in the organization
#[utoipa::path(
    get,
    path = "/user/{user_id}/permissions/{org_id}",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
        ("user_id" = Uuid, Path, description = "user ID"),
        ("org_id" = Uuid, Path, description = "organization ID")
    ),
    security(
        ("user_roles" = ["admin", "user", "Role::EditOrgUserRoles"])
    ),
    responses(
        (status = 200, description = "Set of the user roles successfully returned", body = SetOfRoles),
        (status = 400, description = "Invalid user id"),
        (status = 403, description = "User doesn't have admin role, not user in question, or user doesn't have EditOrgUserRoles"),
        (status = 500, description = "Postgres pool error"),
    ),
)]
pub async fn user_get_roles(
    pool: web::Data<DbPool>,
    identity: Identity,
    path: web::Path<(Uuid, Uuid)>,
    _req: HttpRequest,
) -> Result<web::Json<SetOfRoles>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let session_user = fetch_user(identity, &mut database_connection)?;

    if !(session_user.is_admin()
        || session_user.has_role(&path.1, &Role::EditOrgUserRoles)
        || session_user.user.id == path.0)
    {
        return Err(ServerError::Forbidden);
    }

    use tlms::schema::org_users_relations::dsl::org_users_relations;
    use tlms::schema::org_users_relations::{organization, user_id};

    // fetching interesting user
    match org_users_relations
        .filter(user_id.eq(path.0))
        .filter(organization.eq(path.1))
        .load::<OrgUsersRelation>(&mut database_connection)
    {
        Ok(user_list) => Ok(web::Json(SetOfRoles {
            roles: user_list.iter().map(|x| x.role).collect(),
        })),
        Err(e) => {
            error!("error while listing rules {:?}", e);
            Err(ServerError::BadClientData)
        }
    }
}

/// Sets a list of roles for a user in a organization
#[utoipa::path(
    put,
    path = "/user/{user_id}/permissions/{org_id}",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
        ("user_id" = Uuid, Path, description = "User ID"),
        ("org_id" = Uuid, Path, description = "Organization ID")
    ),
    request_body(
        content = SetOfRoles,
        description = "List of roles to grant to the user",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin", "Role::EditOrgUserRoles"])
    ),
    responses(
        (status = 200, description = "Successfully set user roles in the organization"),
        (status = 400, description = "Invalid user id"),
        (status = 403, description = "User doesn't have admin role or user doesn't have EditOrgUserRoles"),
        (status = 500, description = "Postgres pool error"),
    ),
)]
pub async fn user_set_roles(
    pool: web::Data<DbPool>,
    identity: Identity,
    path: web::Path<(Uuid, Uuid)>,
    body: web::Form<SetOfRoles>,
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

    if !(session_user.is_admin() || session_user.has_role(&path.1, &Role::EditOrgUserRoles)) {
        return Err(ServerError::Forbidden);
    }

    let insert_values: Vec<OrgUsersRelation> = body
        .roles
        .iter()
        .map(|x| OrgUsersRelation {
            id: Uuid::new_v4(),
            organization: path.1,
            user_id: path.0,
            role: *x,
        })
        .collect();

    use tlms::schema::org_users_relations::dsl::org_users_relations;
    use tlms::schema::org_users_relations::{organization, user_id};

    if let Err(e) = diesel::delete(org_users_relations)
        .filter(user_id.eq(path.0))
        .filter(organization.eq(path.1))
        .execute(&mut database_connection)
    {
        error!("cannot delete roles because of {:?}", e);
        return Err(ServerError::BadClientData);
    };

    if let Err(e) = diesel::insert_into(org_users_relations)
        .values(&insert_values)
        .execute(&mut database_connection)
    {
        error!("while trying to insert user {:?}", e);
        return Err(ServerError::BadClientData);
    };

    Ok(HttpResponse::Ok().finish())
}
