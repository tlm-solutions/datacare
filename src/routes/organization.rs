use std::collections::HashMap;

use crate::{
    routes::auth::fetch_user,
    routes::{ListRequest, ListResponse, ServerError},
    DbPool,
};
use tlms::management::user::{Organization, Role};
use tlms::management::Station;
use tlms::schema::organizations::dsl::organizations;

use actix_identity::Identity;
use actix_web::{delete, get, post, put};
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};

use log::{error, warn};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Request body for creating an organization
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    /// Organization name
    pub name: String,
}

/// Request body for updating the information about organization
#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdateOrganizationRequest {
    /// Organization name
    pub name: String,
    /// If organization should be listed publicly
    pub public: bool,
    /// Organization owner
    pub owner: Uuid,
}

/// Request for forcibly deleting an organization
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ForceDeleteRequest {
    /// If true, organization will be forcefully deleted
    pub force: bool,
}

/// Response containing verbose information about organization
#[derive(Serialize, Deserialize, ToSchema)]
pub struct OrganizationInfoResponse {
    /// Information about the organization
    #[serde(flatten)]
    pub organization: Organization,

    /// List of associated organizations
    pub stations: Vec<Station>, // List of users in organization with their respective permissions
                                //pub users: HashMap<Uuid, Vec<Role>>,
}

/// Creates an organization with the owner of the currently authenticated user. The owner can be
/// changed later overwritten by the update endpoint.
#[utoipa::path(
    post,
    path = "/organization",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of the user"),
    ),
    request_body(
        content = CreateOrganizationRequest,
        description = "Information required to create an organization",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin"])
    ),
    responses(
        (status = 200, description = "Organization was successfully created", body = Organization),
        (status = 400, description = "Invalid user data"),
        (status = 403, description = "Invalid user permissions"),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[post("/organization")]
pub async fn orga_create(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    request: web::Json<CreateOrganizationRequest>,
) -> Result<web::Json<Organization>, ServerError> {
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

    // if the region doesn't exist we can directly dispose of the request

    let new_organization = Organization {
        id: Uuid::new_v4(),
        name: request.name.clone(),
        public: true,
        owner: user_session.user.id,
        deactivated: false,
    };

    match diesel::insert_into(organizations)
        .values(&new_organization)
        .execute(&mut database_connection)
    {
        Err(e) => {
            error!("while trying to insert organization {:?}", e);
            Err(ServerError::InternalError)
        }
        Ok(_) => Ok(web::Json(new_organization)),
    }
}

/// Returns a list of public organizations.
#[utoipa::path(
    get,
    path = "/organization",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
    ),
    request_body(
        content = ListRequest,
        description = "parameters for region list pageination",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "List of organizations was successfully returned", body = ListResponse<Organization>),
        (status = 400, description = "Invalid user data"),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[get("/organization")]
pub async fn orga_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    optional_params: Option<web::Query<ListRequest>>,
) -> Result<web::Json<ListResponse<Organization>>, ServerError> {
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

    let count: i64 = match organizations.count().get_result(&mut database_connection) {
        Ok(result) => result,
        Err(e) => {
            error!("database error {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    match organizations
        .limit(query_params.limit)
        .offset(query_params.offset)
        .order(tlms::schema::organizations::name)
        .load::<Organization>(&mut database_connection)
    {
        Ok(orga_list) => Ok(web::Json(ListResponse {
            count,
            elements: orga_list,
        })),
        Err(e) => {
            error!("error while querying database for organization {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Overwrites the specified organization with given data.
#[utoipa::path(
    put,
    path = "/organization/{id}",
    params(
        ("x-csrf-token" = String, Header, deprecated, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Organization identifier")
    ),
    request_body(
        content = UpdateOrganizationRequest,
        description = "Fields that will be overwritten by this endpoint",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin", "Role::EditOwnOrganization"])
    ),
    responses(
        (status = 200, description = "Organization got successfully updated", body = Organization),
        (status = 400, description = "Invalid user data"),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[put("/organization/{id}")]
pub async fn organization_update(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    identity: Identity,
    path: web::Path<(Uuid,)>,
    request: web::Json<UpdateOrganizationRequest>,
) -> Result<web::Json<Organization>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // get currently logged in user
    let user_session = fetch_user(identity, &mut database_connection)?;

    use tlms::schema::organizations::{id, name, owner, public};

    let relevant_organization = match organizations
        .filter(id.eq(path.0))
        .first::<Organization>(&mut database_connection)
    {
        Ok(possible_organization) => possible_organization,
        Err(e) => {
            error!("error while searching for mentioned organization {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // there multiple combinations that would allow a user to edit this organization
    // 1.) being admin
    // 2.) user owns this orga can has the EditOwnOrganization role
    if !(user_session.is_admin()
        || (user_session.user.id == relevant_organization.owner
            && user_session.has_role(&relevant_organization.id, &Role::EditOwnOrganization)))
    {
        return Err(ServerError::Forbidden);
    }

    // updating organization
    match diesel::update(organizations.filter(id.eq(path.0)))
        .set((
            name.eq(request.name.clone()),
            public.eq(request.public),
            owner.eq(request.owner),
        ))
        .get_result::<Organization>(&mut database_connection)
    {
        Ok(result) => Ok(web::Json(result)),
        Err(e) => {
            error!("cannot update organization because of {:?}", e);
            Err(ServerError::InternalError)
        }
    }
}

/// Tries to delete a organization. If this is not possible - deactivates it.
#[utoipa::path(
    delete,
    path = "/organization/{id}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Organization identifier")
    ),
    request_body(
        content = Option<ForceDeleteRequest>,
        description = "Optional request body. If the force flag it set the organization is permanently deleted.",
        content_type = "application/json"
    ),
    security(
        ("user_roles" = ["admin", "owner"])
    ),
    responses(
        (status = 200, description = "organization got successfully deleted"),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
#[delete("/organization/{id}")]
pub async fn organization_delete(
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

    use tlms::schema::organizations::{deactivated, id};

    let relevant_organization = match organizations
        .filter(id.eq(path.0))
        .first::<Organization>(&mut database_connection)
    {
        Ok(possible_organization) => possible_organization,
        Err(e) => {
            error!("error while searching for mentioned organization {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    // there multiple combinations that would allow a user to delete this organization
    // 1.) being admin
    // 2.) being the owner of the orga
    if !(user_session.is_admin() || (user_session.user.id == relevant_organization.owner)) {
        return Err(ServerError::Forbidden);
    }

    warn!(
        "trying to delete organization! : {}",
        relevant_organization.id
    );

    // actually deleting the row is only allowed if the user is administrator
    if user_session.is_admin() && request.is_some() && request.unwrap().force {
        match diesel::delete(organizations.filter(id.eq(path.0))).execute(&mut database_connection)
        {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot delete organizations because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    } else {
        match diesel::update(organizations.filter(id.eq(path.0)))
            .set((deactivated.eq(true),))
            .get_result::<Organization>(&mut database_connection)
        {
            Ok(_) => Ok(HttpResponse::Ok().finish()),
            Err(e) => {
                error!("cannot deactivate organizations because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    }
}

/// Returns detailed information about the organization
#[utoipa::path(
    get,
    path = "/organization/{id}",
    params(
        ("x-csrf-token" = String, Header, description = "Current csrf token of user"),
        ("id" = Uuid, Path, description = "Organization identifier")
    ),
    responses(
        (status = 200, description = "Organization information successfully returned", body = OrganizationInfoResponse),
        (status = 400, description = "Invalid user data"),
        (status = 500, description = "Postgres pool error"),
    ),
)]
#[get("/organization/{id}")]
pub async fn organization_info(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    path: web::Path<(Uuid,)>,
) -> Result<web::Json<OrganizationInfoResponse>, ServerError> {
    let mut database_connection = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot get connection from connection pool {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    use tlms::management::user::OrgUsersRelation;
    use tlms::schema::org_users_relations::dsl::org_users_relations;
    use tlms::schema::org_users_relations::organization as org_id;
    use tlms::schema::organizations::id;
    use tlms::schema::stations::dsl::stations;
    use tlms::schema::stations::organization as station_org;

    let relevant_organization = match organizations
        .filter(id.eq(path.0))
        .first::<Organization>(&mut database_connection)
    {
        Ok(possible_organization) => possible_organization,
        Err(e) => {
            error!("error while searching for mentioned organization {:?}", e);
            return Err(ServerError::InternalError);
        }
    };

    let station_list = match stations
        .filter(station_org.eq(path.0))
        .load::<Station>(&mut database_connection)
    {
        Ok(station_list) => station_list,
        Err(e) => {
            error!(
                "error while searching for stations belonging to this orga {:?}",
                e
            );
            return Err(ServerError::InternalError);
        }
    };

    // fetching interesting user
    let mut user_roles: HashMap<Uuid, Vec<Role>> = HashMap::new();

    match org_users_relations
        .filter(org_id.eq(path.0))
        .load::<OrgUsersRelation>(&mut database_connection)
    {
        Ok(user_list) => {
            for entry in user_list {
                user_roles
                    .entry(entry.user_id)
                    .or_insert_with(Vec::new)
                    .push(entry.role);
            }
        }
        Err(e) => {
            error!("error while listing rules {:?}", e);
            return Err(ServerError::BadClientData);
        }
    }

    Ok(web::Json(OrganizationInfoResponse {
        organization: relevant_organization,
        stations: station_list,
        //users: user_roles,
    }))
}
