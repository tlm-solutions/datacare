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
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::query_dsl::RunQueryDsl;
use diesel::{ExpressionMethods, QueryDsl};

use log::{error, warn};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// containes the value for approved that should be set
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    pub name: String,
}

/// containes the value for approved that should be set
#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdateOrganizationRequest {
    pub name: String,
    pub public: bool,
    pub owner: Uuid,
}

/// containes the value for approved that should be set
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ForceDeleteRequest {
    pub force: bool,
}

/// containes the value for approved that should be set
#[derive(Serialize, Deserialize, ToSchema)]
pub struct OrganizationInfoResponse {
    /// info about the organization
    #[serde(flatten)]
    pub organization: Organization,

    /// list of associated organizations
    pub stations: Vec<Station>,

    /// list of user persmissions
    pub users: HashMap<Uuid, Vec<Role>>,
}

/// will create a organization with the owner of the currently authenticated user
#[utoipa::path(
    post,
    path = "/organization",
    responses(
        (status = 200, description = "organization was successfully created", body = Organization),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
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
            Err(ServerError::BadClientData)
        }
        Ok(_) => Ok(web::Json(new_organization)),
    }
}

/// will return a list of organizations
#[utoipa::path(
    get,
    path = "/organization",
    responses(
        (status = 200, description = "list of organizations was successfully returned", body = Vec<Organization>),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
pub async fn orga_list(
    pool: web::Data<DbPool>,
    _req: HttpRequest,
    optional_params: Option<web::Form<ListRequest>>,
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
            Err(ServerError::BadClientData)
        }
    }
}

/// will edit a organization
#[utoipa::path(
    put,
    path = "/organization/{id}",
    responses(
        (status = 200, description = "organization got successfully updated", body = Organization),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
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

/// will try to delete a organization if this is not possible we will deactivate it.
#[utoipa::path(
    delete,
    path = "/organization/{id}",
    responses(
        (status = 200, description = "organization got successfully deleted"),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
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
                error!("cannot deactivate user because of {:?}", e);
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
                error!("cannot deactivate user because of {:?}", e);
                Err(ServerError::InternalError)
            }
        }
    }
}

/// will return information about the requested organization
#[utoipa::path(
    get,
    path = "/organization/{id}",
    responses(
        (status = 200, description = "organization information successfully returned"),
        (status = 400, description = "invalid user data"),
        (status = 500, description = "postgres pool error"),
    ),
)]
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
                    .push(Role::try_from(entry.role).unwrap());
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
        users: user_roles,
    }))
}
