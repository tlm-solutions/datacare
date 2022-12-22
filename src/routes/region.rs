use super::{write_result, IdentifierRequest, UserConnection};

use dump_dvb::management::{InsertRegion, Region};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RegionRequest {
    pub name: String,
    pub transport_company: String,
    pub regional_company: Option<String>,
    pub frequency: Option<i64>,
    pub r09_type: Option<i32>,
    pub encoding: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyRegionRequest {
    id: i64,
    pub name: Option<String>,
    pub transport_company: Option<String>,
    pub regional_company: Option<Option<String>>,
    pub frequency: Option<Option<i64>>,
    pub r09_type: Option<Option<i32>>,
    pub encoding: Option<Option<i32>>,
}

fn admin(connection: &mut UserConnection) -> bool {
    connection.user.as_ref().unwrap().is_admin()
}

pub fn create_region(connection: &mut UserConnection, request: RegionRequest) {
    if !admin(connection) {
        write_result(connection, false, "you are not administrator");
        return;
    }

    let result = connection
        .database
        .lock()
        .unwrap()
        .create_region(&InsertRegion {
            id: None,
            name: request.name,
            transport_company: request.transport_company,
            regional_company: request.regional_company,
            frequency: request.frequency,
            r09_type: request.r09_type,
            encoding: request.encoding,
        });

    write_result(connection, result, "created region");
}

pub fn modify_region(connection: &mut UserConnection, request: ModifyRegionRequest) {
    if !admin(connection) {
        write_result(connection, false, "you are not administrator");
        return;
    }

    let result_region = connection.database.lock().unwrap().query_region(request.id);

    if result_region.is_none() {
        write_result(connection, false, "this region does not exists");
        return;
    }

    let region = result_region.unwrap();

    let result = connection.database.lock().unwrap().update_region(&Region {
        id: request.id,
        name: request.name.unwrap_or(region.name),
        transport_company: request
            .transport_company
            .unwrap_or(region.transport_company),
        regional_company: request.regional_company.unwrap_or(region.regional_company),
        frequency: request.frequency.unwrap_or(region.frequency),
        r09_type: request.r09_type.unwrap_or(region.r09_type),
        encoding: request.encoding.unwrap_or(region.encoding),
    });

    write_result(connection, result, "modified region");
}

pub fn delete_region(connection: &mut UserConnection, request: IdentifierRequest) {
    if !admin(connection) {
        write_result(connection, false, "you are not administrator");
        return;
    }

    let result = connection
        .database
        .lock()
        .unwrap()
        .delete_region(request.id.into());

    write_result(connection, result, "deleted region");
}

pub fn list_regions(connection: &mut UserConnection) {
    let data = connection.database.lock().unwrap().list_regions();

    let serialized = serde_json::to_string(&data).unwrap();
    connection
        .socket
        .write_message(tungstenite::Message::Text(serialized))
        .unwrap();
}
