use super::{write_result, DeactivateRequest, Station, UserConnection, UuidRequest};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug)]
pub struct CreateStationRequest {
    pub name: String,
    pub token: Option<String>,
    pub public: bool,
    pub lat: f64,
    pub lon: f64,
    pub region: i64,
    pub radio: Option<i32>,
    pub architecture: Option<i32>,
    pub device: Option<i32>,
    pub elevation: Option<f64>,
    pub telegram_decoder_version: Option<Vec<i32>>,
    pub antenna: Option<i32>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ModifyStation {
    pub id: Uuid,
    pub name: Option<String>,
    pub public: Option<bool>,
    pub radio: Option<i32>,
    pub architecture: Option<i32>,
    pub device: Option<i32>,
    pub elevation: Option<f64>,
    pub telegram_decoder_version: Option<Vec<i32>>,
    pub antenna: Option<i32>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ApproveStation {
    pub id: Uuid,
    pub approved: bool,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UuidResponse {
    pub id: Uuid,
    pub success: bool,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ReturnToken {
    pub id: Uuid,
    pub token: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct CreateStationResponse {
    pub success: bool,
    pub id: Uuid,
    pub name: String,
    pub public: bool,
    pub lat: f64,
    pub lon: f64,
    pub region: i64,
    pub radio: Option<i32>,
    pub architecture: Option<i32>,
    pub device: Option<i32>,
    pub elevation: Option<f64>,
    pub telegram_decoder_version: Option<Vec<i32>>,
    pub antenna: Option<i32>,
    pub owner: Uuid,
}

fn owns_station(connection: &mut UserConnection, station_id: &Uuid) -> bool {
    let result_station = connection
        .database
        .lock()
        .unwrap()
        .query_station(station_id);

    if result_station.is_none() {
        return false;
    }

    let station = result_station.unwrap();

    station.owner == connection.user.as_ref().unwrap().id
}

pub fn create_station(connection: &mut UserConnection, request: CreateStationRequest) {
    if connection
        .database
        .lock()
        .unwrap()
        .check_region_exists(request.region)
        && connection.user.is_some()
    {
        let result_region = connection
            .database
            .lock()
            .unwrap()
            .query_region(request.region);

        if result_region.is_none() {
            write_result(connection, false, "this region does not exists");
            return;
        }

        let random_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let station = Station {
            id: Uuid::new_v4(),
            token: Some(random_token),
            name: request.name,
            public: request.public,
            lat: request.lat,
            lon: request.lon,
            region: request.region as i64,
            radio: request.radio,
            architecture: request.architecture,
            device: request.device,
            elevation: request.elevation,
            telegram_decoder_version: request.telegram_decoder_version,
            antenna: request.antenna,
            owner: connection.user.as_ref().unwrap().id,
            approved: false,
            deactivated: false,
        };

        let result = connection.database.lock().unwrap().create_station(&station);
        let serialized = serde_json::to_string(&CreateStationResponse {
            success: result,
            id: station.id,
            name: station.name,
            public: station.public,
            lat: station.lat,
            lon: station.lon,
            region: station.region,
            radio: station.radio,
            architecture: station.architecture,
            device: station.device,
            elevation: station.elevation,
            telegram_decoder_version: station.telegram_decoder_version,
            antenna: station.antenna,
            owner: station.owner,
        })
        .unwrap();

        connection
            .socket
            .write_message(tungstenite::Message::Text(serialized))
            .unwrap();
    } else {
        write_result(connection, false, "region doesn't exist or no user struct");
    }
}

pub fn list_stations(connection: &mut UserConnection) {
    let data = connection
        .database
        .lock()
        .unwrap()
        .list_stations(&connection.user.as_ref().unwrap().id);

    let serialized = serde_json::to_string(&data).unwrap();
    connection
        .socket
        .write_message(tungstenite::Message::Text(serialized))
        .unwrap();
}

pub fn delete_station(connection: &mut UserConnection, request: UuidRequest) {
    let mut result_query = false;
    if connection.user.as_ref().unwrap().is_admin() {
        result_query = connection
            .database
            .lock()
            .unwrap()
            .delete_station(&request.id);
    }

    write_result(connection, result_query, "deleted station");
}

pub fn modify_station(connection: &mut UserConnection, request: ModifyStation) {
    let result_station = connection
        .database
        .lock()
        .unwrap()
        .query_station(&request.id);

    if result_station.as_ref().is_none() {
        write_result(connection, false, "no station with this id");
        return;
    }

    let station = result_station.unwrap();
    let user_id = connection.user.as_ref().unwrap().id;

    if connection.user.as_ref().unwrap().is_admin() || station.owner == user_id {
        if !connection.database.lock().unwrap().create_history(&station) {
            write_result(connection, false, "cannot create history");
            return;
        }

        let response = connection
            .database
            .lock()
            .unwrap()
            .update_station(&Station {
                id: request.id,
                approved: station.approved,
                name: request.name.as_ref().unwrap_or(&station.name).to_string(),
                lat: station.lat,
                lon: station.lon,
                region: station.region,
                architecture: request.architecture,
                antenna: request.antenna,
                device: request.device,
                elevation: request.elevation,
                public: request.public.unwrap_or(station.public),
                radio: request.radio,
                telegram_decoder_version: request.telegram_decoder_version,
                token: None,
                owner: station.owner,
                deactivated: station.deactivated,
            });
        write_result(connection, response, "modified station");
    } else {
        write_result(
            connection,
            false,
            "you are not administrator of this station",
        );
    }
}

pub fn approve_station(connection: &mut UserConnection, request: ApproveStation) {
    if connection.user.as_ref().unwrap().is_admin() {
        let response = connection
            .database
            .lock()
            .unwrap()
            .set_approved(&request.id, request.approved);
        write_result(connection, response, "approve station");
    } else {
        write_result(connection, false, "you are not adminisrator");
    }
}

pub fn deactivate_station(connection: &mut UserConnection, request: DeactivateRequest) {
    let mut result_query = false;
    if connection.user.as_ref().unwrap().is_admin() || owns_station(connection, &request.id) {
        result_query = connection
            .database
            .lock()
            .unwrap()
            .set_deactivated_station(&request.id, request.deactivated);
    }

    write_result(connection, result_query, "deactivated station");
}

pub fn generate_token(connection: &mut UserConnection, request: UuidRequest) {
    if connection.user.as_ref().unwrap().is_admin() || owns_station(connection, &request.id) {
        let random_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let response = connection
            .database
            .lock()
            .unwrap()
            .set_token(&request.id, &random_token);

        if response {
            let serialized = serde_json::to_string(&ReturnToken {
                id: request.id,
                token: random_token,
            })
            .unwrap();
            connection
                .socket
                .write_message(tungstenite::Message::Text(serialized))
                .unwrap();
        } else {
            write_result(connection, false, "generated token");
        }
    } else {
        write_result(
            connection,
            false,
            "you are no administrator or owner of this station",
        );
    }
}

pub fn all_stations(connection: &mut UserConnection) {
    if connection.user.as_ref().unwrap().is_admin() {
        let response = connection.database.lock().unwrap().all_stations();
        let serialized = serde_json::to_string(&response).unwrap();
        connection
            .socket
            .write_message(tungstenite::Message::Text(serialized))
            .unwrap();
    } else {
        public_stations(connection);
    }
}

pub fn public_stations(connection: &mut UserConnection) {
    let response = connection.database.lock().unwrap().public_stations();
    let serialized = serde_json::to_string(&response).unwrap();
    connection
        .socket
        .write_message(tungstenite::Message::Text(serialized))
        .unwrap();
}
