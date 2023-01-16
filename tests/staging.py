import requests
import json
import logging
import http.client as http_client

import random
import string


def get_random_string(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


register_form = {"name": "foobar", "email": get_random_string(8) + "@example.com", "password": "testtesttest"}

login_form = {"email": "test@test.com", "password": "test"}

update_form = {
    "id": "fill_me",
    "name": "SuccessFullTest",
    "role": 9,
}

region_create_form = {"name": "testregion", "transport_company": "testcompany"}

edit_region_form = {"name": "updatedregion", "transport_company": "updated"}

station_create_form = {"name": "test_station", "lat": 0.0, "lon": 0.0, "region": 0, "owner": "foo", "public": True}


station_update_form = {"name": "new_station_name", "lat": 54.0, "lon": 54.0, "public": True}


# this enables higly verbose logging for debug purposes
# http_client.HTTPConnection.debuglevel = 1
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

print_config = "minimal"


def handle_response(response, print_body=False):
    if response.status_code != 200:
        print(response.__dict__)
        raise Exception("An API call didnot return 200")
    else:
        if print_config == "minimal":
            print("[SUCCESS] {} {}".format(response.request.method, response.url))

        if print_config == "all":
            print(response.__dict__)

        if print_body:
            print(response.__dict__)


def test_region(s: requests.Session):
    create_region = s.post("https://datacare.staging.dvb.solutions/region", json=region_create_form)
    handle_response(create_region)
    region_id = json.loads(create_region.content)["id"]

    list_region = s.get("https://datacare.staging.dvb.solutions/region")
    handle_response(list_region)
    random_id = json.loads(list_region.content)[0]["id"]

    handle_response(s.get("https://datacare.staging.dvb.solutions/region/{}".format(0)))
    handle_response(s.put("https://datacare.staging.dvb.solutions/region/{}".format(region_id), json=edit_region_form))
    handle_response(s.delete("https://datacare.staging.dvb.solutions/region/{}".format(region_id)))


def test_station(s: requests.Session, user_id: str):
    station_create_form["owner"] = user_id
    create_station = s.post("https://datacare.staging.dvb.solutions/station", json=station_create_form)
    handle_response(create_station)
    station_id = json.loads(create_station.content)["id"]

    handle_response(s.get("https://datacare.staging.dvb.solutions/station"))
    handle_response(
        s.put("https://datacare.staging.dvb.solutions/station/{}".format(station_id), json=station_update_form)
    )
    handle_response(s.get("https://datacare.staging.dvb.solutions/station/{}".format(station_id)))
    handle_response(
        s.post("https://datacare.staging.dvb.solutions/station/{}/approve".format(station_id), json={"approve": True})
    )
    handle_response(s.delete("https://datacare.staging.dvb.solutions/station/{}".format(station_id)))

with requests.Session() as s:
    create_user_response = s.post("https://datacare.staging.dvb.solutions/auth/register", json=register_form)
    handle_response(create_user_response)

    handle_response(s.post("https://datacare.staging.dvb.solutions/auth/logout"))
    handle_response(s.post("https://datacare.staging.dvb.solutions/auth/login", json=login_form))
    response = s.get("https://datacare.staging.dvb.solutions/auth")
    handle_response(response)
    user_id = json.loads(response.content)["id"]

    test_region(s)
    test_station(s, user_id)

    handle_response(s.get("https://datacare.staging.dvb.solutions/user/{}".format(user_id)))
    handle_response(s.get("https://datacare.staging.dvb.solutions/user"))

    user_id = json.loads(create_user_response.content)["id"]
    update_form["id"] = user_id
    handle_response(s.put("https://datacare.staging.dvb.solutions/user/{}".format(user_id), json=update_form))
    handle_response(s.delete("https://datacare.staging.dvb.solutions/user/{}".format(user_id)))
