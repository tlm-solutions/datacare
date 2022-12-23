import requests
import logging
import http.client as http_client

import random
import string

def get_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

register_form = {
    "name": "foobar",
    "email": get_random_string(8) + "@example.com",
    "password": "testtesttest"
}

login_form = {
    "email": "test@example.com",
    "password": "testtesttest"
}

# this enables higly verbose logging for debug purposes
#http_client.HTTPConnection.debuglevel = 1
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

with requests.Session() as s:
    create_user_response = s.post('https://datacare.staging.dvb.solutions/user/register', json = register_form)
    print(create_user_response)
    print(create_user_response.headers)
    print(create_user_response.content)

    list_user_response = s.get('https://datacare.staging.dvb.solutions/user/info')
    print(list_user_response)
    print(list_user_response.content)

