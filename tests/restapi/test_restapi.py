import pytest
import time
import logging
import requests
import json

from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

API_VERSION = 'v1'
GET = 'GET'
POST = 'POST'

CLIENT_CERT = 'restapiclient.crt'
CLIENT_KEY = 'restapiclient.key'

# Helper functions
def request(method, url, params=None):
    session = requests.Session()
    session.headers.update({'Content-type': 'application/json'})
    if method == GET:
        req = requests.Request('GET', url)
    elif method == POST:
        req = requests.Request('POST', url, data=params)
    req_p = req.prepare()
    clientcert=(CLIENT_CERT, CLIENT_KEY)
    response = session.send(req_p,
                    verify=False,
                    cert=clientcert
                )
    response.close()
    return response


# Test functions
def test_heartbeat(construct_url):
    path = API_VERSION+"/state/heartbeat"
    url = construct_url(path)
    if url:
        r = request(GET, url)
        pytest_assert(r.status_code == 200)
    else:
        logger.error("Malformed URL for "+path+"!")


def test_data_path(construct_url):
    path = API_VERSION+"/config/tunnel/decap/vxlan"
    params = '{"ip_addr": "10.3.152.32"}'
    url = construct_url(path)
    if url:
        r = request(POST, url, params)
        pytest_assert(r.status_code == 204)
    else:
        logger.error("Malformed URL for "+path+"!")

    path = API_VERSION+"/config/vrouter/vnet-guid-1"
    params = '{"vnid": 1000}'
    url = construct_url(path)
    if url:
        r = request(POST, url, params)
        pytest_assert(r.status_code == 204)
    else:
        logger.error("Malformed URL for "+path+"!")

    path = API_VERSION+"/config/vrouter/vnet-guid-1"
    url = construct_url(path)
    if url:
        r = request(GET, url)
        pytest_assert(r.status_code == 200)
    else:
        logger.error("Malformed URL for "+path+"!")

    path = API_VERSION+"/config/interface/vlan/1000"
    params = '{"vnet_id": "vnet-guid-1", "ip_prefix": "100.0.10.1/24"}'
    url = construct_url(path)
    if url:
        r = request(POST, url, params)
        pytest_assert(r.status_code == 204)
    else:
        logger.error("Malformed URL for "+path+"!")

    path = API_VERSION+"/config/interface/vlan/1000"
    url = construct_url(path)
    if url:
        r = request(GET, url)
        pytest_assert(r.status_code == 200)
    else:
        logger.error("Malformed URL for "+path+"!")
