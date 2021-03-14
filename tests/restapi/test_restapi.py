import pytest
import time
import logging
import requests

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

RESTAPI_PORT = "8081"

def test_heartbeat(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    url = "https://"+duthost.mgmt_ip+":"+RESTAPI_PORT+"/v1/state/heartbeat"
    r = requests.get(url, cert=('restapiclient.crt', 'restapiclient.key'), verify=False)
    assert r.status_code == 200