import logging
import pytest
import time
from tests.common import config_reload
import urllib3
from urlparse import urlunparse

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state

RESTAPI_SERVER_START_WAIT_TIME = 15
RESTAPI_CONTAINER_NAME = 'restapi'

@pytest.fixture(scope="module", autouse=True)
def setup_restapi_server(duthosts, rand_one_dut_hostname, localhost):
    '''
    Create RESTAPI client certificates and copy the subject names to the config DB
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if RESTAPI is enabled on the device
    pyrequire(check_container_state(duthost, RESTAPI_CONTAINER_NAME, should_be_running=True), 
                "Test was not supported on devices which do not support RESTAPI!")

    # Create Root key
    local_command = "openssl genrsa -out restapiCA.key 2048"
    localhost.shell(local_command)

    # Create Root cert
    local_command = "openssl req \
                        -x509 \
                        -new \
                        -nodes \
                        -key restapiCA.key \
                        -sha256 \
                        -days 1825 \
                        -subj '/CN=test.restapi.sonic' \
                        -out restapiCA.pem"
    localhost.shell(local_command)

    # Create server key
    local_command = "openssl genrsa -out restapiserver.key 2048"
    localhost.shell(local_command)

    # Create server CSR
    local_command = "openssl req \
                        -new \
                        -key restapiserver.key \
                        -subj '/CN=test.server.restapi.sonic' \
                        -out restapiserver.csr"
    localhost.shell(local_command)

    # Sign server certificate
    local_command = "openssl x509 \
                        -req \
                        -in restapiserver.csr \
                        -CA restapiCA.pem \
                        -CAkey restapiCA.key \
                        -CAcreateserial \
                        -out restapiserver.crt \
                        -days 825 \
                        -sha256"
    localhost.shell(local_command)

    # Create client key
    local_command = "openssl genrsa -out restapiclient.key 2048"
    localhost.shell(local_command)

    # Create client CSR
    local_command = "openssl req \
                        -new \
                        -key restapiclient.key \
                        -subj '/CN=test.client.restapi.sonic' \
                        -out restapiclient.csr"
    localhost.shell(local_command)

    # Sign client certificate
    local_command = "openssl x509 \
                        -req \
                        -in restapiclient.csr \
                        -CA restapiCA.pem \
                        -CAkey restapiCA.key \
                        -CAcreateserial \
                        -out restapiclient.crt \
                        -days 825 \
                        -sha256"
    localhost.shell(local_command)

    # Copy CA certificate and server certificate over to the DUT
    duthost.copy(src='restapiCA.pem', dest='/etc/sonic/credentials/')
    duthost.copy(src='restapiserver.crt', dest='/etc/sonic/credentials/testrestapiserver.crt')
    duthost.copy(src='restapiserver.key', dest='/etc/sonic/credentials/testrestapiserver.key')

    # Set client certificate subject name in config DB
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'client_crt_cname' \
                    'test.client.restapi.sonic'"
    duthost.shell(dut_command)

    # Set CA cert path in config DB
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'ca_crt' \
                    '/etc/sonic/credentials/restapiCA.pem'"
    duthost.shell(dut_command)

    # Set server certificate path in config DB
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'server_crt' \
                    '/etc/sonic/credentials/testrestapiserver.crt'"
    duthost.shell(dut_command)
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'server_key' \
                    '/etc/sonic/credentials/testrestapiserver.key'"
    duthost.shell(dut_command)

    # Restart RESTAPI server with the updated config
    dut_command = "sudo systemctl restart restapi"
    duthost.shell(dut_command)
    time.sleep(RESTAPI_SERVER_START_WAIT_TIME)

    urllib3.disable_warnings()

    yield
    config_reload(duthost)
    # Delete all created certs
    local_command = "rm \
                        restapiCA.* \
                        restapiserver.* \
                        restapiclient.*"
    localhost.shell(local_command)

@pytest.fixture
def construct_url(duthosts, rand_one_dut_hostname):
    def get_endpoint(path):
        duthost = duthosts[rand_one_dut_hostname]
        RESTAPI_PORT = "8081"
        netloc = duthost.mgmt_ip+":"+RESTAPI_PORT
        try:
            tup = ('https', netloc, path, '', '', '')
            endpoint = urlunparse(tup)
        except Exception:
            logging.error("Invalid URL: "+endpoint)
            return None
        return endpoint
    return get_endpoint

@pytest.fixture
def vlan_members(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    VLAN_INDEX = 0
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vlan_interfaces = mg_facts["minigraph_vlans"].values()[VLAN_INDEX]["members"]
    return vlan_interfaces
