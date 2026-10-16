import logging
import pytest
import urllib3
import ipaddress
from datetime import datetime, timedelta, timezone
from six.moves.urllib.parse import urlunparse

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

from helper import apply_cert_config

RESTAPI_CONTAINER_NAME = 'restapi'


@pytest.fixture(scope="module")
def setup_loganalyzer(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="TestRestapi")
    loganalyzer.expect_regex = [".*restapi#.*https endpoint started.*"]
    return loganalyzer


@pytest.fixture(scope="module", autouse=True)
def setup_restapi_server(duthosts, rand_one_dut_hostname, localhost, setup_loganalyzer):
    '''
    Create RESTAPI client certificates and copy the subject names to the config DB
    '''
    duthost = duthosts[rand_one_dut_hostname]
    loganalyzer = setup_loganalyzer

    # Check if RESTAPI is enabled on the device
    pyrequire(check_container_state(duthost, RESTAPI_CONTAINER_NAME, should_be_running=True),
              "Test was not supported on devices which do not support RESTAPI!")

    # Create Root key
    local_command = "openssl genrsa -out restapiCA.key 2048"
    localhost.shell(local_command)

    # Set up validity windows. Backdate notBefore by 1 month so clock skew between
    # the test runner and the DUT does not cause a premature/expired cert error.
    # OpenSSL 3.0 lacks the x509 -not_before option, so use 'openssl ca' with
    # -startdate/-enddate to set explicit validity windows.
    now = datetime.now(timezone.utc)
    cert_not_before = (now - timedelta(days=30)).strftime("%Y%m%d%H%M%SZ")
    ca_not_after = (now + timedelta(days=1825)).strftime("%Y%m%d%H%M%SZ")
    cert_not_after = (now + timedelta(days=825)).strftime("%Y%m%d%H%M%SZ")
    localhost.shell("mkdir -p restapi_newcerts && touch restapi_index.txt && echo 01 > restapi_serial")
    ca_config = ("[ca]\\ndefault_ca = CA_default\\n"
                 "[CA_default]\\ndatabase = restapi_index.txt\\nserial = restapi_serial\\n"
                 "new_certs_dir = restapi_newcerts\\ndefault_md = sha256\\n"
                 "policy = policy_any\\ncopy_extensions = none\\n"
                 "[policy_any]\\ncommonName = supplied\\n"
                 "[v3_ca]\\nbasicConstraints = critical,CA:TRUE\\n"
                 "keyUsage = critical,keyCertSign,cRLSign\\nsubjectKeyIdentifier = hash\\n")
    localhost.shell(f"printf '{ca_config}' > restapi_ca.cnf")

    # Create Root CSR and self-sign it as the CA cert with a backdated notBefore.
    local_command = "openssl req \
                        -new \
                        -key restapiCA.key \
                        -subj '/CN=test.restapi.sonic' \
                        -out restapiCA.csr"
    localhost.shell(local_command)
    local_command = f"openssl ca \
                        -batch \
                        -config restapi_ca.cnf \
                        -selfsign \
                        -keyfile restapiCA.key \
                        -in restapiCA.csr \
                        -out restapiCA.pem \
                        -extensions v3_ca \
                        -startdate {cert_not_before} \
                        -enddate {ca_not_after} \
                        -notext \
                        -md sha256"
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

    # Sign server certificate, reusing the backdated validity window and CA
    # database set up for the CA certificate above.
    local_command = f"openssl ca \
                        -batch \
                        -config restapi_ca.cnf \
                        -cert restapiCA.pem \
                        -keyfile restapiCA.key \
                        -in restapiserver.csr \
                        -out restapiserver.crt \
                        -startdate {cert_not_before} \
                        -enddate {cert_not_after} \
                        -notext \
                        -md sha256"
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

    # Sign client certificate, reusing the same backdated validity window and CA
    # database set up for the CA certificate above.
    local_command = f"openssl ca \
                        -batch \
                        -config restapi_ca.cnf \
                        -cert restapiCA.pem \
                        -keyfile restapiCA.key \
                        -in restapiclient.csr \
                        -out restapiclient.crt \
                        -startdate {cert_not_before} \
                        -enddate {cert_not_after} \
                        -notext \
                        -md sha256"
    localhost.shell(local_command)

    # Copy CA certificate and server certificate over to the DUT
    duthost.copy(src='restapiCA.pem', dest='/etc/sonic/credentials/')
    duthost.copy(src='restapiserver.crt',
                 dest='/etc/sonic/credentials/testrestapiserver.crt')
    duthost.copy(src='restapiserver.key',
                 dest='/etc/sonic/credentials/testrestapiserver.key')

    try:
        with loganalyzer:
            apply_cert_config(duthost)
        urllib3.disable_warnings()
        yield
    except LogAnalyzerError as err:
        pytest.fail(str(err))
    finally:
        # Perform a config load_minigraph to ensure config_db is not corrupted
        config_reload(duthost, config_source='minigraph')
        # Delete all created certs
        local_command = "rm -rf \
                            restapiCA.* \
                            restapiserver.* \
                            restapiclient.* \
                            restapi_ca.cnf \
                            restapi_index.txt* \
                            restapi_serial* \
                            restapi_newcerts"
        localhost.shell(local_command)


@pytest.fixture
def construct_url(duthosts, rand_one_dut_hostname):
    def get_endpoint(path):
        duthost = duthosts[rand_one_dut_hostname]
        RESTAPI_PORT = "8081"

        # Handle IPv6 addresses by wrapping them in square brackets
        try:
            ip_obj = ipaddress.ip_address(duthost.mgmt_ip)
            if ip_obj.version == 6:
                netloc = "[{}]:{}".format(duthost.mgmt_ip, RESTAPI_PORT)
            else:
                netloc = "{}:{}".format(duthost.mgmt_ip, RESTAPI_PORT)
        except ValueError:
            # If it's not a valid IP address, treat it as hostname and use as-is
            netloc = "{}:{}".format(duthost.mgmt_ip, RESTAPI_PORT)

        try:
            tup = ('https', netloc, path, '', '', '')
            endpoint = urlunparse(tup)
        except Exception:
            logging.error("Invalid URL")
            return None
        return endpoint
    return get_endpoint


@pytest.fixture
def vlan_members(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    VLAN_INDEX = 0
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if mg_facts["minigraph_vlans"] != {}:
        vlan_interfaces = list(mg_facts["minigraph_vlans"].values())[
            VLAN_INDEX]["members"]
        if vlan_interfaces is not None:
            return vlan_interfaces
    return []


@pytest.fixture
def is_support_warm_fast_reboot(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    support_warm_fast_reboot = True
    if 'isolated' in duthosts.tbinfo['topo']['name'] or \
            duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_smartswitch"):
        support_warm_fast_reboot = False
        logging.info("Skipping warm and fast reboot tests for isolated topology or smartswitch")
        logging.info("Applying cert config")
        apply_cert_config(duthost)

    yield support_warm_fast_reboot
