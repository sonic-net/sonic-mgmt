import json
import logging
import pytest

from tests.acms.helper import container_name, watchdog_container_name
from tests.acms.helper import create_acms_conf
from tests.common.helpers.assertions import pytest_assert
from tests.acms.helper import TEST_DATA_CLOUD


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

DOCKER_EXEC_CMD = "docker exec {} bash -c "
NSENTER_CMD = "nsenter --target 1 --pid --mount --uts --ipc --net"
ACMS_WATCHDOG_CMD = DOCKER_EXEC_CMD.format(watchdog_container_name) + "'{} {}'"
CURL_HTTP_CODE_CMD = "curl -s -o /dev/null -w \%\{http_code\} http://localhost:51001"   # noqa: W605
CURL_CMD = "curl http://localhost:51001"   # ACMS watchdog http endpoint is 51001
CA_PEM = "/etc/sonic/credentials/AME_ROOT_CERTIFICATE.pem"
ALLOWED_ISSUERS = {
    "issuer=C = US, O = Microsoft Corporation, CN = Commercial Cloud Root CA R1",
    "issuer=DC = GBL, DC = AME, CN = ameroot",
}


@pytest.fixture(scope='function', autouse=True)
def setup_certs(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "docker exec %s supervisorctl stop start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop acms" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)

    yield

    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)


def check_ca_cert(duthost, cert_name):
    """
    Check if CA cert is downloaded.
    """
    dut_command = "docker exec %s ls /etc/sonic/credentials" % container_name
    command_result = duthost.shell(dut_command)
    return cert_name in command_result["stdout"]


@pytest.fixture(scope='function', params=TEST_DATA_CLOUD, ids=[d["cloudtype"] for d in TEST_DATA_CLOUD])
def setup_ca_pem_cert(request, duthosts, rand_one_dut_hostname, creds):
    """
    Test ACMS CA_cert_downloader.py functionality.
    """
    test_data = request.param
    duthost = duthosts[rand_one_dut_hostname]
    http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    if ("http" not in http_proxy):
        pytest.skip("ACMS does not work without http proxy: " + http_proxy)
    cloudtype = test_data["cloudtype"]
    region_list = test_data["region_list"]
    for region in region_list:
        logger.info("Testing region %s in cloud %s" % (region, cloudtype))
        dut_command = "rm /var/opt/msft/client/*"
        duthost.shell(dut_command, module_ignore_errors=True)
        dut_command = "rm /etc/sonic/credentials/*"
        duthost.shell(dut_command, module_ignore_errors=True)
        create_acms_conf(region, cloudtype, duthost, "/var/opt/msft/client/acms_secrets.ini")
        dut_command = 'timeout %ds docker exec -e http_proxy="%s" -e https_proxy="%s" %s CA_cert_downloader.py' \
            % (5, http_proxy, https_proxy, container_name)
        duthost.shell(dut_command, module_ignore_errors=True)
        if check_ca_cert(duthost, 'ROOT_CERTIFICATE.pem'):
            return
        logger.info("Failed to download CA cert for cloud %s region %s" % (cloudtype, region))
        dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
        duthost.shell(dut_command, module_ignore_errors=True)
    pytest.fail("Failed to download CA cert for %s" % cloudtype)


def test_acms_multi_root_ca_pem(duthosts,
                                enum_rand_one_per_hwsku_hostname,
                                setup_ca_pem_cert):
    """
    Validates the Root CA PEM bundle:
     1) Every issuer must be in the ALLOWED_ISSUERS set
     2) At least one CCME cert present
     3) At least one AME cert present
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    cmd = f"openssl crl2pkcs7 -nocrl -certfile {CA_PEM} | openssl pkcs7 -print_certs -noout"
    output = duthost.shell(cmd)["stdout"]

    # Check issuers
    issuers = [line.strip() for line in output.splitlines() if line.startswith("issuer=")]
    for issuer in issuers:
        pytest_assert(issuer in ALLOWED_ISSUERS, f"Unexpected issuer found: {issuer}")

    # Check CCME cert
    pytest_assert("CN = CCME" in output, f"FAIL no CCME certificate found in {CA_PEM}")

    # Check AME cert
    pytest_assert("CN = AME" in output, f"FAIL no AME certificate found in {CA_PEM}")


def test_acms_healthy(duthosts,
                      enum_rand_one_per_hwsku_hostname,
                      verify_acms_containers_running,
                      setup_ca_pem_cert):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command(ACMS_WATCHDOG_CMD.format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        pytest.fail("Invalid JSON response from ACMS watchdog: {}".format(output))

    # Define expected keys
    expected_keys = [
        "check_ca_pem"
    ]

    # Check if all expected keys exist and have the value "OK"
    for key in expected_keys:
        pytest_assert(response.get(key) == "OK",
                      "ACMS watchdog check failed for {}: {}".format(key, response.get(key)))

    output = duthost.command(ACMS_WATCHDOG_CMD.format(NSENTER_CMD, CURL_HTTP_CODE_CMD),
                             module_ignore_errors=True)["stdout"]
    pytest_assert(output == "200", "ACMS watchdog should be healthy")


def test_acms_missing_ca_pem(duthosts,
                             enum_rand_one_per_hwsku_hostname,
                             verify_acms_containers_running):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command(ACMS_WATCHDOG_CMD.format(NSENTER_CMD, CURL_CMD), module_ignore_errors=True)["stdout"]
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        pytest.fail("Invalid JSON response from ACMS watchdog: {}".format(output))

    # Define expected keys
    expected_keys = [
        "check_ca_pem"
    ]

    # Check if all expected keys exist and have the value "OK"
    for key in expected_keys:
        msg = response.get(key, "")
        pytest_assert(msg.startswith("FAIL cannot access") and
                      "ROOT_CERTIFICATE.pem" in msg and
                      "No such file or directory" in msg,
                      "Unexpected results for {}: {}".format(key, response.get(key)))

    output = duthost.command(ACMS_WATCHDOG_CMD.format(NSENTER_CMD, CURL_HTTP_CODE_CMD),
                             module_ignore_errors=True)["stdout"]
    pytest_assert(output == "500", "ACMS watchdog should be unhealthy")
