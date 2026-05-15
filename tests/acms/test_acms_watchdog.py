import json
import logging

import pytest

from tests.acms.helper import container_name

from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CURL_HTTP_CODE_CMD = "curl -s -o /dev/null -w \%\{http_code\} http://localhost:51001"   # noqa: W605
CURL_CMD = "curl http://localhost:51001"   # ACMS watchdog http endpoint is 51001


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


def test_acms_healthy(duthosts,
                      enum_rand_one_per_hwsku_hostname,
                      verify_acms_containers_running,
                      setup_ca_pem_cert):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command(CURL_CMD, module_ignore_errors=True)["stdout"]
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        pytest.fail("Invalid JSON response from ACMS watchdog: {}".format(output))

    pytest_assert(len(response) > 0, "ACMS watchdog returned an empty response")

    # Dynamically check all keys returned by the watchdog
    for key in response:
        pytest_assert(response[key] == "OK",
                      "ACMS watchdog check failed for {}: {}".format(key, response[key]))

    output = duthost.command(CURL_HTTP_CODE_CMD, module_ignore_errors=True)["stdout"]
    pytest_assert(output == "200", "ACMS watchdog should be healthy")


def test_acms_missing_ca_pem(duthosts,
                             enum_rand_one_per_hwsku_hostname,
                             verify_acms_containers_running):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command(CURL_CMD, module_ignore_errors=True)["stdout"]
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        pytest.fail("Invalid JSON response from ACMS watchdog: {}".format(output))

    # Verify check_ca_pem reports the expected failure
    msg = response.get("check_ca_pem", "")
    pytest_assert(msg.startswith("FAIL cannot access") and
                  "ROOT_CERTIFICATE.pem" in msg and
                  "No such file or directory" in msg,
                  "Unexpected results for check_ca_pem: {}".format(msg))

    # All other keys should still be OK
    for key in response:
        if key != "check_ca_pem":
            pytest_assert(response[key] == "OK",
                          "ACMS watchdog check failed for {}: {}".format(key, response[key]))

    output = duthost.command(CURL_HTTP_CODE_CMD, module_ignore_errors=True)["stdout"]
    pytest_assert(output == "500", "ACMS watchdog should be unhealthy")
