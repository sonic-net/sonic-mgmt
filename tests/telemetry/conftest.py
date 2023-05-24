import logging
import pytest

from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until, wait_tcp_connection
from telemetry_utils import get_list_stdout, setup_telemetry_forpyclient, restore_telemetry_forpyclient

logger = logging.getLogger(__name__)

TELEMETRY_PORT = 50051


@pytest.fixture(scope="module")
def gnxi_path(ptfhost):
    """
    gnxi's location is updated from /gnxi to /root/gnxi
    in RP https://github.com/sonic-net/sonic-buildimage/pull/10599.
    But old docker-ptf images don't have this update,
    test case will fail for these docker-ptf images,
    because it should still call /gnxi files.
    For avoiding this conflict, check gnxi path before test and set GNXI_PATH to correct value.
    Add a new gnxi_path module fixture to make sure to set GNXI_PATH before test.
    """
    path_exists = ptfhost.stat(path="/root/gnxi/")
    if path_exists["stat"]["exists"] and path_exists["stat"]["isdir"]:
        gnxipath = "/root/gnxi/"
    else:
        gnxipath = "/gnxi/"
    return gnxipath


@pytest.fixture(scope="module", autouse=True)
def verify_telemetry_dockerimage(duthosts, enum_rand_one_per_hwsku_hostname):
    """If telemetry docker is available in image then return true
    """
    docker_out_list = []
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    docker_out = duthost.shell('docker images docker-sonic-telemetry', module_ignore_errors=False)['stdout_lines']
    docker_out_list = get_list_stdout(docker_out)
    matching = [s for s in docker_out_list if b"docker-sonic-telemetry" in s]
    if not (len(matching) > 0):
        pytest.skip("docker-sonic-telemetry is not part of the image")


@pytest.fixture(scope="module")
def setup_streaming_telemetry(duthosts, enum_rand_one_per_hwsku_hostname, localhost,  ptfhost, gnxi_path):
    """
    @summary: Post setting up the streaming telemetry before running the test.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    default_client_auth = setup_telemetry_forpyclient(duthost)

    # Wait until telemetry was restarted
    py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "telemetry"), "TELEMETRY not started.")
    logger.info("telemetry process restarted. Now run pyclient on ptfdocker")

    # Wait until the TCP port was opened
    dut_ip = duthost.mgmt_ip
    wait_tcp_connection(localhost, dut_ip, TELEMETRY_PORT, timeout_s=60)

    # pyclient should be available on ptfhost. If it was not available, then fail pytest.
    file_exists = ptfhost.stat(path=gnxi_path + "gnmi_cli_py/py_gnmicli.py")
    py_assert(file_exists["stat"]["exists"] is True)

    yield
    restore_telemetry_forpyclient(duthost, default_client_auth)
