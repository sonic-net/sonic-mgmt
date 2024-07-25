import logging
import pytest
import os
import sys

from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until, wait_tcp_connection, get_mgmt_ipv6
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.telemetry.telemetry_utils import get_list_stdout, setup_telemetry_forpyclient, restore_telemetry_forpyclient
from contextlib import contextmanager

EVENTS_TESTS_PATH = "./telemetry/events"
sys.path.append(EVENTS_TESTS_PATH)

BASE_DIR = "logs/telemetry"
DATA_DIR = os.path.join(BASE_DIR, "files")

logger = logging.getLogger(__name__)


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
    docker_out = duthost.shell('docker images', module_ignore_errors=False)['stdout_lines']
    docker_out_list = get_list_stdout(docker_out)
    matching = [s for s in docker_out_list if b"docker-sonic-gnmi" in s or b"docker-sonic-telemetry" in s]
    if not (len(matching) > 0):
        pytest.skip("docker-sonic-gnmi and docker-sonic-telemetry are not part of the image")


def check_gnmi_config(duthost):
    cmd = 'sonic-db-cli CONFIG_DB HGET "GNMI|gnmi" port'
    port = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return port != ""


def create_gnmi_config(duthost):
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|gnmi' port 50052"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|gnmi' client_auth true"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "ca_crt /etc/sonic/telemetry/dsmsroot.cer"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "server_crt /etc/sonic/telemetry/streamingtelemetryserver.cer"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "server_key /etc/sonic/telemetry/streamingtelemetryserver.key"
    duthost.shell(cmd, module_ignore_errors=True)


def delete_gnmi_config(duthost):
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' port"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' client_auth"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' ca_crt"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_crt"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_key"
    duthost.shell(cmd, module_ignore_errors=True)


@pytest.fixture(scope="module")
def setup_streaming_telemetry(request, duthosts, enum_rand_one_per_hwsku_hostname, localhost, ptfhost, gnxi_path):
    with _context_for_setup_streaming_telemetry(request, duthosts, enum_rand_one_per_hwsku_hostname,
                                                localhost, ptfhost, gnxi_path) as result:
        yield result


@pytest.fixture(scope="function")
def setup_streaming_telemetry_func(request, duthosts, enum_rand_one_per_hwsku_hostname, localhost, ptfhost, gnxi_path):
    with _context_for_setup_streaming_telemetry(request, duthosts, enum_rand_one_per_hwsku_hostname,
                                                localhost, ptfhost, gnxi_path) as result:
        yield result


@contextmanager
def _context_for_setup_streaming_telemetry(request, duthosts, enum_rand_one_per_hwsku_hostname,
                                           localhost, ptfhost, gnxi_path):
    """
    @summary: Post setting up the streaming telemetry before running the test.
    """
    is_ipv6 = request.param
    try:
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        has_gnmi_config = check_gnmi_config(duthost)
        if not has_gnmi_config:
            create_gnmi_config(duthost)
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        default_client_auth = setup_telemetry_forpyclient(duthost)

        if default_client_auth == "true":
            duthost.shell('sonic-db-cli CONFIG_DB HSET "%s|gnmi" "client_auth" "false"' % (env.gnmi_config_table),
                          module_ignore_errors=False)
            duthost.shell("systemctl reset-failed %s" % (env.gnmi_container))
            duthost.service(name=env.gnmi_container, state="restarted")
        else:
            logger.info('client auth is false. No need to restart telemetry')

        # Wait until telemetry was restarted
        py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
                  "%s not started." % (env.gnmi_container))
        logger.info("telemetry process restarted. Now run pyclient on ptfdocker")

        # Wait until the TCP port was opened
        dut_ip = duthost.mgmt_ip
        if is_ipv6:
            dut_ip = get_mgmt_ipv6(duthost)
        wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60)

        # pyclient should be available on ptfhost. If it was not available, then fail pytest.
        if is_ipv6:
            cmd = "docker cp %s:/usr/sbin/gnmi_get ~/" % (env.gnmi_container)
            ret = duthost.shell(cmd)['rc']
            py_assert(ret == 0)
        else:
            file_exists = ptfhost.stat(path=gnxi_path + "gnmi_cli_py/py_gnmicli.py")
            py_assert(file_exists["stat"]["exists"] is True)
    except RunAnsibleModuleFail as e:
        logger.info("Error happens in the setup period of setup_streaming_telemetry, recover the telemetry.")
        restore_telemetry_forpyclient(duthost, default_client_auth)
        raise e

    yield
    restore_telemetry_forpyclient(duthost, default_client_auth)
    if not has_gnmi_config:
        delete_gnmi_config(duthost)


def do_init(duthost):
    for i in [BASE_DIR, DATA_DIR]:
        try:
            os.mkdir(i)
        except OSError as e:
            logger.info("Dir/file already exists: {}, skipping mkdir".format(e))

        duthost.copy(src="telemetry/validate_yang_events.py", dest="~/")


@pytest.fixture(scope="module")
def test_eventd_healthy(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_streaming_telemetry, gnxi_path):
    """
    @summary: Test eventd heartbeat before testing all testcases
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    features_dict, succeeded = duthost.get_feature_status()
    if succeeded and ('eventd' not in features_dict or features_dict['eventd'] == 'disabled'):
        pytest.skip("eventd is disabled on the system")

    do_init(duthost)

    module = __import__("eventd_events")

    duthost.shell("systemctl restart eventd")

    py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "eventd"), "eventd not started.")

    module.test_event(duthost, gnxi_path, ptfhost, DATA_DIR, None)

    logger.info("Completed test file: {}".format("eventd_events test completed."))
