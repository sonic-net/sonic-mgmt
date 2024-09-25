import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, wait_tcp_connection
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from telemetry_utils import generate_client_cli
from telemetry_utils import archive_telemetry_certs, unarchive_telemetry_certs, rotate_telemetry_certs

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

METHOD_GET = "get"
SUBMODE_POLL = 2

"""

Testing cert rotation by telemetry

1. Test that telemetry will stay up without certs
2. Test that when we serve one successful request, delete certs, second request will not work
3. Test that when we have no certs, first request will fail, rotate certs, second request will work
4. Test that when we have certs, request will succeed, rotate certs, second request will also succeed

"""


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_telemetry_not_exit(duthosts, rand_one_dut_hostname, setup_streaming_telemetry, localhost):
    """ Test that telemetry server will not exit when certs are missing. We will shutdown telemetry,
    remove certs and verify that telemetry is up and running.
    """
    logger.info("Testing telemetry server will startup without certs")

    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

    # Shutting down telemetry
    duthost.service(name=env.gnmi_container, state="stopped")

    # Remove certs
    archive_telemetry_certs(duthost)

    # Bring back telemetry
    duthost.shell("systemctl reset-failed %s" % (env.gnmi_container), module_ignore_errors=True)
    duthost.service(name=env.gnmi_container, state="restarted")

    # Wait until telemetry is active and running
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
                  "%s not started." % (env.gnmi_container))

    # Restore certs
    unarchive_telemetry_certs(duthost)

    # Wait for telemetry server to listen on port
    dut_ip = duthost.mgmt_ip
    wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60)


def test_telemetry_post_cert_del(duthosts, rand_one_dut_hostname, ptfhost, gnxi_path, localhost):
    """ Test that telemetry server with certificates will accept requests.
    When certs are deleted, subsequent requests will not work.
    """
    logger.info("Testing telemetry server post cert add")

    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

    # Initial request should pass with certs
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET,
                              target="OTHERS", xpath="proc/uptime")
    ret = ptfhost.shell(cmd)['rc']
    assert ret == 0, "Telemetry server request should complete with certs"

    # Remove certs
    archive_telemetry_certs(duthost)

    # Requests should fail without certs
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET,
                              target="OTHERS", xpath="proc/uptime")
    ret = ptfhost.shell(cmd, module_ignore_errors=True)['rc']
    assert ret != 0, "Telemetry server request should fail without certs"

    # Restore certs
    unarchive_telemetry_certs(duthost)

    # Wait for telemetry server to listen on port
    dut_ip = duthost.mgmt_ip
    wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60)


def test_telemetry_post_cert_add(duthosts, rand_one_dut_hostname, ptfhost, gnxi_path, localhost):
    """ Test that telemetry server with no certificates will reject requests.
    When certs are rotated, subsequent requests will work.
    """
    logger.info("Testing telemetry server post cert add")

    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

    # Remove certs
    archive_telemetry_certs(duthost)

    # Initial request should fail without certs
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET,
                              target="OTHERS", xpath="proc/uptime")
    ret = ptfhost.shell(cmd, module_ignore_errors=True)['rc']
    assert ret != 0, "Telemetry server request should fail without certs"

    # Rotate certs
    rotate_telemetry_certs(duthost, localhost)

    # Wait for telemetry server to listen on port
    dut_ip = duthost.mgmt_ip
    wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60)

    # Requests should successfully complete with certs
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET,
                              target="OTHERS", xpath="proc/uptime")
    ret = ptfhost.shell(cmd)['rc']
    assert ret == 0, "Telemetry server request should complete with certs"


def test_telemetry_cert_rotate(duthosts, rand_one_dut_hostname, ptfhost, gnxi_path, localhost):
    """ Test that telemetry server with certs will serve requests.
    When certs are rotated, subsequent requests will work.
    """
    logger.info("Testing telemetry server cert rotate")

    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

    # Initial request should complete with certs
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET,
                              target="OTHERS", xpath="proc/uptime")
    ret = ptfhost.shell(cmd)['rc']
    assert ret == 0, "Telemetry server request should fail without certs"

    # Rotate certs
    rotate_telemetry_certs(duthost, localhost)

    # Wait for telemetry server to listen on port
    dut_ip = duthost.mgmt_ip
    wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60)

    # Requests should successfully complete with certs
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET,
                              target="OTHERS", xpath="proc/uptime")
    ret = ptfhost.shell(cmd)['rc']
    assert ret == 0, "Telemetry server request should complete with certs"
