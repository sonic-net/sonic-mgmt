import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, wait_tcp_connection
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.gnmi.conftest import setup_gnmi_rotated_server
from .helper import gnmi_get, archive_gnmi_certs, unarchive_gnmi_certs


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]

logger = logging.getLogger(__name__)

"""
Testing cert rotation on the gnmi container.

1. Server stays up without certs.
2. Serve one request, delete certs, next request fails.
3. No certs -> request fails; rotate certs -> request works.
4. Serving with certs -> hot-rotate certs -> still serves (no disruption).
"""


def _gnmi_get_ok(duthost, ptfhost):
    """Return True if an OTHERS/proc/uptime GET against the gnmi server succeeds."""
    try:
        gnmi_get(duthost, ptfhost, ["proc/uptime"], target="OTHERS", origin=None)
        return True
    except Exception as e:
        logger.debug("gnmi get failed: {}".format(e))
        return False


def test_gnmi_not_exit(duthosts, rand_one_dut_hostname, localhost):
    """The gnmi server stays up when its certs are missing."""
    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    duthost.service(name=env.gnmi_container, state="stopped")
    archive_gnmi_certs(duthost)
    duthost.shell("systemctl reset-failed %s" % env.gnmi_container, module_ignore_errors=True)
    duthost.service(name=env.gnmi_container, state="restarted")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
                  "%s not started." % env.gnmi_container)

    unarchive_gnmi_certs(duthost)
    wait_tcp_connection(localhost, duthost.mgmt_ip, env.gnmi_port, timeout_s=60)


def test_gnmi_post_cert_del(duthosts, rand_one_dut_hostname, ptfhost, localhost):
    """With certs a request succeeds; after deleting certs it fails."""
    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    pytest_assert(wait_until(30, 5, 0, _gnmi_get_ok, duthost, ptfhost),
                  "gnmi request should complete with certs")

    archive_gnmi_certs(duthost)
    try:
        pytest_assert(not _gnmi_get_ok(duthost, ptfhost),
                      "gnmi request should fail without certs")
    finally:
        unarchive_gnmi_certs(duthost)
        wait_tcp_connection(localhost, duthost.mgmt_ip, env.gnmi_port, timeout_s=60)


def test_gnmi_post_cert_add(duthosts, rand_one_dut_hostname, ptfhost, localhost):
    """With no certs a request fails; after rotating certs it succeeds."""
    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    archive_gnmi_certs(duthost)
    pytest_assert(not _gnmi_get_ok(duthost, ptfhost),
                  "gnmi request should fail without certs")

    setup_gnmi_rotated_server(duthosts, rand_one_dut_hostname, localhost, ptfhost)
    wait_tcp_connection(localhost, duthost.mgmt_ip, env.gnmi_port, timeout_s=60)

    pytest_assert(wait_until(30, 5, 0, _gnmi_get_ok, duthost, ptfhost),
                  "gnmi request should complete after cert rotation")


def test_gnmi_cert_rotate(duthosts, rand_one_dut_hostname, ptfhost, localhost):
    """A serving gnmi server keeps serving after its certs are hot-rotated (no
    feature restart). Complements test_mimic_hwproxy_cert_rotation, which rotates
    across a feature disable/enable and checks capabilities rather than a GET."""
    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    pytest_assert(wait_until(30, 5, 0, _gnmi_get_ok, duthost, ptfhost),
                  "gnmi request should complete with certs")

    setup_gnmi_rotated_server(duthosts, rand_one_dut_hostname, localhost, ptfhost)
    wait_tcp_connection(localhost, duthost.mgmt_ip, env.gnmi_port, timeout_s=60)

    pytest_assert(wait_until(30, 5, 0, _gnmi_get_ok, duthost, ptfhost),
                  "gnmi request should complete after cert rotation")
