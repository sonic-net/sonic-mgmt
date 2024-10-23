import pytest
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.helpers.assertions import pytest_require as py_require
from dhcp_server_test_common import clean_dhcp_server_config

DHCP_RELAY_CONTAINER_NAME = "dhcp_relay"
DHCP_SERVER_CONTAINER_NAME = "dhcp_server"
DHCP_SERVER_FEATRUE_NAME = "dhcp_server"


@pytest.fixture(scope="module", autouse=True)
def dhcp_server_setup_teardown(duthost):
    features_state, _ = duthost.get_feature_status()
    py_require(DHCP_SERVER_FEATRUE_NAME in features_state, "Skip on vs testbed without dhcp server feature")
    restore_state_flag = False
    if "enabled" not in features_state.get(DHCP_SERVER_FEATRUE_NAME, ""):
        restore_state_flag = True
        duthost.shell("config feature state dhcp_server enabled")
        duthost.shell("sudo systemctl restart dhcp_relay.service")

    def is_supervisor_subprocess_running(duthost, container_name, app_name):
        return "RUNNING" in duthost.shell(f"docker exec {container_name} supervisorctl status {app_name}")["stdout"]
    py_assert(
        wait_until(120, 1, 1,
                   is_supervisor_subprocess_running,
                   duthost,
                   DHCP_SERVER_CONTAINER_NAME,
                   "dhcp-server-ipv4:kea-dhcp4"),
        'feature dhcp_server is enabled but container is not running'
    )
    py_assert(
        wait_until(120, 1, 1,
                   is_supervisor_subprocess_running,
                   duthost,
                   DHCP_RELAY_CONTAINER_NAME,
                   "dhcp-relay:dhcprelayd"),
        'dhcprelayd in container dhcp_relay is not running'
    )

    yield

    if restore_state_flag:
        duthost.shell("config feature state dhcp_server disabled", module_ignore_errors=True)
        duthost.shell("sudo systemctl restart dhcp_relay.service")
        duthost.shell("docker rm dhcp_server", module_ignore_errors=True)


@pytest.fixture(scope="function", autouse=True)
def clean_dhcp_server_config_after_test(duthost):
    clean_dhcp_server_config(duthost)

    yield

    clean_dhcp_server_config(duthost)
