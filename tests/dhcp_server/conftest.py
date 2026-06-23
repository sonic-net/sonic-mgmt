import pytest
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.helpers.assertions import pytest_require as py_require
from dhcp_server_test_common import clean_dhcp_server_config

DHCP_RELAY_CONTAINER_NAME = "dhcp_relay"
DHCP_SERVER_CONTAINER_NAME = "dhcp_server"
DHCP_SERVER_FEATRUE_NAME = "dhcp_server"


def is_dhcprelayd_running(duthost):
    """
    Check if dhcprelayd is running in the dhcp_relay container, handling
    dynamic supervisor process naming.

    The dhcp_relay container's supervisor config is dynamically generated from
    a Jinja2 template (docker-dhcp-relay.supervisord.conf.j2) at container
    startup based on CONFIG_DB state. The template conditionally includes
    dhcp-relay.programs.j2, which creates a [group:dhcp-relay] section that
    groups dhcprelayd and dhcp6relay together.

    The group is created when there are VLANs with DHCP relay configured
    (dhcp_servers or dhcpv6_servers in CONFIG_DB). On a normal production DUT,
    this is almost always the case, and the process appears as
    "dhcp-relay:dhcprelayd" (group:program format). In this state,
    supervisorctl requires the group prefix; the bare name "dhcprelayd"
    returns "ERROR (no such process)" (rc=4).

    When the relay count is 0 (no VLANs with dhcp_servers or dhcpv6_servers),
    the template skips the group section, and dhcprelayd becomes a standalone
    [program:dhcprelayd]. In this state, the bare name works but the
    group-prefixed name fails.

    Note: the enable_sonic_dhcpv4_relay_agent fixture teardown does not cause
    this condition — config dhcpv4_relay add/del does not modify VLAN.dhcp_servers,
    so the original relay config remains intact after teardown. The no-group state
    has been observed in practice but the exact trigger is unclear; it may result
    from external CONFIG_DB modifications or edge cases during container restarts.

    This function tries both naming conventions to handle either state.
    """
    # Try group format first (normal production state)
    result = duthost.shell(
        "docker exec {} supervisorctl status dhcp-relay:dhcprelayd".format(DHCP_RELAY_CONTAINER_NAME),
        module_ignore_errors=True)
    if "RUNNING" in result.get("stdout", ""):
        return True
    # Fall back to standalone format (after test fixture modifies CONFIG_DB)
    result = duthost.shell(
        "docker exec {} supervisorctl status dhcprelayd".format(DHCP_RELAY_CONTAINER_NAME),
        module_ignore_errors=True)
    return "RUNNING" in result.get("stdout", "")


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
                   is_dhcprelayd_running,
                   duthost),
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
