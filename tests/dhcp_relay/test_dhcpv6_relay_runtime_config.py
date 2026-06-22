"""
DHCPv6 relay runtime reconfiguration tests.

These tests validate that the SONiC-native ``dhcp6relay`` applies configuration
changes at runtime, without restarting the ``dhcp_relay`` container. The
behaviours under test are:

  * ``dhcp6relay`` is started unconditionally, even when no ``dhcpv6_servers``
    are configured;
  * ``dhcpv6_servers`` added or removed through CONFIG_DB are applied without a
    container restart (the process PID is unchanged and the ``need restart
    container to take effect`` log is no longer emitted);
  * a VLAN whose DHCPv6 relay becomes active or inactive at runtime (its IPv6
    address added or removed) is added to / removed from the running relay
    without a container restart.

Every configuration change is driven through CONFIG_DB (``sonic-db-cli`` /
``config`` CLI). The tests never pass arguments to the ``dhcp6relay`` binary
directly and never drive ``supervisorctl`` to start or stop the agent.
"""
import logging
import time

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx', 't0-2vlans'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

DHCP_RELAY_CONTAINER = "dhcp_relay"
# CONFIG_DB stores list-typed fields with a trailing '@'; the relay sees the
# field without the suffix once swss deserialises the list.
DHCPV6_SERVERS_FIELD = "dhcpv6_servers@"
NEED_RESTART_LOG = "need restart container to take effect"


def _dhcp6relay_pid(duthost):
    """Return the dhcp6relay PID inside the dhcp_relay container as a string, or
    an empty string if it is not running."""
    return duthost.shell(
        "docker exec {} pidof dhcp6relay".format(DHCP_RELAY_CONTAINER),
        module_ignore_errors=True
    )["stdout"].strip()


def _dhcp6relay_running(duthost):
    return _dhcp6relay_pid(duthost) != ""


def _supervisor_lists_dhcp6relay(duthost):
    """True if supervisord knows about the dhcp6relay program (it is listed in
    the dhcp-relay group), regardless of dhcpv6_servers being configured."""
    out = duthost.shell(
        "docker exec {} supervisorctl status dhcp-relay:dhcp6relay".format(DHCP_RELAY_CONTAINER),
        module_ignore_errors=True
    )["stdout"]
    return "dhcp6relay" in out and "no such process" not in out.lower()


def _write_syslog_marker(duthost):
    """Write a unique marker into syslog and return it, so a later read can be
    scoped to only the lines produced after this point."""
    marker = "dhcp6relay_rt_test_{}".format(int(time.time() * 1000))
    duthost.shell("logger {}".format(marker))
    return marker


def _syslog_since(duthost, marker):
    """Return syslog text from the marker line onward."""
    return duthost.shell(
        "sudo sed -n '/{}/,$p' /var/log/syslog".format(marker),
        module_ignore_errors=True
    )["stdout"]


def _restart_dhcp_relay(duthost):
    """Restart the dhcp_relay container (re-renders supervisord from CONFIG_DB)
    and wait for dhcp6relay to come back up."""
    duthost.shell("sudo systemctl reset-failed {}".format(DHCP_RELAY_CONTAINER))
    duthost.shell("sudo systemctl restart {}".format(DHCP_RELAY_CONTAINER))
    pytest_assert(
        wait_until(90, 3, 5, _dhcp6relay_running, duthost),
        "dhcp6relay did not come up after dhcp_relay restart"
    )


@pytest.fixture(scope="function")
def no_dhcpv6_servers(duthost):
    """Snapshot every DHCP_RELAY row's dhcpv6_servers list, clear them all so the
    DUT has no DHCPv6 relay server configured, restart the container to re-render
    supervisord, then restore the original configuration on teardown."""
    keys = duthost.shell(
        'sonic-db-cli CONFIG_DB KEYS "DHCP_RELAY|*"'
    )["stdout"].splitlines()
    saved = {}
    for key in keys:
        servers = duthost.shell(
            'sonic-db-cli CONFIG_DB HGET "{}" "{}"'.format(key, DHCPV6_SERVERS_FIELD)
        )["stdout"].strip()
        if servers:
            saved[key] = servers
            duthost.shell(
                'sonic-db-cli CONFIG_DB HDEL "{}" "{}"'.format(key, DHCPV6_SERVERS_FIELD)
            )
    _restart_dhcp_relay(duthost)

    yield

    for key, servers in saved.items():
        duthost.shell(
            'sonic-db-cli CONFIG_DB HSET "{}" "{}" "{}"'.format(key, DHCPV6_SERVERS_FIELD, servers)
        )
    _restart_dhcp_relay(duthost)


@pytest.fixture(scope="function")
def first_relay_vlan(duthost):
    """Return the name of the first VLAN that has a DHCPv6 relay configured, or
    skip the test if none exists."""
    keys = duthost.shell(
        'sonic-db-cli CONFIG_DB KEYS "DHCP_RELAY|*"'
    )["stdout"].splitlines()
    for key in keys:
        servers = duthost.shell(
            'sonic-db-cli CONFIG_DB HGET "{}" "{}"'.format(key, DHCPV6_SERVERS_FIELD)
        )["stdout"].strip()
        if servers:
            return key.split("|", 1)[1]
    pytest.skip("No DHCP_RELAY VLAN with dhcpv6_servers configured on the DUT")
    return None


@pytest.fixture(scope="function")
def runtime_added_vlan(duthost):
    """Create a fresh VLAN that has a DHCPv6 relay configured but NO IPv6 address
    on its interface yet, while dhcp6relay is already running. Yields the VLAN
    name and the IPv6 address to add at runtime. Cleans everything up on teardown.
    All operations go through the config CLI / CONFIG_DB; no container restart."""
    vlan_id = 4002
    vlan = "Vlan{}".format(vlan_id)
    vlan_ipv6 = "fc02:4002::1/64"
    servers = "2000::100,2000::200"

    # Start clean in case a previous aborted run left this VLAN behind.
    duthost.shell("sudo config interface ip remove {} {}".format(vlan, vlan_ipv6),
                  module_ignore_errors=True)
    duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan),
                  module_ignore_errors=True)
    duthost.shell("sudo config vlan del {}".format(vlan_id), module_ignore_errors=True)

    # Create the VLAN (no IPv6 address yet) and give it a DHCPv6 relay config.
    duthost.shell("sudo config vlan add {}".format(vlan_id))
    duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" "{}" "{}"'
                  .format(vlan, DHCPV6_SERVERS_FIELD, servers))

    yield vlan, vlan_ipv6

    duthost.shell("sudo config interface ip remove {} {}".format(vlan, vlan_ipv6),
                  module_ignore_errors=True)
    duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan),
                  module_ignore_errors=True)
    duthost.shell("sudo config vlan del {}".format(vlan_id), module_ignore_errors=True)


@pytest.fixture(scope="function")
def runtime_active_vlan(duthost):
    """Create a fresh VLAN that has BOTH a DHCPv6 relay AND an IPv6 address on
    its interface, so the relay adds it at runtime and it is fully active. Yields
    the VLAN name and the IPv6 address (so a test can remove it again). Cleans
    everything up on teardown. All operations go through the config CLI /
    CONFIG_DB; no container restart."""
    vlan_id = 4003
    vlan = "Vlan{}".format(vlan_id)
    vlan_ipv6 = "fc02:4003::1/64"
    servers = "2000::100,2000::200"

    # Start clean in case a previous aborted run left this VLAN behind.
    duthost.shell("sudo config interface ip remove {} {}".format(vlan, vlan_ipv6),
                  module_ignore_errors=True)
    duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan),
                  module_ignore_errors=True)
    duthost.shell("sudo config vlan del {}".format(vlan_id), module_ignore_errors=True)

    # Create the VLAN, give it a DHCPv6 relay config and an IPv6 address so the
    # relay activates it.
    duthost.shell("sudo config vlan add {}".format(vlan_id))
    duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" "{}" "{}"'
                  .format(vlan, DHCPV6_SERVERS_FIELD, servers))
    duthost.shell("sudo config interface ip add {} {}".format(vlan, vlan_ipv6))

    yield vlan, vlan_ipv6

    duthost.shell("sudo config interface ip remove {} {}".format(vlan, vlan_ipv6),
                  module_ignore_errors=True)
    duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan),
                  module_ignore_errors=True)
    duthost.shell("sudo config vlan del {}".format(vlan_id), module_ignore_errors=True)


def test_dhcp6relay_starts_without_dhcpv6_servers(duthost, no_dhcpv6_servers):
    """dhcp6relay must start unconditionally, even when no VLAN has any
    dhcpv6_servers configured. The no_dhcpv6_servers fixture clears all server
    lists and restarts the container, so supervisord re-renders with no DHCPv6
    relay servers present; the agent must still be listed and running."""
    pytest_assert(
        wait_until(60, 3, 0, _supervisor_lists_dhcp6relay, duthost),
        "dhcp6relay is not registered in supervisord when no dhcpv6_servers are configured"
    )
    pytest_assert(
        _dhcp6relay_running(duthost),
        "dhcp6relay is not running when no dhcpv6_servers are configured"
    )


def test_dhcp6relay_runtime_ipv6_added_after_start(duthost, runtime_added_vlan):
    """A VLAN that has a DHCPv6 relay configured but no IPv6 address on its
    interface must not be relayed; once an IPv6 address is configured on that
    VLAN interface at runtime (after the agent is already running), the relay
    must add the relay instance without a container restart."""
    vlan, vlan_ipv6 = runtime_added_vlan
    add_log = "Add relay config for {} at runtime".format(vlan)

    pid_before = _dhcp6relay_pid(duthost)
    pytest_assert(pid_before != "", "dhcp6relay is not running")

    # With no IPv6 on the VLAN interface, the relay must not add a relay config
    # for it (build_desired_config skips VLANs without an IPv6 address).
    marker_noip = _write_syslog_marker(duthost)
    time.sleep(3)
    pytest_assert(
        add_log not in _syslog_since(duthost, marker_noip),
        "dhcp6relay added a relay config for {} before it had an IPv6 address".format(vlan)
    )

    # Configure an IPv6 address on the VLAN interface at runtime.
    marker_add = _write_syslog_marker(duthost)
    duthost.shell("sudo config interface ip add {} {}".format(vlan, vlan_ipv6))

    # The relay must now add the relay config for this VLAN at runtime, without
    # restarting the container.
    pytest_assert(
        wait_until(30, 2, 0, lambda: add_log in _syslog_since(duthost, marker_add)),
        "dhcp6relay did not add the relay config for {} after its IPv6 address was configured".format(vlan)
    )
    pytest_assert(
        pid_before == _dhcp6relay_pid(duthost),
        "dhcp6relay restarted when an IPv6 address was added at runtime"
    )
    pytest_assert(
        NEED_RESTART_LOG not in _syslog_since(duthost, marker_add),
        "dhcp6relay emitted '{}' when an IPv6 address was added at runtime".format(NEED_RESTART_LOG)
    )


def test_dhcp6relay_runtime_server_change_no_restart(duthost, first_relay_vlan):
    """Adding and removing a dhcpv6_server through CONFIG_DB must be applied at
    runtime: the dhcp6relay process PID is unchanged (no container restart) and
    the legacy 'need restart container to take effect' log is not emitted."""
    vlan = first_relay_vlan
    key = "DHCP_RELAY|{}".format(vlan)
    original = duthost.shell(
        'sonic-db-cli CONFIG_DB HGET "{}" "{}"'.format(key, DHCPV6_SERVERS_FIELD)
    )["stdout"].strip()

    pid_before = _dhcp6relay_pid(duthost)
    pytest_assert(pid_before != "", "dhcp6relay is not running")
    marker = _write_syslog_marker(duthost)

    updated = original + ",2000::dead:beef"
    try:
        duthost.shell(
            'sonic-db-cli CONFIG_DB HSET "{}" "{}" "{}"'.format(key, DHCPV6_SERVERS_FIELD, updated)
        )
        pytest_assert(
            wait_until(30, 2, 0,
                       lambda: "Update relay config for {} at runtime".format(vlan)
                       in _syslog_since(duthost, marker)),
            "dhcp6relay did not apply the runtime server change for {}".format(vlan)
        )
        pid_after = _dhcp6relay_pid(duthost)
        pytest_assert(
            pid_before == pid_after,
            "dhcp6relay restarted on a runtime server change (pid {} -> {})".format(pid_before, pid_after)
        )
        pytest_assert(
            NEED_RESTART_LOG not in _syslog_since(duthost, marker),
            "dhcp6relay emitted '{}' on a runtime config change".format(NEED_RESTART_LOG)
        )
    finally:
        duthost.shell(
            'sonic-db-cli CONFIG_DB HSET "{}" "{}" "{}"'.format(key, DHCPV6_SERVERS_FIELD, original)
        )


def test_dhcp6relay_runtime_relay_removed_no_restart(duthost, runtime_active_vlan):
    """Mirror of the runtime-add test (the removal half of the diff path): once a
    VLAN's DHCPv6 relay is active, removing its IPv6 address at runtime makes the
    VLAN drop out of the desired config, so the relay must remove that relay
    instance (logging 'Remove relay config for <vlan> at runtime') without a
    container restart and without the legacy 'need restart' log."""
    vlan, vlan_ipv6 = runtime_active_vlan
    remove_log = "Remove relay config for {} at runtime".format(vlan)

    pid_before = _dhcp6relay_pid(duthost)
    pytest_assert(pid_before != "", "dhcp6relay is not running")

    # The fixture configured the VLAN with an IPv6 + relay; give the relay a
    # moment to have added it before we exercise removal.
    time.sleep(3)

    # Remove the IPv6 address at runtime -> the VLAN no longer has an address to
    # bind, so build_desired_config drops it and the relay must remove it.
    marker = _write_syslog_marker(duthost)
    duthost.shell("sudo config interface ip remove {} {}".format(vlan, vlan_ipv6))

    pytest_assert(
        wait_until(30, 2, 0, lambda: remove_log in _syslog_since(duthost, marker)),
        "dhcp6relay did not remove the relay config for {} after its IPv6 was removed".format(vlan)
    )
    pytest_assert(
        pid_before == _dhcp6relay_pid(duthost),
        "dhcp6relay restarted when an IPv6 address was removed at runtime"
    )
    pytest_assert(
        NEED_RESTART_LOG not in _syslog_since(duthost, marker),
        "dhcp6relay emitted '{}' when an IPv6 address was removed at runtime".format(NEED_RESTART_LOG)
    )
