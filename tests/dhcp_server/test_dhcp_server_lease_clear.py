"""DHCP lease clear tests (L01-L07 of the IPv4 match condition test plan).

The clear command does not depend on the DHCP interface mode, so the scenarios run in PORT and MATCH mode.
"""
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from dhcp_server_match_common import match_env, match_config_snapshot, match_test_isolation  # noqa: F401
from dhcp_server_match_common import TEST_MAC_PREFIX, DHCP_SERVER_CONTAINER, KEA_PROGRAM, \
    MatchConfig, DhcpClient, run_cli, apply_match_configs, second_vlan, verify_client_lease, \
    get_kea_subnet_leases, get_state_db_leases, get_state_db_lease, wait_for_kea_pools, \
    cleanup_test_leases, new_client_mac

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('mx'),
]

LEASE_SYNC_KEY = "DHCP_SERVER_IPV4_LEASE_SYNC|GLOBAL"
CLEAR_CMD = "sonic-clear dhcp_server ipv4 lease"


@pytest.fixture(scope="module", autouse=True)
def lease_clear_module_setup(match_config_snapshot):  # noqa: F811
    yield


@pytest.fixture(autouse=True)
def lease_clear_test_setup(match_test_isolation):  # noqa: F811
    yield


def _pool_config(env, mode, prefix=""):
    """One range on P1 and one on P2, as port bindings (PORT) or port-only bindings (MATCH)."""
    cfg = MatchConfig(env, mode=mode)
    pools = [(env.p1, prefix + "lc_r1", env.ip(100), env.ip(104)),
             (env.p2, prefix + "lc_r2", env.ip(110), env.ip(114))]
    for index, (port, range_name, start, end) in enumerate(pools, 1):
        cfg.add_range(range_name, start, end)
        if mode == "PORT":
            cfg.add_port_binding(port.name, [range_name])
        else:
            match_name = "{}lc_port_p{}".format(prefix, index)
            cfg.add_match(match_name, "circuit_id", port.alias)
            cfg.add_binding("{}on_p{}".format(prefix, index), [match_name], ranges=[range_name])
    return cfg


def _test_leases(leases):
    return {mac: ip for mac, ip in leases.items() if mac.startswith(TEST_MAC_PREFIX)}


def _kea_leases(duthost, env):
    return _test_leases(get_kea_subnet_leases(duthost, env.vlan_id))


def _state_leases(duthost, env):
    return _test_leases(get_state_db_leases(duthost, env.vlan))


def _require_only_test_leases(duthost, env):
    """``--all`` wipes the whole subnet, so it must not hold leases of real clients."""
    others = {mac: ip for mac, ip in get_kea_subnet_leases(duthost, env.vlan_id).items()
              if not mac.startswith(TEST_MAC_PREFIX)}
    pytest_require(not others, "{} has non-test leases that --all would delete: {}".format(env.vlan, others))


def _clear(duthost, vlan, target, user=None):
    cmd = "{} {} {}".format(CLEAR_CMD, vlan, target).strip()
    if user:
        cmd = "sudo -u {} {}".format(user, cmd)
    result = duthost.shell(cmd, module_ignore_errors=True)
    logger.info("%s -> rc %s: %s %s", cmd, result["rc"], result["stdout"], result["stderr"])
    return result


def _clear_ok(duthost, vlan, target):
    result = _clear(duthost, vlan, target)
    pytest_assert(result["rc"] == 0, "'{} {} {}' failed: {}".format(CLEAR_CMD, vlan, target, result["stderr"]))
    pytest_assert("Cleared matching lease(s) on {} from Kea and State DB.".format(vlan) in result["stdout"],
                  "Unexpected clear output: {}".format(result["stdout"]))


def _clear_fails(duthost, vlan, target, rc, error, user=None):
    result = _clear(duthost, vlan, target, user)
    output = result["stdout"] + result["stderr"]
    pytest_assert(result["rc"] == rc and error in output,
                  "'{} {} {}' returned {} '{}', expected {} '{}'".format(
                      CLEAR_CMD, vlan, target, result["rc"], output, rc, error))


def _sync_ids(duthost):
    return [duthost.shell("sonic-db-cli STATE_DB HGET '{}' {}".format(LEASE_SYNC_KEY, field))["stdout"].strip()
            for field in ("request_id", "completed_id")]


def _lease_clients(duthost, env, ptfadapter, count, port=None):
    """DORA ``count`` clients on ``port`` (P1 by default) and verify their Kea and State DB leases."""
    port = port or env.p1
    pool = env.ip_range(100, 104) if port == env.p1 else env.ip_range(110, 114)
    clients = []
    for _ in range(count):
        client = DhcpClient(env, ptfadapter, port)
        client.dora(pool)
        verify_client_lease(duthost, env, client, client.ip)
        clients.append(client)
    return clients


def _expected_map(clients):
    return {client.mac: client.ip for client in clients}


def _assert_leases(duthost, env, expected, what):
    """Kea and State DB must hold exactly ``expected`` test leases; State DB may lag a lease event."""
    kea = _kea_leases(duthost, env)
    pytest_assert(kea == expected, "{}: Kea leases on {} are {}, expected {}".format(what, env.vlan, kea, expected))
    state = {}

    def _state_matches():
        state["leases"] = _state_leases(duthost, env)
        return state["leases"] == expected
    pytest_assert(wait_until(20, 2, 0, _state_matches), "{}: State DB leases on {} are {}, expected {}".format(
        what, env.vlan, state.get("leases"), expected))


def _wait_kea_running(duthost, timeout=300):
    pytest_assert(wait_until(timeout, 3, 0, lambda: "RUNNING" in duthost.shell(
        "docker exec {} supervisorctl status {}".format(DHCP_SERVER_CONTAINER, KEA_PROGRAM),
        module_ignore_errors=True)["stdout"]), "kea-dhcp4 is not running")


@pytest.mark.parametrize("mode", ["PORT", "MATCH"])
def test_dhcp_server_lease_clear_single_ip(duthost, ptfadapter, match_env, mode):  # noqa: F811
    """L01: clearing one lease removes only that lease, from Kea and State DB."""
    env = match_env
    _pool_config(env, mode).apply(duthost)
    clients = _lease_clients(duthost, env, ptfadapter, 3)
    _assert_leases(duthost, env, _expected_map(clients), "Before clear")
    request_before, _ = _sync_ids(duthost)

    _clear_ok(duthost, env.vlan, clients[1].ip)
    # The command returns only after State DB is refreshed, so there is no wait here.
    kea = _kea_leases(duthost, env)
    state = _state_leases(duthost, env)
    remaining = _expected_map([clients[0], clients[2]])
    pytest_assert(kea == remaining, "Kea leases after clear are {}, expected {}".format(kea, remaining))
    pytest_assert(state == remaining, "State DB leases after clear are {}, expected {}".format(state, remaining))
    pytest_assert(not get_state_db_lease(duthost, env.vlan, clients[1].mac), "Cleared lease is still in State DB")
    request_id, completed_id = _sync_ids(duthost)
    pytest_assert(request_id and request_id != request_before, "Clear did not request a State DB sync")
    pytest_assert(completed_id == request_id,
                  "State DB sync completed_id {} does not match request_id {}".format(completed_id, request_id))


@pytest.mark.parametrize("mode", ["PORT", "MATCH"])
def test_dhcp_server_lease_clear_all(duthost, tbinfo, ptfadapter, match_env, mode):  # noqa: F811
    """L02: clearing all leases of one DHCP interface leaves the leases of another VLAN unchanged."""
    with second_vlan(duthost, tbinfo, match_env) as (env_a, env_b):
        _require_only_test_leases(duthost, env_a)
        apply_match_configs(duthost, [_pool_config(env_a, mode), _pool_config(env_b, mode, prefix="b_")])
        clients_a = (_lease_clients(duthost, env_a, ptfadapter, 2) +
                     _lease_clients(duthost, env_a, ptfadapter, 1, port=env_a.p2))
        clients_b = (_lease_clients(duthost, env_b, ptfadapter, 2) +
                     _lease_clients(duthost, env_b, ptfadapter, 1, port=env_b.p2))
        _assert_leases(duthost, env_a, _expected_map(clients_a), "Before clear")
        _assert_leases(duthost, env_b, _expected_map(clients_b), "Before clear")

        _clear_ok(duthost, env_a.vlan, "--all")
        pytest_assert(not get_kea_subnet_leases(duthost, env_a.vlan_id), "Kea still has leases on {}".format(
            env_a.vlan))
        pytest_assert(not get_state_db_leases(duthost, env_a.vlan), "State DB still has leases on {}".format(
            env_a.vlan))
        _assert_leases(duthost, env_b, _expected_map(clients_b), "Other VLAN after clear")
        cleanup_test_leases(duthost)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("action", ["kea_restart", "service_restart", "cold_reboot"])
@pytest.mark.parametrize("mode", ["PORT", "MATCH"])
def test_dhcp_server_lease_clear_persistence(duthost, localhost, ptfadapter, match_env, mode, action):  # noqa: F811
    """L03: a deletion is persisted in the Kea lease file and survives restart and reboot."""
    env = match_env
    cfg = _pool_config(env, mode)
    cfg.apply(duthost)
    clients = _lease_clients(duthost, env, ptfadapter, 3)
    if action == "kea_restart":
        _clear_ok(duthost, env.vlan, clients[0].ip)
        expected = _expected_map(clients[1:])
    else:
        _require_only_test_leases(duthost, env)
        _clear_ok(duthost, env.vlan, "--all")
        expected = {}
    _assert_leases(duthost, env, expected, "After clear")

    if action == "kea_restart":
        duthost.shell("docker exec {} supervisorctl restart {}".format(DHCP_SERVER_CONTAINER, KEA_PROGRAM))
    elif action == "service_restart":
        duthost.shell("sudo systemctl restart dhcp_server")
    else:
        run_cli(duthost, "config save -y")
        reboot(duthost, localhost, reboot_type="cold", safe_reboot=True)
    _wait_kea_running(duthost)
    wait_for_kea_pools(duthost, env, cfg.expected_pools(), timeout=180)

    kea = _kea_leases(duthost, env)
    pytest_assert(kea == expected, "Kea leases after {} are {}, expected {}".format(action, kea, expected))
    # Cleared leases must not come back in State DB; after a cold reboot State DB is empty until the next
    # lease event, so only the absence of the cleared leases is checked there.
    cleared = [client.mac for client in clients if client.mac not in expected]
    state = _state_leases(duthost, env)
    pytest_assert(not set(cleared) & set(state), "Cleared leases reappeared in State DB after {}: {}".format(
        action, state))
    if action != "cold_reboot":
        _assert_leases(duthost, env, expected, "After {}".format(action))


@pytest.mark.parametrize("mode", ["PORT", "MATCH"])
def test_dhcp_server_lease_clear_device_replacement(duthost, ptfadapter, match_env, mode):  # noqa: F811
    """L04: a replacement device gets the address of the old device without waiting for lease expiry."""
    env = match_env
    address = env.ip(21)
    cfg = MatchConfig(env, mode=mode)
    cfg.add_range("lc_single", address)
    if mode == "PORT":
        cfg.add_port_binding(env.p1.name, ["lc_single"])
    else:
        cfg.add_match("lc_port_p1", "circuit_id", env.p1.alias)
        cfg.add_binding("lc_single_on_p1", ["lc_port_p1"], ranges=["lc_single"])
    cfg.apply(duthost)
    pytest_assert(address not in _kea_leases(duthost, env).values(), "Precondition: {} is leased".format(address))

    old_device = DhcpClient(env, ptfadapter, env.p1)
    old_device.dora(address)
    verify_client_lease(duthost, env, old_device, address)
    # The old device is now "disconnected": it never renews or uses the address again.
    new_device = DhcpClient(env, ptfadapter, env.p1)
    new_device.expect_no_offer()

    _clear_ok(duthost, env.vlan, address)
    new_device.dora(address)
    verify_client_lease(duthost, env, new_device, address)
    pytest_assert(_kea_leases(duthost, env) == {new_device.mac: address},
                  "Kea leases are {}, expected only the new device".format(_kea_leases(duthost, env)))


def _set_feature_state(duthost, state):
    duthost.shell("config feature state dhcp_server {}".format(state))
    if state == "enabled":
        duthost.shell("sudo systemctl restart dhcp_relay.service")
        _wait_kea_running(duthost)


def test_dhcp_server_lease_clear_negative(duthost, ptfadapter, match_env):  # noqa: F811
    """L05: error handling of the clear command; an existing lease is never affected."""
    env = match_env
    cfg = _pool_config(env, "MATCH")
    cfg.apply(duthost)
    unleased = env.ip(104)
    _require_only_test_leases(duthost, env)

    # No lease at all on the DHCP interface.
    _clear_fails(duthost, env.vlan, unleased, 1, "No matching Kea lease on {}".format(env.vlan))
    _clear_fails(duthost, env.vlan, "--all", 1, "No matching Kea lease on {}".format(env.vlan))

    client = _lease_clients(duthost, env, ptfadapter, 1)[0]
    if client.ip == unleased:
        unleased = env.ip(103)
    expected = _expected_map([client])
    cases = [
        (unleased, 1, "No matching Kea lease on {}".format(env.vlan), None),
        ("{} --all".format(client.ip), 2, "Supply exactly one of IP_ADDRESS or --all", None),
        ("", 2, "Supply exactly one of IP_ADDRESS or --all", None),
        ("192.168.0.300", 2, "Must be an IPv4 address", None),
        ("not-an-ip", 2, "Must be an IPv4 address", None),
        (client.ip, 1, "Root privileges are required; run with sudo", "admin"),
    ]
    for target, rc, error, user in cases:
        _clear_fails(duthost, env.vlan, target, rc, error, user)
    _clear_fails(duthost, "Vlan4093", client.ip, 1, "DHCP interface Vlan4093 is not configured")
    _assert_leases(duthost, env, expected, "After rejected clear commands")

    _set_feature_state(duthost, "disabled")
    try:
        result = _clear(duthost, env.vlan, client.ip)
        output = result["stdout"] + result["stderr"]
        pytest_assert(result["rc"] != 0 and "Feature dhcp_server is not enabled" in output,
                      "Clear with the feature disabled returned {} '{}'".format(result["rc"], output))
    finally:
        _set_feature_state(duthost, "enabled")
    wait_for_kea_pools(duthost, env, cfg.expected_pools(), timeout=180)
    pytest_assert(_kea_leases(duthost, env) == expected, "Lease of {} was lost after the rejected clear".format(
        client.mac))


def test_dhcp_server_lease_clear_stale_state_db(duthost, match_env):  # noqa: F811
    """L06: a State DB lease without a Kea lease is removed by the clear command, which still fails."""
    env = match_env
    _pool_config(env, "MATCH").apply(duthost)
    stale_ip = env.ip(102)
    pytest_assert(stale_ip not in get_kea_subnet_leases(duthost, env.vlan_id).values(),
                  "Precondition: {} has a Kea lease".format(stale_ip))
    stale_key = "DHCP_SERVER_IPV4_LEASE|{}|{}".format(env.vlan, new_client_mac())
    duthost.shell("sonic-db-cli STATE_DB HSET '{}' ip {} lease_start 1 lease_end 2".format(stale_key, stale_ip))
    try:
        _clear_fails(duthost, env.vlan, stale_ip, 1, "No matching Kea lease on {}".format(env.vlan))
        pytest_assert(duthost.shell("sonic-db-cli STATE_DB EXISTS '{}'".format(stale_key))["stdout"].strip() == "0",
                      "Stale State DB entry {} was not removed".format(stale_key))
    finally:
        duthost.shell("sonic-db-cli STATE_DB DEL '{}'".format(stale_key), module_ignore_errors=True)


@pytest.mark.parametrize("mode", ["PORT", "MATCH"])
def test_dhcp_server_lease_clear_concurrency(duthost, ptfadapter, match_env, mode):  # noqa: F811
    """L07: two clear commands never run at the same time, and State DB ends up matching Kea."""
    env = match_env
    _pool_config(env, mode).apply(duthost)
    clients = _lease_clients(duthost, env, ptfadapter, 3)
    targets = [clients[0].ip, clients[1].ip]
    script = " ".join("({} {} {} > /tmp/lease_clear_{} 2>&1; echo \"rc=$?\" >> /tmp/lease_clear_{}) &".format(
        CLEAR_CMD, env.vlan, ip, index, index) for index, ip in enumerate(targets)) + " wait"
    duthost.shell(script)
    outputs = [duthost.shell("cat /tmp/lease_clear_{0}; rm -f /tmp/lease_clear_{0}".format(index))["stdout"]
               for index in range(len(targets))]
    logger.info("Concurrent clear outputs: %s", outputs)
    codes = [int(re.search(r"rc=(\d+)", output).group(1)) for output in outputs]
    pytest_assert(0 in codes, "Neither concurrent clear succeeded: {}".format(outputs))
    for ip, code, output in zip(targets, codes, outputs):
        if code != 0:
            pytest_assert("Another DHCP lease clear is in progress" in output,
                          "Concurrent clear of {} failed for another reason: {}".format(ip, output))
            _clear_ok(duthost, env.vlan, ip)
    _assert_leases(duthost, env, _expected_map(clients[2:]), "After concurrent clears")
    pytest_assert(_state_leases(duthost, env) == _kea_leases(duthost, env), "State DB does not match Kea")
