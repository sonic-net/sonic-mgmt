'''
Conftest for the mirror session label tests.

Everything defined here applies only to tests/span/mirror_label/, including the
autouse fixtures. Fixtures of tests/span/conftest.py (cfg_facts, ports_for_test,
setup_monitor_port, ...) are inherited.
'''

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert as _pytest_assert
from mirror_label_helpers import (
    CONFIG_DB,
    ERSPAN_DST_NET,
    redis_cmd,
    remove_all_label_sessions,
    label_unsupported_reason,
    span_direction_for,
)

logger = logging.getLogger(__name__)

ERSPAN_DUT_IP = "192.168.200.1/30"
ERSPAN_NEXTHOP_IP = "192.168.200.2"


def pytest_addoption(parser):
    parser.addoption(
        "--label_max_sessions", action="store", type=int, default=None,
        help="Number of mirror sessions the platform supports for the label scale test "
             "(no default: the scale test is skipped when this is not passed)")


@pytest.fixture(scope="module", autouse=True)
def label_capability(duthosts, rand_one_dut_hostname):
    '''
    Readiness gate: skip the whole module unless every ASIC reports
    MIRROR_SESSION_LABEL_CAPABLE=true and the CLI offers --label.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    reason = label_unsupported_reason(duthost)
    if reason:
        pytest.skip(reason)
    show_out = duthost.command("show mirror_session")["stdout"]
    logger.info("show mirror_session\n%s", show_out)


@pytest.fixture(scope="module")
def label_asic(duthosts, rand_one_dut_hostname):
    '''ASIC whose databases the tests inspect (the first one).'''
    return duthosts[rand_one_dut_hostname].asics[0]


@pytest.fixture(scope="module")
def span_direction(label_asic):
    '''
    Direction of the SPAN sessions that have a source port: "both" where the ASIC mirrors ingress and
    egress, "rx" where it mirrors ingress only. The test is skipped when ingress mirroring is not supported.
    '''
    direction = span_direction_for(label_asic)
    if direction is None:
        pytest.skip("Port ingress mirroring is not supported by the ASIC")
    logger.info("SPAN sessions use direction %s", direction)
    return direction


@pytest.fixture(scope="module")
def label_ports(ports_for_test):
    '''
    Ports used by the label tests, taken from the ports selected by tests/span/conftest.py:
      src     - SPAN source port (PTF injects here)
      dst     - SPAN destination port (removed from its VLAN by setup_monitor_port)
      routed  - port turned into an L3 port towards the PTF for ERSPAN
    '''
    return {
        "src": ports_for_test["source1"],
        "dst": ports_for_test["monitor"],
        "routed": ports_for_test["source2"],
        "vlan": ports_for_test["vlan"],
    }


@pytest.fixture(scope="module")
def label_erspan_route(duthosts, rand_one_dut_hostname, ptfhost, label_ports):
    '''
    Persistent ERSPAN control plane: IP on the routed port, one static route for the whole
    ERSPAN destination /24 and a static neighbour, all written to CONFIG_DB so they survive
    config reload and reboots (vtysh / "ip neigh" entries would not).
    '''
    duthost = duthosts[rand_one_dut_hostname]
    asic = duthost.asics[0]
    port = label_ports["routed"]["name"]
    vlan = label_ports["vlan"]
    tagging_mode = label_ports["routed"]["tagging_mode"]
    neigh_key = "NEIGH|{}|{}".format(port, ERSPAN_NEXTHOP_IP)

    ptf_mac = ptfhost.shell(
        "cat /sys/class/net/eth{}/address".format(label_ports["routed"]["index"]))["stdout"].strip()

    def _cleanup():
        duthost.command("config route del prefix {} nexthop {}".format(ERSPAN_DST_NET, ERSPAN_NEXTHOP_IP),
                        module_ignore_errors=True)
        redis_cmd(asic, CONFIG_DB, 'DEL "{}"'.format(neigh_key))
        duthost.command("ip neigh del {} dev {}".format(ERSPAN_NEXTHOP_IP, port), module_ignore_errors=True)
        duthost.command("config interface ip remove {} {}".format(port, ERSPAN_DUT_IP), module_ignore_errors=True)
        duthost.command("config vlan member add {} {} --{}".format(vlan, port, tagging_mode),
                        module_ignore_errors=True)

    _cleanup()
    duthost.command("config vlan member del {} {}".format(vlan, port))
    duthost.command("config interface ip add {} {}".format(port, ERSPAN_DUT_IP))
    duthost.command("config route add prefix {} nexthop {}".format(ERSPAN_DST_NET, ERSPAN_NEXTHOP_IP))
    redis_cmd(asic, CONFIG_DB, 'HSET "{}" neigh "{}" family IPv4'.format(neigh_key, ptf_mac))
    duthost.command("ip neigh replace {} lladdr {} dev {}".format(ERSPAN_NEXTHOP_IP, ptf_mac, port))
    logger.info("ERSPAN route: %s via %s on %s (PTF mac %s)", ERSPAN_DST_NET, ERSPAN_NEXTHOP_IP, port, ptf_mac)

    yield {"port": port, "ptf_index": label_ports["routed"]["index"], "ptf_mac": ptf_mac}

    _cleanup()


@pytest.fixture(autouse=True)
def label_session_cleanup(duthosts, rand_one_dut_hostname):
    '''Remove every label-test session before and after each test (CLI-created and HSET-injected).'''
    duthost = duthosts[rand_one_dut_hostname]
    asic = duthost.asics[0]
    remove_all_label_sessions(duthost, asic)
    yield
    remove_all_label_sessions(duthost, asic)


@pytest.fixture
def label_max_sessions(request):
    '''Number of mirror sessions to create in the scale test; the test is skipped when it is not given.'''
    value = request.config.getoption("--label_max_sessions")
    if value is None:
        pytest.skip("--label_max_sessions is not set")
    _pytest_assert(value >= 1, "--label_max_sessions must be >= 1, got {}".format(value))
    return value


CONFIG_DB_FILE = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json.label_backup"


@pytest.fixture(scope="module")
def label_config_backup(duthosts, rand_one_dut_hostname):
    '''
    Back up the saved configuration before tests that run "config save"; restore the file at the end
    so that no test configuration stays in /etc/sonic/config_db.json. Request it first in the test
    signature so that it is set up before, and torn down after, the other label fixtures.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command("cp {} {}".format(CONFIG_DB_FILE, CONFIG_DB_BACKUP))
    yield CONFIG_DB_BACKUP
    duthost.command("cp {} {}".format(CONFIG_DB_BACKUP, CONFIG_DB_FILE))
    duthost.command("rm -f {}".format(CONFIG_DB_BACKUP), module_ignore_errors=True)
