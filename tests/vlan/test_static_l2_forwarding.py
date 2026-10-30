"""
sonic-mgmt data-plane tests for config-driven static L2 forwarding (per-VLAN).

Covers the three independent sub-features (HLD: https://github.com/sonic-net/SONiC/pull/2468):

  1. Per-VLAN MAC-learning disable -> SAI_VLAN_ATTR_LEARN_DISABLE
  2. Per-VLAN BUM flood disable     -> SAI_VLAN_ATTR_{UNKNOWN_UNICAST,UNKNOWN_MULTICAST,BROADCAST}_FLOOD_CONTROL_TYPE
  3. Static FDB via CONFIG_DB       -> SAI_FDB_ENTRY_TYPE_STATIC

Each sub-feature is toggled via the CONFIG_DB (the same path used by `config apply-patch` / gNMI /
the `config mac` CLI) and verified from the data plane using PTF. Every test restores the default
(learning on, flooding on, no static FDB) on teardown.
"""
import collections
import logging
import time

import pytest
import ptf.testutils as testutils

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.duthost_utils import ports_list                      # noqa: F401
from tests.common.helpers.portchannel_to_vlan import running_vlan_ports_list

pytestmark = [
    pytest.mark.topology('t0'),
]
logger = logging.getLogger(__name__)

TEST_SRC_MAC = "00:aa:12:34:56:78"      # unknown src MAC used for learning / flood tests
STATIC_MAC = "00:bb:12:34:56:99"        # MAC programmed as a static FDB entry
FDB_WAIT_SEC = 20                       # max time to wait for an FDB entry to (dis)appear


# ---------------------------------------------------------------------------
# CONFIG_DB helpers (equivalent to `config apply-patch` / gNMI / `config mac`)
# ---------------------------------------------------------------------------
def _set_vlan_field(duthost, vlan_id, field, value):
    duthost.shell("sonic-db-cli CONFIG_DB HSET 'VLAN|Vlan{}' {} {}".format(vlan_id, field, value))


def _del_vlan_field(duthost, vlan_id, field):
    duthost.shell("sonic-db-cli CONFIG_DB HDEL 'VLAN|Vlan{}' {}".format(vlan_id, field),
                  module_ignore_errors=True)


def _add_static_fdb(duthost, vlan_id, mac, port):
    # CLI equivalent: `config mac add <mac> <vlan_id> <port>`
    duthost.shell("sonic-db-cli CONFIG_DB HSET 'FDB|Vlan{}|{}' port {}".format(vlan_id, mac, port))


def _del_static_fdb(duthost, vlan_id, mac):
    # CLI equivalent: `config mac del <mac> <vlan_id>`
    duthost.shell("sonic-db-cli CONFIG_DB DEL 'FDB|Vlan{}|{}'".format(vlan_id, mac),
                  module_ignore_errors=True)


def _fdb_lines(duthost):
    return duthost.command("fdbshow")["stdout_lines"]


def _mac_in_fdb(duthost, mac):
    mac = mac.lower()
    return any(mac in line.lower() for line in _fdb_lines(duthost))


def _mac_not_in_fdb(duthost, mac):
    return not _mac_in_fdb(duthost, mac)


def _mac_is_static(duthost, mac):
    mac = mac.lower()
    for line in _fdb_lines(duthost):
        if mac in line.lower():
            return "static" in line.lower()
    return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def vlan_members(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list):    # noqa: F811
    """
    Pick a VLAN that has at least two single-port untagged members and return
    (vlan_id, [(dut_port_name, ptf_port_index), ...]). Skips if none is available.
    """
    vlan_ports = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    by_vlan = collections.defaultdict(list)
    for vlan_port in vlan_ports:
        pvid = vlan_port.get("pvid")
        # single-port untagged members give a clean port-name <-> ptf-index mapping
        if pvid and len(vlan_port["port_index"]) == 1:
            by_vlan[pvid].append((vlan_port["dev"], vlan_port["port_index"][0]))
    selected = None
    for vlan_id, members in by_vlan.items():
        if len(members) >= 2:
            logger.info("static-l2: using Vlan%d with untagged members %s", vlan_id, members)
            selected = (vlan_id, members)
            break
    if selected is None:
        pytest.skip("static-l2: need a VLAN with >= 2 single-port untagged members")
    return selected


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    if loganalyzer:
        duthost = duthosts[rand_one_dut_hostname]
        loganalyzer[duthost.hostname].ignore_regex.extend([
            r".*ERR swss#orchagent: .*update: Failed to get port by bridge port ID.*",
        ])
    yield


def _l2_packet(dst_mac, src_mac=TEST_SRC_MAC):
    return testutils.simple_udp_packet(eth_dst=dst_mac, eth_src=src_mac,
                                       ip_src="192.168.0.1", ip_dst="192.168.0.2")


# ---------------------------------------------------------------------------
# 1. Per-VLAN MAC-learning disable
# ---------------------------------------------------------------------------
class TestVlanMacLearningDisable:

    @pytest.fixture(autouse=True)
    def restore(self, duthosts, rand_one_dut_hostname, vlan_members):
        yield
        duthost = duthosts[rand_one_dut_hostname]
        vlan_id, _ = vlan_members
        _del_vlan_field(duthost, vlan_id, "mac_learning")
        duthost.command("sonic-clear fdb all", module_ignore_errors=True)

    def test_mac_learning_disable(self, duthosts, rand_one_dut_hostname, ptfadapter, vlan_members):
        duthost = duthosts[rand_one_dut_hostname]
        vlan_id, members = vlan_members
        _, src_idx = members[0]
        pkt = _l2_packet(dst_mac="00:aa:99:99:99:99")

        # mac_learning=disabled -> the src MAC must NOT be learned
        duthost.command("sonic-clear fdb all", module_ignore_errors=True)
        _set_vlan_field(duthost, vlan_id, "mac_learning", "disabled")
        ptfadapter.dataplane.flush()
        for _ in range(5):
            testutils.send(ptfadapter, src_idx, pkt)
        pytest_assert(
            wait_until(FDB_WAIT_SEC, 3, 0, _mac_not_in_fdb, duthost, TEST_SRC_MAC),
            "MAC {} was learned on Vlan{} even though mac_learning=disabled".format(TEST_SRC_MAC, vlan_id))

        # mac_learning=enabled -> the src MAC IS learned (control)
        _set_vlan_field(duthost, vlan_id, "mac_learning", "enabled")
        duthost.command("sonic-clear fdb all", module_ignore_errors=True)
        ptfadapter.dataplane.flush()
        for _ in range(5):
            testutils.send(ptfadapter, src_idx, pkt)
        pytest_assert(
            wait_until(FDB_WAIT_SEC, 3, 0, _mac_in_fdb, duthost, TEST_SRC_MAC),
            "MAC {} was NOT learned on Vlan{} with mac_learning=enabled".format(TEST_SRC_MAC, vlan_id))


# ---------------------------------------------------------------------------
# 2. Per-VLAN BUM flood disable (broadcast)
# ---------------------------------------------------------------------------
class TestVlanBumFloodDisable:

    FLOOD_FIELDS = ["unknown_unicast_flood", "unknown_multicast_flood", "broadcast_flood"]

    @pytest.fixture(autouse=True)
    def restore(self, duthosts, rand_one_dut_hostname, vlan_members):
        yield
        duthost = duthosts[rand_one_dut_hostname]
        vlan_id, _ = vlan_members
        for field in self.FLOOD_FIELDS:
            _del_vlan_field(duthost, vlan_id, field)

    def test_broadcast_flood_disable(self, duthosts, rand_one_dut_hostname, ptfadapter, vlan_members):
        duthost = duthosts[rand_one_dut_hostname]
        vlan_id, members = vlan_members
        _, src_idx = members[0]
        dst_idxs = [idx for _, idx in members[1:]]
        bcast = _l2_packet(dst_mac="ff:ff:ff:ff:ff:ff")

        # all flood types disabled -> broadcast must NOT be flooded to other members
        for field in self.FLOOD_FIELDS:
            _set_vlan_field(duthost, vlan_id, field, "disabled")
        time.sleep(3)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_idx, bcast)
        testutils.verify_no_packet_any(ptfadapter, bcast, dst_idxs)

        # flood types enabled -> broadcast IS flooded to the other members (control)
        for field in self.FLOOD_FIELDS:
            _set_vlan_field(duthost, vlan_id, field, "enabled")
        time.sleep(3)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_idx, bcast)
        testutils.verify_packets_any(ptfadapter, bcast, dst_idxs)


# ---------------------------------------------------------------------------
# 3. Static FDB via CONFIG_DB
# ---------------------------------------------------------------------------
class TestVlanStaticFdb:

    @pytest.fixture(autouse=True)
    def restore(self, duthosts, rand_one_dut_hostname, vlan_members):
        yield
        duthost = duthosts[rand_one_dut_hostname]
        vlan_id, _ = vlan_members
        _del_static_fdb(duthost, vlan_id, STATIC_MAC)
        duthost.command("sonic-clear fdb all", module_ignore_errors=True)

    def test_static_fdb_forwarding(self, duthosts, rand_one_dut_hostname, ptfadapter, vlan_members):
        duthost = duthosts[rand_one_dut_hostname]
        vlan_id, members = vlan_members
        _, src_idx = members[0]
        dst_dev, dst_idx = members[1]
        ucast = _l2_packet(dst_mac=STATIC_MAC)

        # add a static FDB entry STATIC_MAC -> dst_dev
        duthost.command("sonic-clear fdb all", module_ignore_errors=True)
        _add_static_fdb(duthost, vlan_id, STATIC_MAC, dst_dev)
        pytest_assert(
            wait_until(FDB_WAIT_SEC, 3, 0, _mac_is_static, duthost, STATIC_MAC),
            "Static FDB {} not present/Static in fdbshow".format(STATIC_MAC))

        # a unicast to STATIC_MAC is forwarded only to the configured port
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_idx, ucast)
        testutils.verify_packets(ptfadapter, ucast, ports=[dst_idx])

        # delete the static FDB entry -> it disappears
        _del_static_fdb(duthost, vlan_id, STATIC_MAC)
        pytest_assert(
            wait_until(FDB_WAIT_SEC, 3, 0, _mac_not_in_fdb, duthost, STATIC_MAC),
            "Static FDB {} still present after delete".format(STATIC_MAC))
