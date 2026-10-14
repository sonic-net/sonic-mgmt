import ipaddress
import logging

import pytest

from tests.common.config_reload import config_reload
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.helpers.assertions import pytest_assert as py_assert, pytest_require as py_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.utilities import wait_until
from tests.gribi.helper import (FIB_ACK_TIMEOUT, GRIBI_PORT, GribiClient, gribi_listening,
                                neighbor_resolved, restart_gribi)

logger = logging.getLogger(__name__)

CHECKPOINT = "gribi_test_setup"
TEST_VRF = "Vrfgribi"


def _db_get(duthost, db, key, field):
    return duthost.shell("sonic-db-cli {} HGET '{}' {}".format(db, key, field),
                         module_ignore_errors=True)["stdout"].strip()


@pytest.fixture(scope="module")
def gribi_dut(duthosts, rand_one_dut_hostname):
    """Enable the gribi feature with test settings; restore CONFIG_DB afterwards."""
    duthost = duthosts[rand_one_dut_hostname]
    py_require(_db_get(duthost, "CONFIG_DB", "FEATURE|gribi", "state") != "",
               "Image does not ship the gribi feature")
    py_require(_db_get(duthost, "CONFIG_DB", "SYSTEM_DEFAULTS|swss_zmq", "status") == "enabled",
               "gribid needs orchagent's ZeroMQ route channel (SYSTEM_DEFAULTS|swss_zmq)")

    # routeorch reports route results (the source of gRIBI FIB acks) only when
    # orchagent runs with -F, which orchagent.sh sets from suppress-fib-pending.
    enabled_fib_suppress = _db_get(duthost, "CONFIG_DB", "DEVICE_METADATA|localhost",
                                   "suppress-fib-pending") != "enabled"
    if enabled_fib_suppress:
        _set_fib_suppress(duthost, "enabled")

    create_checkpoint(duthost, CHECKPOINT)
    duthost.shell("sonic-db-cli CONFIG_DB HSET 'GRIBI|config' port {} fib_ack_timeout {} enable_reflection true"
                  .format(GRIBI_PORT, FIB_ACK_TIMEOUT))
    duthost.shell("sudo config feature state gribi enabled")
    py_assert(wait_until(60, 2, 0, check_container_state, duthost, "gribi", True),
              "gribi container did not start")
    # The container may already have been running with other settings.
    py_assert(restart_gribi(duthost), "gribid is not listening on port {}".format(GRIBI_PORT))

    yield duthost

    duthost.shell("sudo config feature state gribi disabled", module_ignore_errors=True)
    rollback_or_reload(duthost, CHECKPOINT)
    delete_checkpoint(duthost, CHECKPOINT)
    if enabled_fib_suppress:
        _set_fib_suppress(duthost, "disabled")


def _set_fib_suppress(duthost, state):
    """orchagent reads suppress-fib-pending only at startup, hence the reload."""
    duthost.shell("sudo config suppress-fib-pending {}".format(state))
    duthost.shell("sudo config save -y")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)


@pytest.fixture(scope="module")
def gribi_client(gribi_dut, ptfhost):
    return GribiClient(ptfhost, gribi_dut)


def _uplinks(duthost, tbinfo, version):
    """(PortChannel, local address with prefix, peer address) for each resolved uplink neighbor."""
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    out = []
    for intf in mg_facts["minigraph_portchannel_interfaces"]:
        peer = str(intf["peer_addr"])
        if ipaddress.ip_address(peer).version != version:
            continue
        if neighbor_resolved(duthost, intf["attachto"], peer):
            out.append((intf["attachto"], "{}/{}".format(intf["addr"], intf["prefixlen"]), peer))
    return out


@pytest.fixture(scope="module")
def uplinks_v4(gribi_dut, tbinfo):
    ups = _uplinks(gribi_dut, tbinfo, 4)
    py_require(len(ups) >= 2, "Need two resolved IPv4 PortChannel neighbors, found {}".format(ups))
    return ups


@pytest.fixture(scope="module")
def uplinks_v6(gribi_dut, tbinfo):
    ups = _uplinks(gribi_dut, tbinfo, 6)
    py_require(len(ups) >= 1, "No resolved IPv6 PortChannel neighbor")
    return ups


@pytest.fixture(scope="module")
def gribi_vrf(gribi_dut, tbinfo, uplinks_v4):
    """
    Move the last IPv4 uplink PortChannel into TEST_VRF and resolve its peer
    there. Yields (vrf, portchannel, peer).

    The port's addresses (v4 and v6) are removed and its neighbors left to
    drain before the bind: orchagent skips moving a RIF that neighbors still
    reference, and an address added before the move lands in the default VRF.
    """
    duthost = gribi_dut
    pc, local, peer = uplinks_v4[-1]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    addrs = ["{}/{}".format(i["addr"], i["prefixlen"])
             for i in mg_facts["minigraph_portchannel_interfaces"] if i["attachto"] == pc]

    for addr in addrs:
        duthost.shell("sudo config interface ip remove {} {}".format(pc, addr), module_ignore_errors=True)
    py_assert(wait_until(60, 3, 0, lambda: not duthost.shell(
        "sonic-db-cli APPL_DB KEYS 'NEIGH_TABLE:{}:*'".format(pc))["stdout"].strip()),
        "neighbors on {} did not drain".format(pc))
    duthost.shell("sudo config vrf add {}".format(TEST_VRF))
    duthost.shell("sudo config interface vrf bind {} {}".format(pc, TEST_VRF))
    py_assert(wait_until(30, 2, 0, lambda: _db_get(
        duthost, "APPL_DB", "INTF_TABLE:{}".format(pc), "vrf_name") == TEST_VRF),
        "{} was not bound to {}".format(pc, TEST_VRF))
    duthost.shell("sudo config interface ip add {} {}".format(pc, local))
    py_assert(wait_until(60, 3, 0, lambda: duthost.shell(
        "sudo ip vrf exec {} ping -c 1 -W 1 {}".format(TEST_VRF, peer), module_ignore_errors=True)["rc"] == 0
        and neighbor_resolved(duthost, pc, peer)),
        "{} did not resolve in {}".format(peer, TEST_VRF))
    # gribid creates network instances from the VRF table at startup.
    py_assert(restart_gribi(duthost), "gribid did not come back after adding {}".format(TEST_VRF))

    yield TEST_VRF, pc, peer

    duthost.shell("sudo config interface ip remove {} {}".format(pc, local), module_ignore_errors=True)
    duthost.shell("sudo config interface vrf unbind {}".format(pc), module_ignore_errors=True)
    duthost.shell("sudo config vrf del {}".format(TEST_VRF), module_ignore_errors=True)
    for addr in addrs:
        duthost.shell("sudo config interface ip add {} {}".format(pc, addr), module_ignore_errors=True)
    if gribi_listening(duthost):
        restart_gribi(duthost)
