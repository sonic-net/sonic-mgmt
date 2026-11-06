"""
Ensure identical config replace does not disable the port's ASIC bridge-port or break L2 forwarding.
"""
import logging
import shlex
import uuid

import pytest
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.vlan_hardening import ignore_expected_loganalyzer_exceptions  # noqa: F401
from tests.common.helpers.vlan_hardening import (
    borrow_ports,
    get_bridge_port_admin_state,
    get_config_facts,
    pick_free_vlan_id,
    ptf_indices_for_ports,
    release_prior_membership,
    restore_borrowed_port,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# VLAN ID search range for a temporary test VLAN not already in use.
TEST_VLAN_ID_RANGE = range(1988, 2047)

# Max wait for ASIC_DB/STATE_DB to settle after config or admin-flap, using wait_until.
SETTLE_TIMEOUT = 60
SETTLE_INTERVAL = 2
FLAP_TIMEOUT = 30
FLAP_INTERVAL = 2


_STRIP_BGPRAW_SCRIPT = (
    "import json\n"
    "import sys\n"
    "\n"
    "path = sys.argv[1]\n"
    "with open(path) as f:\n"
    "    data = json.load(f)\n"
    "data.pop('bgpraw', None)\n"
    "with open(path, 'w') as f:\n"
    "    json.dump(data, f)\n"
)


def _trigger_config_replace(duthost, snapshot_path):
    # Replay the current running config via `config replace`, stripping `bgpraw` for compatibility.
    duthost.shell("show runningconfiguration all > {}".format(shlex.quote(snapshot_path)))
    # The snapshot path (which embeds duthost.hostname) is passed as a CLI arg rather than
    # interpolated into the Python source, so a hostname containing a quote can't break the script.
    script_path = "/tmp/strip_bgpraw_{}.py".format(uuid.uuid4().hex)
    duthost.copy(content=_STRIP_BGPRAW_SCRIPT, dest=script_path)
    try:
        duthost.shell("python3 {} {}".format(shlex.quote(script_path), shlex.quote(snapshot_path)))
    finally:
        duthost.shell("rm -f {}".format(shlex.quote(script_path)), module_ignore_errors=True)
    result = duthost.shell("config replace {}".format(shlex.quote(snapshot_path)), module_ignore_errors=True)
    pytest_assert(
        not result['rc'],
        "config replace failed unexpectedly (rc={}): stdout={} stderr={}".format(
            result['rc'], result.get('stdout'), result.get('stderr'))
    )
    return result


def _recover_if_stranded(duthost, asic, port):
    # Best-effort teardown recovery for a BRIDGE_PORT stranded admin_state=false.
    try:
        state = get_bridge_port_admin_state(duthost, asic, port)
        if state is not False:
            if state is None:
                logger.info(
                    "Post-teardown BRIDGE_PORT admin_state check for %s returned None (no bound BRIDGE_PORT "
                    "object found in ASIC_DB); nothing to recover.", port)
            return

        logger.warning(
            "Port %s BRIDGE_PORT object is STILL stranded at admin_state=false after normal teardown; "
            "attempting a recovery interface flap.", port)

        duthost.shell("config interface shutdown {}".format(port))

        def _oper_down():
            status = duthost.get_interfaces_status()
            return status.get(port, {}).get('oper', '').lower() == 'down'

        if not wait_until(FLAP_TIMEOUT, FLAP_INTERVAL, 0, _oper_down):
            logger.warning("Port %s did not report oper down within %ss during recovery flap.", port, FLAP_TIMEOUT)

        duthost.shell("config interface startup {}".format(port))

        def _oper_up():
            status = duthost.get_interfaces_status()
            return status.get(port, {}).get('oper', '').lower() == 'up'

        if not wait_until(FLAP_TIMEOUT, FLAP_INTERVAL, 0, _oper_up):
            logger.warning("Port %s did not report oper up within %ss during recovery flap.", port, FLAP_TIMEOUT)

        final_state = get_bridge_port_admin_state(duthost, asic, port)
        if final_state is True:
            logger.info("Recovery flap succeeded: %s BRIDGE_PORT admin_state is now True.", port)
        else:
            logger.error(
                "Recovery flap did not restore BRIDGE_PORT admin_state on %s (state=%s); "
                "manual intervention may be required.", port, final_state)
    except Exception as exc:
        logger.error(
            "Exception during BRIDGE_PORT recovery for %s: %s; manual intervention may be required.", port, exc)


@pytest.fixture
def vlan_config_replace_setup(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index, ptfhost):
    # Set up a temporary test VLAN on borrowed ports, verify bridge-port health, then restore on teardown.
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_multi_asic:
        # Restrict to single-ASIC DUTs because config replace replays the entire device configuration.
        pytest.skip("test_vlan_config_replace is scoped to a single ASIC but `config replace` "
                    "replays the whole box's config; skipping on multi-asic DUT {}.".format(duthost.hostname))
    asic = duthost.asic_instance(enum_frontend_asic_index)
    logger.info("Using ptfhost %s for dataplane I/O in this test", ptfhost.hostname)

    borrowed = borrow_ports(duthost, tbinfo, enum_frontend_asic_index, 2)
    if len(borrowed) < 2:
        pytest.skip("Not enough usable ports available to run this test (2 needed, {} found).".format(
            len(borrowed)))
    port_under_test, peer_port = (b["port"] for b in borrowed)
    for descriptor in borrowed:
        release_prior_membership(duthost, descriptor)

    ptf_indices = ptf_indices_for_ports(
        duthost, ptfhost, tbinfo, enum_frontend_asic_index, [port_under_test, peer_port])
    if port_under_test not in ptf_indices or peer_port not in ptf_indices:
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)
        pytest.skip("Borrowed ports {} / {} have no PTF dataplane index on this topology; "
                    "cannot inject traffic.".format(port_under_test, peer_port))

    test_vlan_id = pick_free_vlan_id(get_config_facts(duthost), TEST_VLAN_ID_RANGE)
    # Unique per test invocation: a fixed path would let concurrent/re-run instances of this
    # test on the same DUT clobber each other's snapshot mid-write.
    config_snapshot_path = "/tmp/config_replace_snapshot_{}_{}.json".format(
        duthost.hostname, uuid.uuid4().hex)

    logger.info(
        "Adding %s as test port and %s as peer to test VLAN %s as untagged members",
        port_under_test, peer_port, test_vlan_id)

    # Create the dedicated test VLAN and add both ports as untagged members.
    duthost.shell("config vlan add {}".format(test_vlan_id))
    duthost.shell("config vlan member add {} {} --untagged".format(test_vlan_id, port_under_test))
    duthost.shell("config vlan member add {} {} --untagged".format(test_vlan_id, peer_port))

    # Poll until the port-under-test's BRIDGE_PORT object shows up in ASIC_DB.
    wait_until(SETTLE_TIMEOUT, SETTLE_INTERVAL, 0,
               lambda: get_bridge_port_admin_state(duthost, asic, port_under_test) is not None)

    baseline_state = get_bridge_port_admin_state(duthost, asic, port_under_test)
    pytest_assert(
        baseline_state is True,
        "Pre-existing bad BRIDGE_PORT admin_state on {} (state={}) before test trigger; refusing to "
        "proceed until the DUT bridge-port state is cleared.".format(port_under_test, baseline_state)
    )

    ctx = {
        'duthost': duthost,
        'asic': asic,
        'port_under_test': port_under_test,
        'peer_port': peer_port,
        'test_vlan_id': test_vlan_id,
        'ptf_port_under_test': ptf_indices[port_under_test],
        'ptf_peer_port': ptf_indices[peer_port],
        'config_snapshot_path': config_snapshot_path,
    }

    try:
        yield ctx
    finally:
        duthost.shell("rm -f {}".format(config_snapshot_path), module_ignore_errors=True)

        duthost.shell("config vlan member del {} {}".format(test_vlan_id, port_under_test), module_ignore_errors=True)
        duthost.shell("config vlan member del {} {}".format(test_vlan_id, peer_port), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(test_vlan_id), module_ignore_errors=True)

        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)

        _recover_if_stranded(duthost, asic, port_under_test)


def test_config_replace_preserves_admin_state(vlan_config_replace_setup):
    # Verify identical `config replace` leaves the port's ASIC_DB bridge-port admin_state true.
    duthost = vlan_config_replace_setup['duthost']
    asic = vlan_config_replace_setup['asic']
    port = vlan_config_replace_setup['port_under_test']

    pre_state = get_bridge_port_admin_state(duthost, asic, port)
    pytest_assert(
        pre_state is True,
        "Baseline BRIDGE_PORT admin_state for {} is not True before config replace (state={}); "
        "aborting.".format(port, pre_state)
    )

    _trigger_config_replace(duthost, vlan_config_replace_setup['config_snapshot_path'])

    pytest_assert(
        wait_until(SETTLE_TIMEOUT, SETTLE_INTERVAL, 0,
                   lambda: get_bridge_port_admin_state(duthost, asic, port) is not None),
        "BRIDGE_PORT object for {} never re-appeared in ASIC_DB within {}s after config "
        "replace".format(port, SETTLE_TIMEOUT)
    )

    post_state = get_bridge_port_admin_state(duthost, asic, port)
    pytest_assert(
        post_state is True,
        "After identical config replace, {} has BRIDGE_PORT admin_state={} in ASIC_DB "
        "(expected True).".format(port, post_state)
    )


def test_config_replace_preserves_forwarding(ptfadapter, vlan_config_replace_setup, tbinfo):
    # Verify L2 forwarding still works after identical `config replace`, before and after as control.
    if "dualtor" in tbinfo["topo"]["name"]:
        pytest.skip("Dual TOR device does not support broadcast packets")

    duthost = vlan_config_replace_setup['duthost']
    asic = vlan_config_replace_setup['asic']
    port_under_test = vlan_config_replace_setup['port_under_test']
    ptf_port_under_test = vlan_config_replace_setup['ptf_port_under_test']
    ptf_peer_port = vlan_config_replace_setup['ptf_peer_port']

    pkt = testutils.simple_eth_packet(
        eth_dst="ff:ff:ff:ff:ff:ff",
        eth_src="00:22:00:00:00:02",
        eth_type=0x1234,
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_peer_port, pkt)
    testutils.verify_packets_any(ptfadapter, pkt, ports=[ptf_port_under_test])

    _trigger_config_replace(duthost, vlan_config_replace_setup['config_snapshot_path'])

    pytest_assert(
        wait_until(SETTLE_TIMEOUT, SETTLE_INTERVAL, 0,
                   lambda: get_bridge_port_admin_state(duthost, asic, port_under_test) is not None),
        "BRIDGE_PORT object for {} never re-appeared in ASIC_DB within {}s after config "
        "replace".format(port_under_test, SETTLE_TIMEOUT)
    )

    # Re-send and confirm forwarding still works.
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_peer_port, pkt)
    try:
        testutils.verify_packets_any(ptfadapter, pkt, ports=[ptf_port_under_test])
    except AssertionError as detail:
        pytest.fail(
            "peer->port_under_test forwarding on {} failed after config replace: {}".format(
                port_under_test, detail))
