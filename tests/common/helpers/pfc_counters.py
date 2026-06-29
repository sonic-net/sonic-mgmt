"""
Shared helpers for PFC counter tests.

Provides ``setup_testbed``, ``run_test``, and the ``leaf_fanouts`` fixture so
that any feature-specific test module (qos, macsec, …) can exercise PFC
counter verification without cross-feature imports.
"""

from tests.common.platform.device_utils import eos_to_linux_intf, nxos_to_linux_intf, sonic_to_linux_intf
from tests.common.helpers.drop_counters.drop_counters import GET_L2_COUNTERS, get_pkt_drops
import os
import time
import pytest
import logging

logger = logging.getLogger(__name__)

PFC_GEN_FILE_PATH = os.path.normpath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..',
    'ansible', 'roles', 'test', 'files', 'helpers', 'pfc_gen.py'))
""" Expected PFC generator path at the leaf fanout switch """
PFC_GEN_FILE_DEST = r'~/pfc_gen.py'
PFC_GEN_FILE_ABSOLUTE_PATH = r'/root/pfc_gen_cpu.py'

""" Number of generated packets for each test case """
PKT_COUNT = 10
""" Number of switch priorities """
PRIO_COUNT = 8
""" Name of the PFC storm container on MLNX-OS (Onyx) fanout switches """
ONYX_PFC_CONTAINER_NAME = 'storm'
""" Number of PFC frames sent per priority per port in the RX_OK isolation test """
PFC_RX_OK_ISOLATION_PKT_COUNT = 5000
""" Allowed RX_OK/RX_DRP increase per interface to tolerate background traffic """
RX_COUNTER_BACKGROUND_MARGIN = 500


@pytest.fixture(scope="module")
def leaf_fanouts(conn_graph_facts):                                      # noqa: F811
    """
    @summary: Fixture for getting the list of leaf fanout switches
    @param conn_graph_facts: Topology connectivity information
    @return: Return the list of leaf fanout switches
    """
    leaf_fanouts = []
    conn_facts = conn_graph_facts['device_conn']

    """ for each interface of DUT """
    for _, value in list(conn_facts.items()):
        for _, val in list(value.items()):
            peer_device = val['peerdevice']
            if peer_device not in leaf_fanouts:
                leaf_fanouts.append(peer_device)

    return leaf_fanouts


def setup_testbed(fanouthosts, duthost, leaf_fanouts):                   # noqa: F811
    """
    @Summary: Set up the duthost, including clearing counters,
              and copying the PFC generator to the leaf fanout switches.
    @param duthost: dut host information
    @param leaf_fanouts: Leaf fanout switches
    """
    """ Clear PFC counters """
    duthost.sonic_pfc_counters(method="clear")

    """ Copy the PFC generator to all the leaf fanout switches """
    for peer_device in leaf_fanouts:
        if peer_device not in fanouthosts:
            continue

        peerdev_ans = fanouthosts[peer_device]
        peerdev_ans.host.copy(src=PFC_GEN_FILE_PATH, dest=PFC_GEN_FILE_DEST, force=True)


def _resolve_peer_port_name(peerdev_ans, enum_fanout_graph_facts, peer_port):       # noqa: F811
    """
    @summary: Map a fanout peer port to its Linux interface name based on the
              fanout switch OS, and return it together with the fanout HwSku.
    @param peerdev_ans: Fanout host ansible handle
    @param enum_fanout_graph_facts: Fanout connection graph facts
    @param peer_port: Peer port name on the fanout switch
    @return: Tuple of (peer_port_name, fanout_hwsku)
    """
    fanout_os = peerdev_ans.get_fanout_os()
    fanout_hwsku = enum_fanout_graph_facts[peerdev_ans.hostname]["device_info"]["HwSku"]
    if fanout_os == "nxos":
        peer_port_name = nxos_to_linux_intf(peer_port)
    elif fanout_os == "sonic":
        peer_port_name = sonic_to_linux_intf(peer_port)
    else:
        peer_port_name = eos_to_linux_intf(peer_port, hwsku=fanout_hwsku)
    return peer_port_name, fanout_hwsku


def send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku, priority,
                   pause_time, pkt_count):
    """
    @summary: Send `pkt_count` PFC pause frames targeting a single priority to
              one fanout port.
    @param peerdev_ans: Fanout host ansible handle
    @param peer_port_name: Linux interface name on the fanout switch
    @param fanout_hwsku: Fanout switch HwSku (used to detect MLNX-OS/Onyx)
    @param priority: PFC priority (0-7); encoded as a class-enable bitmap
    @param pause_time: Pause time quanta (0-65535); 0 means unpause
    @param pkt_count: Number of frames to generate
    """
    if fanout_hwsku == "MLNX-OS":
        cmd = 'docker exec %s "python %s -i %s -p %d -t %d -n %d"' % (
            ONYX_PFC_CONTAINER_NAME, PFC_GEN_FILE_ABSOLUTE_PATH,
            peer_port_name, 2 ** priority, pause_time, pkt_count)
        peerdev_ans.host.config(cmd)
    else:
        cmd = "sudo python %s -i %s -p %d -t %d -n %d" % (
            PFC_GEN_FILE_DEST, peer_port_name, 2 ** priority, pause_time, pkt_count)
        peerdev_ans.host.command(cmd)


def run_test(fanouthosts, duthost, conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts,       # noqa: F811
             is_pfc=True, pause_time=65535, check_continuous_pfc=False):
    """
    @Summary: Run test for Ethernet flow control (FC) or priority-based flow control (PFC)
    @param duthost: The object for interacting with DUT through ansible
    @param conn_graph_facts: Testbed topology connectivity information
    @param leaf_fanouts: Leaf fanout switches
    @param is_pfc: If this test is for PFC?
    @param pause_time: Pause time quanta (0-65535) in the frame. 0 means unpause.
    """
    setup_testbed(fanouthosts, duthost, leaf_fanouts)
    asic = duthost.asic_instance()
    asic_type = duthost.facts["asic_type"]
    conn_facts = conn_graph_facts['device_conn'].get(duthost.hostname, {})
    onyx_pfc_container_name = ONYX_PFC_CONTAINER_NAME
    int_status = asic.show_interface(command="status")[
        'ansible_facts']['int_status']
    """ We only test active physical interfaces that have connection graph entries """
    active_phy_intfs = [intf for intf in int_status if
                        intf.startswith('Ethernet') and
                        int_status[intf]['admin_state'] == 'up' and
                        int_status[intf]['oper_state'] == 'up' and
                        intf in conn_facts]
    only_lossless_rx_counters_hwskus = ["Cisco-8122", "Cisco-8223"]
    only_lossless_rx_counters = any(sku in asic.sonichost.facts["hwsku"] for sku in only_lossless_rx_counters_hwskus)
    no_xon_counters_hwskus = ["Cisco-8122", "Cisco-8223"]
    no_xon_counters = any(sku in asic.sonichost.facts["hwsku"] for sku in no_xon_counters_hwskus)
    if only_lossless_rx_counters and asic_type != 'vs':
        config_facts = asic.config_facts(host=asic.hostname, source='persistent')['ansible_facts']
    if not check_continuous_pfc:
        if asic_type != 'vs':
            """ Generate PFC or FC packets for active physical interfaces """
            for intf in active_phy_intfs:
                peer_device = conn_facts[intf]['peerdevice']
                peer_port = conn_facts[intf]['peerport']

                if peer_device not in fanouthosts:
                    continue

                peerdev_ans = fanouthosts[peer_device]
                peer_port_name, fanout_hwsku = _resolve_peer_port_name(
                    peerdev_ans, enum_fanout_graph_facts, peer_port)

                if is_pfc:
                    for priority in range(PRIO_COUNT):
                        send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku,
                                       priority, pause_time, PKT_COUNT)
                else:
                    if fanout_hwsku == "MLNX-OS":
                        cmd = 'docker exec %s "python %s -i %s -g -t %d -n %d"' % (
                            onyx_pfc_container_name, PFC_GEN_FILE_ABSOLUTE_PATH, peer_port_name, pause_time, PKT_COUNT)
                        peerdev_ans.host.config(cmd)
                    else:
                        cmd = "sudo python %s -i %s -g -t %d -n %d" % (
                            PFC_GEN_FILE_DEST, peer_port_name, pause_time, PKT_COUNT)
                        peerdev_ans.host.command(cmd)

        """ SONiC takes some time to update counters in database """
        time.sleep(5)

        """ Check results """
        counter_facts = duthost.sonic_pfc_counters(method="get")[
            'ansible_facts']
        if only_lossless_rx_counters and asic_type != 'vs':
            pfc_enabled_prios = [int(prio) for prio in config_facts["PORT_QOS_MAP"][intf]['pfc_enable'].split(',')]
        failures = []
        for intf in active_phy_intfs:
            if is_pfc and (not no_xon_counters or pause_time != 0):
                if only_lossless_rx_counters:
                    expected_prios = [str(PKT_COUNT if prio in pfc_enabled_prios else 0) for prio in range(PRIO_COUNT)]
                else:
                    expected_prios = [str(PKT_COUNT)] * PRIO_COUNT
            else:
                # Expect 0 counters when "no_xon_counters and pause_time == 0", i.e. when
                # device does not support XON counters and the frame is XON.
                expected_prios = ['0'] * PRIO_COUNT
            logger.info("Verifying PFC RX count matches {}".format(expected_prios))
            if counter_facts[intf]['Rx'] != expected_prios:
                failures.append((counter_facts[intf]['Rx'], expected_prios))
        if asic_type != 'vs':
            for failure in failures:
                logger.error("Got {}, expected {}".format(*failure))
            assert len(failures) == 0, (
                "PFC RX counter increment not matching expected for above logged cases. "
                "Number of failures: {}"
            ).format(len(failures))

    else:
        """ Poll interval and timeout for waiting on counter updates """
        POLL_INTERVAL = 0.5
        POLL_TIMEOUT = 10
        """ Retry sending frames once if the counter does not update in time """
        MAX_RETRIES = 2

        for intf in active_phy_intfs:
            """only check priority 3 and 4: lossless priorities"""
            for priority in range(3, 5):
                """ Clear PFC counters """
                duthost.sonic_pfc_counters(method="clear")

                if asic_type != 'vs':
                    peer_device = conn_facts[intf]['peerdevice']
                    peer_port = conn_facts[intf]['peerport']

                    if peer_device not in fanouthosts:
                        continue

                    peerdev_ans = fanouthosts[peer_device]
                    peer_port_name, fanout_hwsku = _resolve_peer_port_name(
                        peerdev_ans, enum_fanout_graph_facts, peer_port)

                    send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku,
                                   priority, pause_time, PKT_COUNT)

                    pfc_rx = {}
                    for attempt in range(1, MAX_RETRIES + 1):
                        """ Poll until counter reaches PKT_COUNT or timeout """
                        deadline = time.time() + POLL_TIMEOUT
                        pfc_rx = duthost.sonic_pfc_counters(method="get")['ansible_facts']
                        while pfc_rx[intf]['Rx'][priority] != str(PKT_COUNT) and time.time() < deadline:
                            time.sleep(POLL_INTERVAL)
                            pfc_rx = duthost.sonic_pfc_counters(method="get")['ansible_facts']

                        if pfc_rx[intf]['Rx'][priority] == str(PKT_COUNT):
                            break

                        if attempt < MAX_RETRIES:
                            logger.warning(
                                "Attempt %d: PFC counter not updated for interface %s priority %d "
                                "(got %s), retrying send", attempt, intf, priority,
                                pfc_rx[intf]['Rx'][priority])
                            duthost.sonic_pfc_counters(method="clear")
                            send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku,
                                           priority, pause_time, PKT_COUNT)

                else:
                    time.sleep(5)
                    pfc_rx = duthost.sonic_pfc_counters(method="get")['ansible_facts']

                if asic_type != 'vs':
                    """check pfc Rx frame count on particular priority are increased"""
                    assert pfc_rx[intf]['Rx'][priority] == str(PKT_COUNT), (
                        "PFC RX counter value mismatch for interface {} and priority {}. "
                        "Expected value: {}, but got {}."
                    ).format(intf, priority, PKT_COUNT, pfc_rx[intf]['Rx'][priority])

                    """check LHS priorities are 0 count"""
                    for i in range(priority):
                        assert pfc_rx[intf]['Rx'][i] == '0', (
                            "PFC RX counter value is not zero for interface {} and priority {}. "
                            "Expected value: 0, but got {}."
                        ).format(intf, i, pfc_rx[intf]['Rx'][i])

                    """check RHS priorities are 0 count"""
                    for i in range(priority+1, PRIO_COUNT):
                        assert pfc_rx[intf]['Rx'][i] == '0', (
                            "PFC RX counter value is not zero for interface {} and priority {}. "
                            "Expected value: 0, but got {}."
                        ).format(intf, i, pfc_rx[intf]['Rx'][i])


def get_rx_port_counters(duthost):
    """
    @summary: Retrieve RX_OK and RX_DRP counters for all ports in a single
              `portstat -j` pass (multi-ASIC aware via get_pkt_drops).
    @param duthost: dut host information
    @return: Dict mapping interface name to {'RX_OK': int, 'RX_DRP': int}
    """
    raw_counters = get_pkt_drops(duthost, GET_L2_COUNTERS)

    counters = {}
    for port, stats in list(raw_counters.items()):
        rx_ok = stats.get('RX_OK')
        rx_drp = stats.get('RX_DRP')
        counters[port] = {
            'RX_OK': int(str(rx_ok).replace(',', '')) if rx_ok not in (None, 'N/A') else 0,
            'RX_DRP': int(str(rx_drp).replace(',', '')) if rx_drp not in (None, 'N/A') else 0,
        }
    return counters


def run_rx_ok_isolation_test(fanouthosts, duthost, conn_graph_facts,       # noqa: F811
                             enum_fanout_graph_facts, leaf_fanouts,
                             pkt_count=PFC_RX_OK_ISOLATION_PKT_COUNT,
                             margin=RX_COUNTER_BACKGROUND_MARGIN,
                             pause_time=65535):
    """
    @summary: Verify that PFC pause frames are consumed by the MAC and are NOT
              counted as normal RX packets (RX_OK) or RX drops (RX_DRP) on the
              DUT interfaces.

              A large burst of PFC frames is sent across all priorities to every
              active physical interface first; only then is a single counter
              snapshot compared against the baseline (one stats retrieval pass).
              The RX_OK and RX_DRP deltas must each stay within `margin` to
              tolerate background control-plane traffic.
    @param duthost: The object for interacting with DUT through ansible
    @param conn_graph_facts: Testbed topology connectivity information
    @param leaf_fanouts: Leaf fanout switches
    @param pkt_count: Number of PFC frames to send per priority per port
    @param margin: Allowed RX_OK/RX_DRP increase per interface
    @param pause_time: Pause time quanta (0-65535) in the frame
    """
    setup_testbed(fanouthosts, duthost, leaf_fanouts)
    asic = duthost.asic_instance()
    asic_type = duthost.facts["asic_type"]
    if asic_type == 'vs':
        pytest.skip("PFC RX_OK isolation test is not applicable to the VS platform")

    conn_facts = conn_graph_facts['device_conn'].get(duthost.hostname, {})
    int_status = asic.show_interface(command="status")['ansible_facts']['int_status']
    """ We only test active physical interfaces that have connection graph entries """
    active_phy_intfs = [intf for intf in int_status if
                        intf.startswith('Ethernet') and
                        int_status[intf]['admin_state'] == 'up' and
                        int_status[intf]['oper_state'] == 'up' and
                        intf in conn_facts]

    """ Baseline RX counters for all ports in a single retrieval """
    baseline = get_rx_port_counters(duthost)

    """ Send all PFC frames first, across all priorities and all ports """
    for intf in active_phy_intfs:
        peer_device = conn_facts[intf]['peerdevice']
        peer_port = conn_facts[intf]['peerport']

        if peer_device not in fanouthosts:
            continue

        peerdev_ans = fanouthosts[peer_device]
        peer_port_name, fanout_hwsku = _resolve_peer_port_name(
            peerdev_ans, enum_fanout_graph_facts, peer_port)
        for priority in range(PRIO_COUNT):
            send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku,
                           priority, pause_time, pkt_count)

    """ SONiC takes some time to update counters in database """
    time.sleep(5)

    """ Validate RX counters in one single retrieval swoop """
    after = get_rx_port_counters(duthost)

    failures = []
    for intf in active_phy_intfs:
        if intf not in baseline or intf not in after:
            continue
        rx_ok_delta = after[intf]['RX_OK'] - baseline[intf]['RX_OK']
        rx_drp_delta = after[intf]['RX_DRP'] - baseline[intf]['RX_DRP']
        if rx_ok_delta > margin or rx_drp_delta > margin:
            failures.append((intf, rx_ok_delta, rx_drp_delta))
            logger.error(
                "Interface %s: RX_OK increased by %d, RX_DRP increased by %d "
                "(allowed margin %d) after receiving %d PFC frames per priority",
                intf, rx_ok_delta, rx_drp_delta, margin, pkt_count)

    assert len(failures) == 0, (
        "PFC frames were counted as RX_OK or RX_DRP beyond the allowed margin of {} "
        "on the following interfaces [(intf, rx_ok_delta, rx_drp_delta)]: {}"
    ).format(margin, failures)
