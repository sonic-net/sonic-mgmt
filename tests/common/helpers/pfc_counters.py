"""
Shared helpers for PFC counter tests.

Provides ``setup_testbed``, ``run_test``, and the ``leaf_fanouts`` fixture so
that any feature-specific test module (qos, macsec, …) can exercise PFC
counter verification without cross-feature imports.
"""

from tests.common.platform.device_utils import eos_to_linux_intf, nxos_to_linux_intf, sonic_to_linux_intf
from tests.common.helpers.drop_counters.drop_counters import GET_L2_COUNTERS, get_pkt_drops
import os
import random
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
PFC_COUNTER_POLL_TIMEOUT = 20
PFC_COUNTER_POLL_INTERVAL = 1
""" Continuous-PFC per-priority counter polling: max wait and poll interval (seconds) """
PFC_CONTINUOUS_POLL_TIMEOUT = 15
PFC_CONTINUOUS_POLL_INTERVAL = 0.2
""" After clearing counters, require the port to read zero across this window -- longer
than the ~1s FlexCounter poll """
PFC_CLEAR_VERIFY_WINDOW = 1.5
PFC_CLEAR_SETTLE_TIMEOUT = 15
""" Name of the PFC storm container on MLNX-OS (Onyx) fanout switches """
ONYX_PFC_CONTAINER_NAME = 'storm'
""" Number of PFC frames sent per priority per port in the RX_OK isolation test """
PFC_RX_OK_ISOLATION_PKT_COUNT = 5000
""" Allowed RX_OK/RX_DRP increase per interface to tolerate background traffic """
RX_COUNTER_BACKGROUND_MARGIN = 2000
""" Raw COUNTERS_DB PFC RX fields, indexed by priority """
PFC_RX_COUNTER_FIELDS = ['SAI_PORT_STAT_PFC_{}_RX_PKTS'.format(prio) for prio in range(PRIO_COUNT)]
""" Raw COUNTERS_DB sampling (diagnostics only): sample spacing and max wait for the
    target priority to reach the expected delta """
PFC_RAW_SAMPLE_INTERVAL = 0.2
PFC_RAW_SAMPLE_TIMEOUT = 15
""" Keep sampling this long after the expected delta is first seen, so late drops /
    re-adds (non-monotonic settling) are captured too """
PFC_RAW_SETTLE_WINDOW = 3.0


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


def clear_pfc_counters_until_stable(duthost, intf, priority, settle_s: float):            # noqa: F811
    """
    @summary: Clear PFC counters and re-clear until the port reads a stable zero.

              pfcstat reports the current COUNTERS_DB contents **minus** a baseline
              snapshot of same taken at clear time ("pfcstat -c"). But, COUNTERS_DB
              updates asynchronously. A clear issued right after PFC frames are rx'ed
              can capture an unsettled baseline (race condition!), and the offsets will
              persist bogusly for each subsequent read.
              Re-clear until the port stably reads zeroes instead.
    @param duthost: dut host information
    @param intf: Interface being validated
    @param priority: PFC priority index being validated (for diagnostics)
    @param settle_s: Time in seconds to wait for the port to stabilize after clearing PFC counters
    """
    deadline = time.monotonic() + PFC_CLEAR_SETTLE_TIMEOUT
    while True:
        duthost.sonic_pfc_counters(method="clear")
        time.sleep(settle_s)
        baseline_rx = duthost.sonic_pfc_counters(method="get")['ansible_facts'][intf]['Rx']
        if all(v == '0' for v in baseline_rx):
            break
        if time.monotonic() >= deadline:
            # Never measure against a known-dirty baseline: a stale value
            # could satisfy the later assertion with no real traffic.
            pytest.fail(
                "[PFC clear] {} prio {} baseline did not clear within {:.1f}s "
                "(last Rx={})".format(
                    intf, priority, PFC_CLEAR_SETTLE_TIMEOUT, baseline_rx))


def get_port_counter_oid(asic, intf):
    """
    @summary: Look up the SAI object id used to key a port's COUNTERS_DB entry.
    @param asic: Asic instance (namespace aware sonic-db-cli wrapper)
    @param intf: Interface name, e.g. "Ethernet0"
    @return: OID string (e.g. "oid:0x1000000000012") or None when not present
    """
    oid = asic.run_sonic_db_cli_cmd(
        "COUNTERS_DB hget COUNTERS_PORT_NAME_MAP {}".format(intf))['stdout'].strip()
    return oid or None


def get_raw_pfc_rx_counters(asic, counter_oid):
    """
    @summary: Read the raw, un-diffed per-priority PFC RX counters straight from
              COUNTERS_DB, bypassing pfcstat's cached baseline.
    @param asic: Asic instance (namespace aware sonic-db-cli wrapper)
    @param counter_oid: Port OID from `get_port_counter_oid`
    @return: List of PRIO_COUNT ints, with None for any field missing from the DB
    """
    cmd = "COUNTERS_DB hmget COUNTERS:{} {}".format(
        counter_oid, ' '.join(PFC_RX_COUNTER_FIELDS))
    lines = asic.run_sonic_db_cli_cmd(cmd)['stdout_lines']

    values = []
    for line in lines[:PRIO_COUNT]:
        line = line.strip()
        values.append(int(line) if line.isdigit() else None)
    values.extend([None] * (PRIO_COUNT - len(values)))
    return values


def sample_raw_pfc_rx_counters(asic, counter_oid, priority, baseline, expected,
                               timeout=PFC_RAW_SAMPLE_TIMEOUT,
                               settle_window=PFC_RAW_SETTLE_WINDOW,
                               interval=PFC_RAW_SAMPLE_INTERVAL):
    """
    @summary: Sample raw COUNTERS_DB PFC RX counters across the window in which a
              burst of frames becomes visible. Sampling continues for
              `settle_window` after the expected delta is first observed, because
              the counter has been seen to reach the right value, drop a batch,
              then re-add it.
    @param asic: Asic instance (namespace aware sonic-db-cli wrapper)
    @param counter_oid: Port OID from `get_port_counter_oid`
    @param priority: PFC priority index that frames were sent on
    @param baseline: Raw counters read immediately before sending
    @param expected: Number of frames sent on `priority`
    @return: List of (monotonic timestamp, raw counter list) samples
    """
    samples = []
    deadline = time.monotonic() + timeout
    settle_deadline = None

    while True:
        now = time.monotonic()
        values = get_raw_pfc_rx_counters(asic, counter_oid)
        samples.append((now, values))

        reached = (values[priority] is not None and baseline[priority] is not None
                   and values[priority] - baseline[priority] >= expected)
        if reached and settle_deadline is None:
            settle_deadline = now + settle_window
        if now >= deadline or (settle_deadline is not None and now >= settle_deadline):
            return samples
        time.sleep(interval)


def check_raw_pfc_counter_sanity(asic, counter_oid, intf, priority, baseline, expected):
    """
    @summary: Sample raw COUNTERS_DB across a PFC burst and report counter
              anomalies: non-monotonic reads (a counter going backwards),
              double-counting (delta exceeding the number of frames sent) and
              cross-priority leakage. These are platform-level symptoms, so they
              are logged rather than asserted -- the test's own tolerance of them
              is a workaround, not a fix.
    @param asic: Asic instance (namespace aware sonic-db-cli wrapper)
    @param counter_oid: Port OID from `get_port_counter_oid`
    @param intf: Interface being validated
    @param priority: PFC priority index that frames were sent on
    @param baseline: Raw counters read immediately before sending
    @param expected: Number of frames sent on `priority`
    @return: List of anomaly description strings (empty when the counters behaved)
    """
    samples = sample_raw_pfc_rx_counters(asic, counter_oid, priority, baseline, expected)
    anomalies = []

    start_ts = samples[0][0] if samples else 0
    prev = baseline
    for ts, values in samples:
        for prio in range(PRIO_COUNT):
            if values[prio] is None or prev[prio] is None:
                continue
            if values[prio] < prev[prio]:
                anomalies.append(
                    "non-monotonic: prio {} went {} -> {} (-{}) at t+{:.1f}s".format(
                        prio, prev[prio], values[prio], prev[prio] - values[prio],
                        ts - start_ts))
        prev = values

    def delta(values, prio):
        if values[prio] is None or baseline[prio] is None:
            return None
        return values[prio] - baseline[prio]

    peak = max([d for d in (delta(v, priority) for _, v in samples) if d is not None] or [None])
    final = delta(samples[-1][1], priority) if samples else None
    if peak is not None and peak > expected:
        anomalies.append(
            "double-counted: prio {} peaked at delta {} for {} frames sent".format(
                priority, peak, expected))
    if final is not None and final > expected:
        anomalies.append(
            "double-counted (settled): prio {} settled at delta {} for {} frames sent".format(
                priority, final, expected))

    if samples:
        for prio in range(PRIO_COUNT):
            if prio == priority:
                continue
            other = delta(samples[-1][1], prio)
            if other:
                anomalies.append(
                    "cross-priority: prio {} moved by {} while sending on prio {}".format(
                        prio, other, priority))

    trace = ' '.join('t+{:.1f}s={}'.format(ts - start_ts, values) for ts, values in samples)
    if anomalies:
        logger.warning(
            "[PFC raw counters] %s prio %d anomalies: %s | baseline=%s | trace: %s",
            intf, priority, '; '.join(anomalies), baseline, trace)
    else:
        logger.debug("[PFC raw counters] %s prio %d clean | baseline=%s | trace: %s",
                     intf, priority, baseline, trace)
    return anomalies


def send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku, priority,
                   pause_time, pkt_count):
    """
    @summary: Send `pkt_count` PFC pause frames targeting a single priority to
              one fanout port.
    @param peerdev_ans: Fanout host ansible handle
    @param peer_port_name: Linux interface name on the fanout switch
    @param fanout_hwsku: Fanout switch HwSku (used to detect MLNX-OS/Onyx)
    @param priority: PFC priority index (0-7). Pass the index, not a bitmap; it
                     is converted to a class-enable bitmap internally via 2 ** priority.
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
    hwsku = asic.sonichost.facts["hwsku"]
    only_lossless_rx_counters = (
        any(sku in hwsku for sku in only_lossless_rx_counters_hwskus)
        and not hwsku.startswith("Cisco-8122X")
    )
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

        expected_prios_by_intf = {}
        for intf in active_phy_intfs:
            if is_pfc and (not no_xon_counters or pause_time != 0):
                if only_lossless_rx_counters:
                    pfc_enabled_prios = [
                        int(prio) for prio in
                        config_facts["PORT_QOS_MAP"][intf]['pfc_enable'].split(',')
                    ]
                    expected_prios = [
                        str(PKT_COUNT if prio in pfc_enabled_prios else 0)
                        for prio in range(PRIO_COUNT)
                    ]
                else:
                    expected_prios = [str(PKT_COUNT)] * PRIO_COUNT
            else:
                # Expect 0 counters when "no_xon_counters and pause_time == 0", i.e. when
                # device does not support XON counters and the frame is XON.
                expected_prios = ['0'] * PRIO_COUNT
            expected_prios_by_intf[intf] = expected_prios

        """ SONiC updates counters asynchronously; poll until they settle """
        time.sleep(5)
        poll_deadline = time.monotonic() + PFC_COUNTER_POLL_TIMEOUT
        while True:
            counter_facts = duthost.sonic_pfc_counters(method="get")[
                'ansible_facts']
            failures = [
                (intf, counter_facts[intf]['Rx'], expected_prios)
                for intf, expected_prios in expected_prios_by_intf.items()
                if counter_facts[intf]['Rx'] != expected_prios
            ]
            if not failures or time.monotonic() >= poll_deadline:
                break
            time.sleep(PFC_COUNTER_POLL_INTERVAL)

        for intf, expected_prios in expected_prios_by_intf.items():
            logger.info("Verifying PFC RX count matches {}".format(expected_prios))
        if asic_type != 'vs':
            for intf, actual, expected in failures:
                logger.error("{}: got {}, expected {}".format(intf, actual, expected))
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

        # compute needed milliseconds for port stats capture
        port_poll_ms = duthost.get_counter_poll_status().get('PORT_STAT', {}).get('interval', 1000)
        settle_s = max(PFC_CLEAR_VERIFY_WINDOW, 1.5 * port_poll_ms / 1000.0)

        for intf in active_phy_intfs:
            """only check priority 3 and 4: lossless priorities"""
            for priority in range(3, 5):
                if asic_type != 'vs':
                    # Now resolve the peer device for the specified priority
                    peer_device = conn_facts[intf]['peerdevice']
                    peer_port = conn_facts[intf]['peerport']

                    if peer_device not in fanouthosts:
                        continue

                    peerdev_ans = fanouthosts[peer_device]
                    peer_port_name, fanout_hwsku = _resolve_peer_port_name(
                        peerdev_ans, enum_fanout_graph_facts, peer_port)

                    clear_pfc_counters_until_stable(duthost, intf, priority, settle_s)

                    counter_oid = get_port_counter_oid(asic, intf)
                    raw_baseline = (get_raw_pfc_rx_counters(asic, counter_oid)
                                    if counter_oid else None)
                    send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku,
                                   priority, pause_time, PKT_COUNT)
                    if raw_baseline:
                        check_raw_pfc_counter_sanity(asic, counter_oid, intf, priority,
                                                     raw_baseline, PKT_COUNT)

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
                            clear_pfc_counters_until_stable(duthost, intf, priority, settle_s)
                            raw_baseline = (get_raw_pfc_rx_counters(asic, counter_oid)
                                            if counter_oid else None)
                            send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku,
                                           priority, pause_time, PKT_COUNT)
                            if raw_baseline:
                                check_raw_pfc_counter_sanity(asic, counter_oid, intf, priority,
                                                             raw_baseline, PKT_COUNT)

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

              A single active physical interface is chosen at random and
              exercised: a baseline snapshot is taken, a burst of PFC frames is
              sent across all priorities to that port, then the port's counters
              are read back. The narrow measurement window keeps the
              RX_OK/RX_DRP deltas within `margin` instead of accumulating
              background traffic across a full port scan.
    @param duthost: The object for interacting with DUT through ansible
    @param conn_graph_facts: Testbed topology connectivity information
    @param leaf_fanouts: Leaf fanout switches
    @param pkt_count: Number of PFC frames to send per priority per port
    @param margin: Allowed RX_OK/RX_DRP increase per interface
    @param pause_time: Pause time quanta (0-65535) in the frame
    """
    asic_type = duthost.facts["asic_type"]
    if asic_type == 'vs':
        pytest.skip("PFC RX_OK isolation test is not applicable to the VS platform")

    setup_testbed(fanouthosts, duthost, leaf_fanouts)
    asic = duthost.asic_instance()

    conn_facts = conn_graph_facts['device_conn'].get(duthost.hostname, {})
    int_status = asic.show_interface(command="status")['ansible_facts']['int_status']
    """ We only test active physical interfaces that have connection graph entries
        and a reachable fanout """
    active_phy_intfs = [intf for intf in int_status if
                        intf.startswith('Ethernet') and
                        int_status[intf]['admin_state'] == 'up' and
                        int_status[intf]['oper_state'] == 'up' and
                        intf in conn_facts and
                        conn_facts[intf]['peerdevice'] in fanouthosts]

    """ Skip if nothing exercisable was found """
    if len(active_phy_intfs) == 0:
        pytest.skip(
            "No active physical interfaces with a reachable fanout were exercised, so "
            "PFC RX counter isolation could not be validated. Check the testbed "
            "topology and fanout connectivity."
        )

    """ Exercise a single randomly-chosen port so background traffic cannot
        accumulate across a full port scan """
    intf = random.choice(active_phy_intfs)
    peer_device = conn_facts[intf]['peerdevice']
    peer_port = conn_facts[intf]['peerport']
    peerdev_ans = fanouthosts[peer_device]
    peer_port_name, fanout_hwsku = _resolve_peer_port_name(
        peerdev_ans, enum_fanout_graph_facts, peer_port)
    logger.info(
        "Selected interface %s (peer %s port %s) out of %d candidate(s) for "
        "PFC RX_OK isolation test", intf, peer_device, peer_port, len(active_phy_intfs))

    """ Baseline for this port immediately before sending """
    baseline = get_rx_port_counters(duthost)

    for priority in range(PRIO_COUNT):
        send_pfc_frame(peerdev_ans, peer_port_name, fanout_hwsku,
                       priority, pause_time, pkt_count)

    """ SONiC takes some time to update counters in database """
    time.sleep(5)
    after = get_rx_port_counters(duthost)

    assert intf in baseline and intf in after, (
        "Interface {} missing from the {} counter snapshot; cannot validate "
        "its RX_OK/RX_DRP counters"
    ).format(intf, "baseline" if intf not in baseline else "post-send")

    rx_ok_delta = after[intf]['RX_OK'] - baseline[intf]['RX_OK']
    rx_drp_delta = after[intf]['RX_DRP'] - baseline[intf]['RX_DRP']
    if rx_ok_delta > margin or rx_drp_delta > margin:
        logger.error(
            "Interface %s: RX_OK increased by %d, RX_DRP increased by %d "
            "(allowed margin %d) after receiving %d PFC frames per priority",
            intf, rx_ok_delta, rx_drp_delta, margin, pkt_count)

    assert rx_ok_delta <= margin and rx_drp_delta <= margin, (
        "PFC frames were counted as RX_OK or RX_DRP beyond the allowed margin of {} "
        "on interface {} (rx_ok_delta={}, rx_drp_delta={})"
    ).format(margin, intf, rx_ok_delta, rx_drp_delta)
