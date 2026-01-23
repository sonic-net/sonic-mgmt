# tests/counter/test_xon_xoff.py
import time
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import fanout_graph_facts  # noqa F401
from tests.common.platform.device_utils import eos_to_linux_intf, nxos_to_linux_intf, sonic_to_linux_intf

pytestmark = [
    pytest.mark.topology("lt2", "ft2")
]


@pytest.fixture(scope="module")
def setup_fanouthost(duthosts, rand_one_dut_hostname, fanouthosts, conn_graph_facts,
                     fanout_graph_facts, tbinfo):  # noqa F811
    """
    A module level fixture to setup fanout host to send XON frames.
    """
    duthost = duthosts[rand_one_dut_hostname]
    int_status = duthost.show_interface(command="status")['ansible_facts']['int_status']
    active_phy_intfs = [
        intf for intf in int_status
        if intf.startswith('Ethernet') and
        int_status[intf]['admin_state'] == 'up' and
        int_status[intf]['oper_state'] == 'up'
    ]
    neighbors = conn_graph_facts["device_conn"].get(duthost.hostname, {})

    dut_port = None
    fanout_port = None
    fanouthost = None
    for intf in active_phy_intfs:
        peer_device = neighbors.get(intf, {}).get("peerdevice", "")
        peer_port = neighbors.get(intf, {}).get("peerport", "")
        if peer_device in fanouthosts and peer_port:
            fanouthost = fanouthosts[peer_device]
            fanout_os = fanouthost.get_fanout_os()
            fanout_hwsku = fanout_graph_facts[fanouthost.hostname]["device_info"]["HwSku"]
            if fanout_os == "nxos":
                fanout_port = nxos_to_linux_intf(peer_port)
            elif fanout_os == "sonic":
                fanout_port = sonic_to_linux_intf(peer_port)
            else:
                fanout_port = eos_to_linux_intf(peer_port, hwsku=fanout_hwsku)
            dut_port = intf
            break

    pytest_assert(
        dut_port is not None and fanout_port is not None and fanouthost is not None,
        "No active DUT port with valid fanout connection found"
    )

    # Copy pfc_gen.py to fanout host /tmp
    # Since the test is to verify XON frames are not counted, we do not need to
    # run platform specific pfc_gen
    src_pfc_gen_file = "common/helpers/pfc_gen.py"
    fanouthost.copy(src=src_pfc_gen_file, dest="/tmp/pfc_gen.py")

    yield dut_port, fanout_port, fanouthost

    fanouthost.file(path="/tmp/pfc_gen.py", state="absent")


def read_rx_drops(duthost, port):
    """
    Read RX_DROPS counter from COUNTERS_DB for port.
    Returns int (0 if no value).
    """
    try:
        oid = duthost.shell("sonic-db-cli COUNTERS_DB hget COUNTERS_PORT_NAME_MAP {}".format(port))['stdout'].strip()  # noqa E501
        rx_drop = duthost.shell("sonic-db-cli COUNTERS_DB hget COUNTERS:{} SAI_PORT_STAT_IF_IN_DISCARDS".format(oid))['stdout'].strip()  # noqa E501
        return int(rx_drop)
    except Exception:
        return 0


def test_xon_xoff_not_counted_rx_drop(duthosts, rand_one_dut_hostname, setup_fanouthost):
    """
    Test to verify XON frame (class enable = 0) does NOT increase RX_DROPS on DUT port.
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_port, fanout_port, fanouthost = setup_fanouthost

    # Get baseline before sending XON frames
    rx_drop_base = read_rx_drops(duthost, dut_port)

    # Hardcode class enable to 0 for XON frame
    pfc_queue = 0
    # Send 1000 XON frames
    frame_count = 1000

    # Send XON
    cmd = "sudo python3 /tmp/pfc_gen.py -p {} -i {} -n {} -t 65535".format(pfc_queue, fanout_port, frame_count)
    fanouthost.shell(cmd)

    # Wait some time for counters to be updated
    time.sleep(10)

    rx_drop_after = read_rx_drops(duthost, dut_port)

    assert (rx_drop_after - rx_drop_base) <= 10, (
        f"RX_DROP increased on {dut_port}: before={rx_drop_base} after={rx_drop_after}"
    )

    rx_drop_base = rx_drop_after

    # Send XOFF in queue 3 and 4
    cmd = "sudo python3 /tmp/pfc_gen.py -p 24 -i {} -n {} -t 65535".format(fanout_port, frame_count)
    fanouthost.shell(cmd)

    # Wait some time for counters to be updated
    time.sleep(10)

    rx_drop_after = read_rx_drops(duthost, dut_port)

    assert (rx_drop_after - rx_drop_base) <= 10, (
        f"RX_DROP increased on {dut_port}: before={rx_drop_base} after={rx_drop_after}"
    )
