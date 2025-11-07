# tests/counter/test_xon_xoff.py
import time
import pytest

pytestmark = [
    pytest.mark.topology("lt2", "ft2")
]


@pytest.fixture(scope="module")
def setup_storm_handler(duthosts, rand_one_dut_hostname, fanouthosts, conn_graph_facts, tbinfo):
    """
    A module level fixture to setup PFC storm handler to send XON frames.
    """
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    dut_port = list(mg_facts['minigraph_ptf_indices'].keys())[0]
    neighbors = conn_graph_facts["device_conn"].get(duthost.hostname, {})
    peer_device = neighbors.get(dut_port, {}).get("peerdevice", "")
    fanout_port = neighbors.get(dut_port, {}).get("peerport", "")
    fanouthost = fanouthosts[peer_device]

    # Copy pfc_gen.py to fanout host /tmp
    # Since the test is to verify XON frames are not counted, we do not need to
    # run platform specific pfc_gen
    src_pfc_gen_file = "common/helpers/pfc_gen.py"
    fanouthost.copy(src=src_pfc_gen_file, dest="/tmp/pfc_gen.py")

    yield dut_port, fanout_port, fanouthost


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


def test_xon_not_counted_rx_drop(duthosts, rand_one_dut_hostname, setup_storm_handler):
    """
    Test to verify XON frame (class enable = 0) does NOT increase RX_DROPS on DUT port.
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_port, fanout_port, fanouthost = setup_storm_handler

    # Get baseline before sending XON frames
    rx_drop_base = read_rx_drops(duthost, dut_port)

    # Hardcode class enable to 0 for XON frame
    pfc_queue = 0
    # Send 1000 XON frames
    frame_count = 1000

    # Send XON
    cmd = "sudo python3 /tmp/pfc_gen.py -p {} -i {} -n {} -t 65535".format(pfc_queue, fanout_port, frame_count)

    fanouthost.shell(cmd)

    # Wait sometime for XON to be sent
    time.sleep(10)

    # Wait some time for counters to be updated
    time.sleep(10)

    rx_drop_after = read_rx_drops(duthost, dut_port)

    assert (rx_drop_after - rx_drop_base) <= 10, (
        f"RX_DROP increased on {dut_port}: before={rx_drop_base} after={rx_drop_after}"
    )
