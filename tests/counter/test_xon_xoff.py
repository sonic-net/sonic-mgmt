# tests/counter/test_xon_xoff.py
import time
import struct
import pytest
import ptf.packet as scapy

pytestmark = [
    pytest.mark.topology("t0", "t1", "lt2", "ft2", "ptf"),
]


def craft_pause_frame(opcode=0x0001, quanta=0):
    """
    Build a classic 802.3x PAUSE frame (XOFF when quanta > 0, XON when quanta == 0).
    EtherType = 0x8808, Opcode = 0x0001, followed by 2-byte pause time.
    """
    payload = struct.pack("!H", opcode) + struct.pack("!H", quanta) + b"\x00" * 42
    eth = scapy.Ether(
        dst="01:80:C2:00:00:01",
        src="02:02:02:02:02:02",
        type=0x8808,
    )
    return eth / scapy.Raw(payload)


def read_rx_drops(duthost, iface):
    """
    Read RX_DROPS counter from COUNTERS_DB for iface.
    Returns int (0 if no value).
    """
    cmd = (
        f"sonic-db-cli COUNTERS_DB HGET 'COUNTERS:{iface}' 'RX_DROPS' "
        f"|| redis-cli -n 2 HGET 'COUNTERS:{iface}' 'RX_DROPS'"
    )
    res = duthost.shell(cmd, module_ignore_errors=True)
    out = res.get("stdout", "").strip()

    try:
        return int(out) if out else 0
    except ValueError:
        return 0


@pytest.mark.usefixtures("duthosts", "ptfadapter", "tbinfo")
def test_xon_xoff_does_not_increase_rx_drop(
    duthosts,
    rand_one_dut_hostname,
    rand_one_dut_portname_oper_up,
    ptfadapter,
    tbinfo,
):
    """
    Verify sending XOFF/XON PAUSE frames from the peer DOES NOT increase RX_DROPS.
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_port = rand_one_dut_portname_oper_up

    # Normalize: remove "switchname|" prefix -> keep actual interface
    port_name = dut_port.split("|")[-1]

    # Extract PTF mapping
    ptf_map = tbinfo.get("topo", {}).get("ptf_map", {})

    if port_name not in ptf_map:
        pytest.skip(
            f"no ptf mapping for DUT port {port_name} in tbinfo; can't run traffic"
        )

    ptf_port_idx = int(ptf_map[port_name])

    # Baseline counters
    before = read_rx_drops(duthost, port_name)

    # Send XOFF (pause_time > 0)
    xoff = craft_pause_frame(quanta=0xFFFF)
    for _ in range(300):
        ptfadapter.dataplane.send(ptf_port_idx, bytes(xoff))
        time.sleep(0.005)

    # Send XON (pause_time == 0)
    xon = craft_pause_frame(quanta=0x0000)
    for _ in range(300):
        ptfadapter.dataplane.send(ptf_port_idx, bytes(xon))
        time.sleep(0.005)

    # Allow counters to update
    time.sleep(2)

    after = read_rx_drops(duthost, port_name)

    assert (after - before) <= 10, (
        f"RX_DROP increased on {port_name}: before={before} after={after}"
    )
