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
        dst="01:80:C2:00:00:01", src="02:02:02:02:02:02", type=0x8808
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
    Verify that sending XOFF/XON (802.3x PAUSE) frames from peer does NOT
    increase RX_DROPS on DUT port.

    Steps:
      - Pick a random operational front-panel port (fixture)
      - Map it to the PTF port index via tbinfo["topo"]["ptf_map"]
      - Send XOFF then XON frames
      - Assert RX_DROPS delta == 0
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_port = rand_one_dut_portname_oper_up

    # Map DUT port to PTF index (topology must provide ptf_map)
    ptf_map = tbinfo.get("topo", {}).get("ptf_map", {})
    if dut_port not in ptf_map:
        pytest.skip(
            f"no ptf mapping for DUT port {dut_port} in tbinfo; can't run traffic"
        )

    ptf_port_idx = int(ptf_map[dut_port])

    # Baseline
    before = read_rx_drops(duthost, dut_port)

    # Send XOFF (pause_time > 0)
    xoff = craft_pause_frame(quanta=0xFFFF)

    xoff_frames = 300

    for _ in range(xoff_frames):
        ptfadapter.dataplane.send(ptf_port_idx, bytes(xoff))
        time.sleep(0.005)

    # Send XON (pause_time == 0)

    xon = craft_pause_frame(quanta=0x0000)

    xon_frames = 100

    for _ in range(xon_frames):
        ptfadapter.dataplane.send(ptf_port_idx, bytes(xon))
        time.sleep(0.005)

    # Allow counters to settle
    time.sleep(2)

    after = read_rx_drops(duthost, dut_port)

    assert (after - before) <= 0, (
        f"RX_DROP increased on {dut_port}: before={before} after={after}"
    )
