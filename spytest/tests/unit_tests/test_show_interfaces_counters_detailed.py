"""
Parser tests for spytest/templates/show_interfaces_counters_detailed.tmpl.

sonic-utilities prints SAI_PORT_STAT_IP_IN_RECEIVES as "Overruns Received" in
older releases and as "IP Packets Received" after sonic-net/sonic-utilities#4665.
Both labels must keep filling pkt_rx_overruns.

Run without a DUT:
    python3 -m pytest --noconftest spytest/tests/unit_tests/test_show_interfaces_counters_detailed.py -v
"""
import os

import pytest

try:
    import clitable
except ImportError:
    from textfsm import clitable

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "templates"))
COMMAND = "show interfaces counters detailed Ethernet0"

DETAILED_OUTPUT = """\
Packets Received 64 Octets..................... 1
Packets Received 65-127 Octets................. 2
Packets Received 128-255 Octets................ 3
Packets Received 256-511 Octets................ 4
Packets Received 512-1023 Octets............... 5
Packets Received 1024-1518 Octets.............. 6
Packets Received 1519-2047 Octets.............. 7
Packets Received 2048-4095 Octets.............. 8
Packets Received 4096-9216 Octets.............. 9
Packets Received 9217-16383 Octets............. 10

Total Packets Received Without Errors.......... 11
Unicast Packets Received....................... 12
Multicast Packets Received..................... 13
Broadcast Packets Received..................... 14

Jabbers Received............................... 15
Fragments Received............................. 16
Undersize Received............................. 17
{rx_ip_line}

Packets Transmitted 64 Octets.................. 19
Packets Transmitted 65-127 Octets.............. 20
Packets Transmitted 128-255 Octets............. 21
Packets Transmitted 256-511 Octets............. 22
Packets Transmitted 512-1023 Octets............ 23
Packets Transmitted 1024-1518 Octets........... 24
Packets Transmitted 1519-2047 Octets........... 25
Packets Transmitted 2048-4095 Octets........... 26
Packets Transmitted 4096-9216 Octets........... 27
Packets Transmitted 9217-16383 Octets.......... 28

Total Packets Transmitted Successfully......... 29
Unicast Packets Transmitted.................... 30
Multicast Packets Transmitted.................. 31
Broadcast Packets Transmitted.................. 32

WRED Green Dropped Packets..................... 33
WRED Yellow Dropped Packets.................... 34
WRED Red Dropped Packets....................... 35
WRED Total Dropped Packets..................... 36
"""

OLD_RX_IP_LINE = "Overruns Received.............................. 18"
NEW_RX_IP_LINE = "IP Packets Received............................ 18"


def parse(output, cmd=COMMAND):
    # Same index lookup and row conversion as spytest.template.Template.apply()
    cli_table = clitable.CliTable("index", TEMPLATES_DIR)
    attrs = {"Command": cmd}
    row_idx = cli_table.index.GetRowMatch(attrs)
    tmpl = cli_table.index.index[row_idx]["Template"]
    cli_table.ParseCmd(output, attrs)
    header = [name.lower() for name in cli_table.header]
    return tmpl, [dict(zip(header, row)) for row in cli_table]


@pytest.mark.parametrize("rx_ip_line", [OLD_RX_IP_LINE, NEW_RX_IP_LINE], ids=["overruns_label", "ip_packets_label"])
def test_rx_ip_receives_label_parsed_into_pkt_rx_overruns(rx_ip_line):
    tmpl, rows = parse(DETAILED_OUTPUT.format(rx_ip_line=rx_ip_line))

    assert tmpl == "show_interfaces_counters_detailed.tmpl"
    assert len(rows) == 1
    row = rows[0]
    assert row["pkt_rx_overruns"] == "18"
    assert row["pkt_rx_undersize"] == "17"
    assert row["pkt_tx_64_octets"] == "19"
    assert row["pkt_tx_broadcast"] == "32"


def test_old_and_new_labels_produce_identical_rows():
    _, old_rows = parse(DETAILED_OUTPUT.format(rx_ip_line=OLD_RX_IP_LINE))
    _, new_rows = parse(DETAILED_OUTPUT.format(rx_ip_line=NEW_RX_IP_LINE))

    assert new_rows == old_rows
