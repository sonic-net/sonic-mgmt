import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo')
]


def test_console_driver(duthost, tbinfo):
    """
    Test console driver are well installed.
    Verify ttyUSB(0-47) are presented in DUT
    Both c0 and c0-lo have 48 console lines
    """
    topo_console_intfs = tbinfo["topo"]["properties"]["topology"]["console_interfaces"]

    ls_out = duthost.shell('ls /dev/ttyUSB*', module_ignore_errors=True)['stdout']
    num_ttys = len(ls_out.split())
    pytest_assert(num_ttys > 0, "No virtual tty devices been created by console driver")
    pytest_assert(num_ttys >= len(topo_console_intfs),
                  "Number of virtual tty devices [{}] is less than expected [{}]"
                  .format(num_ttys, len(topo_console_intfs)))

    dut_console_config = duthost.console_facts()["ansible_facts"]["console_facts"]["lines"]
    for topo_console_intf in topo_console_intfs:
        line_number, baud_rate, flow_control = topo_console_intf.split(".")
        dut_line_config = dut_console_config[line_number]
        pytest_assert(dut_line_config["baud_rate"] == int(baud_rate),
                      "Baud rate mismatch for line {}: expected {}, got {}".format(line_number, baud_rate,
                                                                                   dut_line_config["baud_rate"]))
        pytest_assert(dut_line_config["flow_control"] == bool(int(flow_control)),
                      "Flow control mismatch for line {}: expected {}, got {}".format(line_number,
                                                                                      bool(int(flow_control)),
                                                                                      dut_line_config["flow_control"]))
