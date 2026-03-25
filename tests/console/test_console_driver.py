import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo')
]


def test_console_driver(duthost, tbinfo, setup_c0):
    """
    Test console driver are well installed.
    Verify ttyUSB(0-47) are presented in DUT
    Both c0 and c0-lo have 48 console lines
    """
    topo_console_intfs = tbinfo["topo"]["properties"]["topology"]["console_interfaces"]

    ls_out = duthost.shell('ls {}*'.format(duthost._get_serial_device_prefix()), module_ignore_errors=True)['stdout']
    num_ttys = len(ls_out.split())
    pytest_assert(num_ttys > 0, "No virtual tty devices been created by console driver")
    pytest_assert(num_ttys >= len(topo_console_intfs),
                  "Number of virtual tty devices [{}] is less than expected [{}]"
                  .format(num_ttys, len(topo_console_intfs)))
