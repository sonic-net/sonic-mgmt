import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo', 'bmc')
]


def test_console_driver(duthost, conn_graph_facts):  # noqa: F811
    """
    Verify that the console driver on the DUT exposes a tty device node for
    every serial line wired to the DUT.

    For each line recorded for this DUT in ``ansible/files/*_serial_links.csv``
    (exposed via the ``conn_graph_facts`` fixture), assert that a tty device
    with a matching line-number suffix exists on the DUT, and that no extra
    tty devices with the same prefix are present.
    """
    dut_serial_links = conn_graph_facts.get('device_serial_link', {}).get(duthost.hostname, {})
    pytest_assert(
        dut_serial_links,
        "No serial links found for DUT '{}' in *_serial_links.csv".format(duthost.hostname),
    )

    device_prefix = duthost.get_serial_device_prefix()
    ls_out = duthost.shell('ls {}*'.format(device_prefix), module_ignore_errors=True)['stdout']
    existing_ttys = set(ls_out.split())
    pytest_assert(
        existing_ttys,
        "No tty devices matching prefix '{}' were created by the console driver on DUT '{}'".format(
            device_prefix, duthost.hostname),
    )

    expected_ttys = {"{}{}".format(device_prefix, line_number) for line_number in dut_serial_links.keys()}
    missing_ttys = sorted(expected_ttys - existing_ttys)
    extra_ttys = sorted(existing_ttys - expected_ttys)
    pytest_assert(
        not missing_ttys and not extra_ttys,
        "tty device set does not match the serial-link inventory: missing={}, extra={}".format(
            missing_ttys, extra_ttys),
    )
