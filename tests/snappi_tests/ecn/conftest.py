import pytest

from tests.snappi_tests.ecn.ecn_args.ecn_args import add_ecn_args
from tests.snappi_tests.ecn.files.ecn_counterpoll_helpers import (
    disable_wred_ecn_counterpoll_entries,
    enable_wred_ecn_counterpoll_for_snappi_ports,
)


@pytest.fixture(scope="module")
def enable_wred_ecn_counterpoll(get_snappi_ports):  # noqa: F811
    """
    Enable WRED ECN counterpoll for (duthost, ASIC) pairs used by snappi_ports.

    Counter types already enabled are left unchanged. Only counter types enabled
    by this fixture are disabled on teardown.
    """
    enabled_by_us = enable_wred_ecn_counterpoll_for_snappi_ports(get_snappi_ports)
    yield enabled_by_us
    disable_wred_ecn_counterpoll_entries(enabled_by_us)


def pytest_addoption(parser):
    '''
    Add option to ECN pytest
    Args:
        parser: pytest parser object
    Returns:
        None
    '''
    add_ecn_args(parser)
