import pytest

from tests.common.helpers.bmc_serial_console import (
    get_console_mux,
    open_bmc_shared_uart,
)
from tests.common.platform.device_utils import (  # noqa: F401
    platform_api_conn,
    start_platform_api_service,
)


def pytest_addoption(parser):
    parser.addoption(
        "--switch_host_restart",
        action="store",
        default="all",
        help="Host-restart scenario: all, random, or reboot,panic,watchdog,reboot-bmc,fast-reboot "
             "(comma-separated).",
    )


@pytest.fixture(scope="module")
def switch_host(duthost):
    """Paired SWITCH-HOST from testbed bmc_host. Asserts if missing."""
    return duthost.get_bmc_host()


@pytest.fixture(scope="module")
def console_mux(duthost):
    return get_console_mux(duthost)


@pytest.fixture(scope="module")
def bmc_shared_uart(duthost, conn_graph_facts, creds):
    """Physical lab-con → BMC UART. Skip if conn-graph has no console link."""
    uart = open_bmc_shared_uart(duthost, conn_graph_facts, creds)
    yield uart
    uart.close()
