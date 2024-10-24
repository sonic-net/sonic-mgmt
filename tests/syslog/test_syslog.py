import logging
import pytest
from tests.common.helpers.syslog_helpers import run_syslog, check_default_route   # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]


@pytest.mark.parametrize("dummy_syslog_server_ip_a, dummy_syslog_server_ip_b",
                         [("7.0.80.166", None),
                          ("fd82:b34f:cc99::100", None),
                          ("7.0.80.165", "7.0.80.166"),
                          ("fd82:b34f:cc99::100", "7.0.80.166"),
                          ("fd82:b34f:cc99::100", "fd82:b34f:cc99::200")])
def test_syslog(rand_selected_dut, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b,
                check_default_route      # noqa: F811
                ):
    run_syslog(rand_selected_dut, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, check_default_route)
