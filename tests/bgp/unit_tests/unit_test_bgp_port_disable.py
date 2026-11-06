"""Regressions for exact TCP listener-port matching."""

from unittest.mock import Mock

import pytest

from tests.bgp.test_bgp_port_disable import verify_daemon_tcp_ports


@pytest.mark.parametrize("address", ["127.0.0.1", "::"])
@pytest.mark.parametrize("ports,error", [
    (["2620"], None),
    (["26200"], "port 2620 is not accessable"),
    (["12601", "26010", "2620"], None),
    (["2601", "2620"], "port 2601 is accessable"),
    ([], "port 2620 is not accessable"),
])
def test_exact_listener_ports(address, ports, error):
    """Reject missing/prohibited exact ports, not numeric lookalikes."""
    dut = Mock()
    dut.shell.return_value = {
        "stdout": "(only\nLocal\n" + "\n".join(f"{address}:{port}" for port in ports)
    }
    if error:
        with pytest.raises(pytest.fail.Exception, match=error):
            verify_daemon_tcp_ports(dut)
    else:
        verify_daemon_tcp_ports(dut)
