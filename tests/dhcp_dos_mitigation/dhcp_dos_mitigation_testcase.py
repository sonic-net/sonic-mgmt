import pytest
import logging
import time


pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


@pytest.mark.topology('any')
class TestDhcpRateLimit:
    def setup_method(self, method):
        """Setup the test environment before each test."""
        self.port = 'Ethernet0'  # Example port, change as needed
        self.packet_rate = 1  # Example packet rate, change as needed
        self.byte_rate = self.packet_rate * 342  # Approximate byte rate

    def teardown_method(self, method):
        """Clean up configurations after each test."""
        self.remove_dhcp_rate_limit(self.port)

    def config_dhcp_rate_limit(self, duthost, port, packet_rate):
        """Configure DHCP rate limit on the specified port."""
        duthost.shell(f'config interface dhcp-mitigation-rate add {port} {packet_rate}')

    def remove_dhcp_rate_limit(self, duthost, port):
        """Remove DHCP rate limit on the specified port."""
        duthost.shell(f'config interface dhcp-mitigation-rate delete {port} {self.packet_rate}')

    def verify_dhcp_rate_limit_set(self, duthost, port):
        """Verify that the DHCP rate limit is set on the specified port."""
        result = duthost.shell(f'show interface dhcp-mitigation-rate | grep {port}')
        assert f'{port} {self.packet_rate}' in result['stdout'], "DHCP rate limit not set correctly"

    def simulate_excessive_dhcp_traffic(self, ptfhost, port, packet_rate):
        """Simulate excessive DHCP traffic on the specified port."""
        ptfhost.shell(f'python3 -c "import scapy.all as scapy;\
                    scapy.sendp(scapy.Ether()/scapy.IP()/scapy.UDP(dport=67),\
                    iface=\'{port}\', count={packet_rate*2}, inter=0.001)"')

    def verify_dhcp_packets_dropped(self, duthost, port):
        """Verify that DHCP packets are being dropped as per the rate limit."""
        result = duthost.shell(f'sudo tc -s qdisc show dev {port} handle ffff:')
        dropped_packets = int(result['stdout'].split('drop ')[1].split()[0])
        assert dropped_packets > 0, "DHCP packets are not being dropped as expected"

    def test_dhcp_rate_limit(self, duthost, ptfhost):
        """Test DHCP rate limiting on an interface."""
        self.config_dhcp_rate_limit(duthost, self.port, self.packet_rate)
        self.verify_dhcp_rate_limit_set(duthost, self.port)

        self.simulate_excessive_dhcp_traffic(ptfhost, self.port, self.packet_rate)
        time.sleep(5)  # Wait for traffic to be processed

        self.verify_dhcp_packets_dropped(duthost, self.port)

        # Clean up
        self.teardown_method(self.test_dhcp_rate_limit)
