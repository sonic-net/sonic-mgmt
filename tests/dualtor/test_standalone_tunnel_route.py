import json
import ipaddress
import pytest
import random
import time
import logging
import scapy.all as scapyall

from ptf import testutils

from tests.common.dualtor.dual_tor_common import active_active_ports                                # noqa F401
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import upper_tor_host                                      # noqa F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                      # noqa F401
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor      # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type                                         # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor                        # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import is_ipv4_address
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.fixture(autouse=True)
def cleanup_neighbors(duthosts):
    """Cleanup neighbors."""
    duthosts.shell("sonic-clear arp")
    duthosts.shell("sonic-clear ndp")
    return


@pytest.fixture
def constants(lower_tor_host, tbinfo):
    class _C(object):
        """Dummy class to save test constants."""

    def _find_ipv4_vlan(mg_facts):
        for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
            if is_ipv4_address(vlan_intf["addr"]):
                return vlan_intf

    def _find_ipv6_vlan(mg_facts):
        for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
            if not is_ipv4_address(vlan_intf["addr"]):
                return vlan_intf

    lower_tor_mg_facts = lower_tor_host.get_extended_minigraph_facts(tbinfo)
    lower_tor_vlan = _find_ipv4_vlan(lower_tor_mg_facts)
    lower_tor_vlan_ipv6 = _find_ipv6_vlan(lower_tor_mg_facts)
    vlan_subnet = ipaddress.ip_network(lower_tor_vlan["subnet"])
    vlan_subnet_v6 = ipaddress.ip_network(lower_tor_vlan_ipv6["subnet"])
    selected_target_ip = vlan_subnet.network_address + 500
    selected_target_ipv6 = vlan_subnet_v6.network_address + 500
    pytest_assert(selected_target_ip in vlan_subnet)
    pytest_assert(selected_target_ipv6 in vlan_subnet_v6)

    _constants = _C()
    _constants.target_ip = selected_target_ip
    _constants.target_ipv6 = selected_target_ipv6
    return _constants


def test_standalone_tunnel_route(
    cable_type, constants, upper_tor_host, lower_tor_host,
    ptfadapter, toggle_all_simulator_ports_to_upper_tor, tbinfo,    # noqa F811
    tunnel_traffic_monitor
):
    def _verify_traffic(duthost, target_ip):
        pkt, _ = build_packet_to_server(duthost, ptfadapter, str(target_ip))
        ptf_t1_intf = random.choice(get_t1_ptf_ports(duthost, tbinfo))
        ptf_t1_intf_index = int(ptf_t1_intf.strip("eth"))

        if target_ip.version == 4:
            tunnel_innner_pkt = pkt[scapyall.IP].copy()
            tunnel_innner_pkt[scapyall.IP].ttl -= 1
        else:
            tunnel_innner_pkt = pkt[scapyall.IPv6].copy()
            tunnel_innner_pkt[scapyall.IPv6].hlim -= 1
        tunnel_monitor = tunnel_traffic_monitor(
            duthost,
            existing=True,
            inner_packet=tunnel_innner_pkt,
            check_items=["ttl", "queue"]
        )
        with tunnel_monitor:
            # Those downstream packets are trapped to kernel to learn
            # the neighbors, and SONiC needs time to process the zero
            # mac and program the tunnel, so there could be packet loss.
            # Let's send twice, first round to setup the tunnel.
            testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)
            time.sleep(5)
            testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)
            time.sleep(5)

    def _verify_failed_neighbor(duthost, target_ip):
        result = duthost.shell("ip neighbor show %s" % target_ip)["stdout"]
        pytest_assert("FAILED" in result)

    def _check_mux_status(duthost, target_status):
        all_mux_status = json.loads(duthost.shell("show mux status --json")["stdout"])["MUX_CABLE"]
        mux_status = {port: status for port, status in list(all_mux_status.items()) if port in active_active_ports}
        for port in mux_status:
            status = mux_status[port]["STATUS"].lower()
            if status != target_status:
                return False
        return True

    logging.info("check upper tor %s", upper_tor_host)
    _verify_traffic(upper_tor_host, constants.target_ip)
    _verify_traffic(upper_tor_host, constants.target_ipv6)
    _verify_failed_neighbor(upper_tor_host, constants.target_ip)
    _verify_failed_neighbor(upper_tor_host, constants.target_ipv6)

    logging.info("check lower tor %s", upper_tor_host)
    _verify_traffic(lower_tor_host, constants.target_ip)
    _verify_traffic(lower_tor_host, constants.target_ipv6)
    _verify_failed_neighbor(lower_tor_host, constants.target_ip)
    _verify_failed_neighbor(lower_tor_host, constants.target_ipv6)

    if cable_type == CableType.active_active:
        try:
            logging.info("toggle lower tor %s to standby", lower_tor_host)
            lower_tor_host.shell("config mux mode standby all")
            wait_until(30, 5, 0, lambda: _check_mux_status(lower_tor_host, "standby"))
            _verify_traffic(lower_tor_host, constants.target_ip)
            _verify_failed_neighbor(lower_tor_host, constants.target_ip)
            _verify_failed_neighbor(lower_tor_host, constants.target_ip)
            _verify_failed_neighbor(lower_tor_host, constants.target_ipv6)
        finally:
            lower_tor_host.shell("config mux mode auto all")
