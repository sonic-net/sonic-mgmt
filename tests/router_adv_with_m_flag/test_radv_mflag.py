import ipaddress
import logging
import time

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_garp_service # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_mock import mock_server_base_ip_addr # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

RADV_MIN_RA_INTERVAL_SECS = 3
RADV_MAX_RA_INTERVAL_SECS = 4

"""
@summary: This fixture collects the data related to downlink VLAN port(s) and
the connected PTF port(s) required to setup the RADV tests

"""

@pytest.fixture(scope="module", autouse=True)
def radv_test_setup(request, duthosts, ptfhost, tbinfo):
    duthost = duthosts[0]
    logging.info("radv_test_setup() DUT {}".format(duthost.hostname))
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # RADVd is configured for each VLAN interface
    vlan_dict = mg_facts['minigraph_vlans']
    vlan_interfaces_list = []
    for vlan_iface_name, vlan_info_dict in vlan_dict.items():
        # Gather information about the downlink VLAN interface this relay agent is listening on
        downlink_vlan_iface = {}
        downlink_vlan_iface['name'] = vlan_iface_name

        # Obtain the link-local IPv6 address of the DUT's downlink VLAN interface
        downlink_vlan_iface['mac'] = duthost.get_dut_iface_mac(vlan_iface_name)
        cmd = "ip -6 -o addr show dev {} scope link | sed -e's/^.*inet6 \([^ ]*\)\/.*$/\\1/;t;d'".format(vlan_iface_name)
        res = duthost.shell(cmd)
        ip6 = ipaddress.IPv6Address(unicode(res['stdout']))
        pytest_assert(ip6.is_link_local,
                "ip6 address:{} of {} is not a link-local address".format(str(ip6), downlink_vlan_iface['name']))
        downlink_vlan_iface['ip6'] = str(ip6)

        # Obtain link-local IPv6 address of the connected PTF port (Eg eth0)
        # This PTF port maps to the first member of the TOR's VLAN
        ptf_port = {}
        ptf_port['port_idx'] = mg_facts['minigraph_ptf_indices'][vlan_info_dict['members'][0]]
        ptf_port['name'] = "eth" + str(ptf_port['port_idx'])
        cmd = "ip -6 -o addr show dev {} scope link | sed -e's/^.*inet6 \([^ ]*\)\/.*$/\\1/;t;d'".format(ptf_port['name'])
        res = ptfhost.shell(cmd)
        ip6 = ipaddress.IPv6Address(unicode(res['stdout']))
        pytest_assert(ip6.is_link_local,
                "ip6 address:{} of {} is not a link-local address".format(str(ip6), ptf_port['name']))
        ptf_port['ip6'] = str(ip6)

        vlan_intf_data = {}
        vlan_intf_data['downlink_vlan_intf'] = downlink_vlan_iface
        vlan_intf_data['ptf_port'] = ptf_port
        vlan_interfaces_list.append(vlan_intf_data)

    return vlan_interfaces_list

"""
@summary: Updates min/max RA interval in RADVd's config file

"""

"""
@summary: Test validates the RADVd's periodic router advertisement sent on each VLAN interface

"""
def test_unsolicited_router_advertisement(
                    request, tbinfo,
                    duthost, ptfhost,
                    radv_test_setup,
                    ):
    if 'dualtor' in tbinfo['topo']['name']:
        request.getfixturevalue('toggle_all_simulator_ports_to_upper_tor')

    for vlan_intf in radv_test_setup:
        # Run the RADV test on the PTF host
        logging.info("Verifying RA on VLAN intf:%s with TOR's mapped PTF port:eth%s",
                                                vlan_intf['downlink_vlan_intf']['name'],
                                                vlan_intf['ptf_port']['port_idx'])
        ptf_runner(ptfhost,
                   "ptftests",
                   "router_adv_mflag_test.RadvUnSolicitedRATest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "downlink_vlan_mac": vlan_intf['downlink_vlan_intf']['mac'],
                           "downlink_vlan_ip6": vlan_intf['downlink_vlan_intf']['ip6'],
                           "ptf_port_index": vlan_intf['ptf_port']['port_idx'],
                           "max_ra_interval": 180},
                   log_file="/tmp/router_adv_mflag_test.RadvUnSolicitedRATest.log")

"""
@summary: Test validates the RADVd's solicited router advertisement sent on each VLAN interface

"""

def test_solicited_router_advertisement(request, tbinfo, ptfhost, duthost, radv_test_setup):
    if 'dualtor' in tbinfo['topo']['name']:
        request.getfixturevalue('toggle_all_simulator_ports_to_upper_tor')

    for vlan_intf in radv_test_setup:
        # Run the RADV solicited RA test on the PTF host
        logging.info("Verifying solicited RA on VLAN intf:%s with TOR's mapped PTF port:eth%s",
                                                        vlan_intf['downlink_vlan_intf']['name'],
                                                        vlan_intf['ptf_port']['port_idx'])
        ptf_runner(ptfhost,
                   "ptftests",
                   "router_adv_mflag_test.RadvSolicitedRATest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "downlink_vlan_mac": vlan_intf['downlink_vlan_intf']['mac'],
                           "downlink_vlan_ip6": vlan_intf['downlink_vlan_intf']['ip6'],
                           "ptf_port_index": vlan_intf['ptf_port']['port_idx'],
                           "ptf_port_ip6": vlan_intf['ptf_port']['ip6'],
                           "max_ra_interval": RADV_MAX_RA_INTERVAL_SECS},
                   log_file="/tmp/router_adv_mflag_test.RadvSolicitedRATest.log")
