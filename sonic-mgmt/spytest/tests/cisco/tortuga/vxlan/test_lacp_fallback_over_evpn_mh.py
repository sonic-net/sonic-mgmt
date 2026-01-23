import os
import tortuga_common_utils as common_obj
import yaml
import pytest
from collections import OrderedDict
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as portchannel_obj
import vxlan_utils as vxlan_obj
import time
import evpn_mh_utils as evpn_mh_obj
import utilities.utils as utils_obj
import apis.system.reboot as reboot_obj

# Global data object for test configuration
data = SpyTestDict()
data.config_vrfs = []

# Configuration file and VXLAN IPs
CONFIGS_FILE = 'lacp_fallback_evpn_mh_config.yaml'
LEAF0_VXLAN_IP = 'fd27::233:d0c6:fefb'
LEAF1_VXLAN_IP = 'fd27::2dc:c1c9:e17c'
LEAF2_VXLAN_IP = 'fd27::2d9:76fd:4c43'

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D3
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['leaf2'] = vars.D5

    domain = ''
    if config_domain == 'bgp' or config_domain == 'pre-sonic-bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            common_obj.config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            common_obj.config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log("FAILED: {}".format(msg))
    st.report_fail('test_case_failed', dut)

def is_mac_exists_with_intf(nodes, src_vtep, mac, intf):
    output = st.show(nodes[src_vtep], 'show mac -a {}'.format(mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'show mac', output, 'show_mac.tmpl')
    st.log(parsed)
    if len(parsed) == 1:    #parsed would contain minimum of 1 entry because of total entries field in show mac o/p
        return False

    if parsed[0]["port"] != intf:
        return False
    return True

@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks():
    """Set up EVPN + BGP infrastructure from yaml configuration"""
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D3
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['leaf2'] = vars.D5

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    evpn_mh_obj.change_fdb_ageout("6000")

    # Apply EVPN + BGP configurations from yaml file
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'pre-sonic-bgp')
            st.wait(2)
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    yield vxlan_config_hooks

    # Cleanup EVPN + BGP configurations
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
            st.wait(2)
            config_static(node, 'pre-sonic-bgp', add=False)
        evpn_mh_obj.change_fdb_ageout("600")

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    """Initialize test data"""
    # Set client IP address for the tests
    data.client_eth1_ip = "10.212.10.6"
    yield

@pytest.fixture(scope="function")
def portchannel_fallback_ping_base_config():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['client'] = vars.D9
    portchannel_name = "PortChannel1"

    # Create portchannel on leaf0(fallback enabled) and leaf1
    portchannel_obj.create_portchannel(nodes['leaf0'], [portchannel_name], fallback=True)
    st.config(nodes['leaf0'], "sudo config portchannel member add {} {}".format(portchannel_name, vars.D1D9P1))
    st.config(nodes['leaf0'], "sudo config vlan member add 10 {} -u".format(portchannel_name))

    portchannel_obj.create_portchannel(nodes['leaf1'], [portchannel_name])
    st.config(nodes['leaf1'], "sudo config portchannel member add {} {}".format(portchannel_name, vars.D2D9P1))
    st.config(nodes['leaf1'], "sudo config vlan member add 10 {} -u".format(portchannel_name))

    #Configure ip address on eth1 connected to leaf0
    st.config(nodes['client'], "sudo ip link set eth1 up", type="click", skip_error_check=True)
    st.config(nodes['client'], "sudo ip addr add {}/24 dev eth1".format(data.client_eth1_ip), type="click", skip_error_check=True)

    yield
    st.config(nodes['leaf0'], "sudo config vlan member del 10 {}".format(portchannel_name))
    st.config(nodes['leaf0'], "sudo config portchannel member del {} {}".format(portchannel_name, vars.D1D9P1))
    st.config(nodes['leaf0'], "sudo config portchannel del {}".format(portchannel_name))
    st.config(nodes['leaf1'], "sudo config vlan member del 10 {}".format(portchannel_name))
    st.config(nodes['leaf1'], "sudo config portchannel member del {} {}".format(portchannel_name, vars.D2D9P1))
    st.config(nodes['leaf1'], "sudo config portchannel del {}".format(portchannel_name))
    st.config(nodes['client'], "sudo ip addr del 10.212.10.6/24 dev eth1", type="click", skip_error_check=True)

@pytest.fixture(scope="function")
def dhcp_server_base_config():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['leaf2'] = vars.D5
    nodes['leaf3'] = vars.D6
    portchannel_name = "PortChannel1"

    # Configure Vlan 10 on leaf3 and add the ports connected to 'client' node to portchannel
    portchannel_obj.create_portchannel(nodes['leaf0'], [portchannel_name], fallback=True)
    st.config(nodes['leaf0'], "sudo config portchannel member add {} {}".format(portchannel_name, vars.D1D9P1))
    st.config(nodes['leaf0'], "sudo config vlan member add 10 {} -u".format(portchannel_name))
    portchannel_obj.create_portchannel(nodes['leaf1'], [portchannel_name])
    st.config(nodes['leaf1'], "sudo config portchannel member add {} {}".format(portchannel_name, vars.D2D9P1))
    st.config(nodes['leaf1'], "sudo config vlan member add 10 {} -u".format(portchannel_name))
    st.config(nodes['leaf2'], 'sudo config vlan member add 10 {} -u'.format(vars.D5D6P1))
    st.config(nodes['leaf3'], 'sudo config vlan add 10')
    st.config(nodes['leaf3'], 'sudo config vlan member add 10 {} -u'.format(vars.D6D5P1))
    st.config(nodes['leaf3'], 'sudo config interface ip add Vlan10 10.212.10.30/24')
    yield

    st.config(nodes['leaf0'], "sudo config vlan member del 10 {}".format(portchannel_name))
    st.config(nodes['leaf0'], "sudo config portchannel member del {} {}".format(portchannel_name, vars.D1D9P1))
    st.config(nodes['leaf0'], "sudo config portchannel del {}".format(portchannel_name))
    st.config(nodes['leaf1'], "sudo config vlan member del 10 {}".format(portchannel_name))
    st.config(nodes['leaf1'], "sudo config portchannel member del {} {}".format(portchannel_name, vars.D2D9P1))
    st.config(nodes['leaf1'], "sudo config portchannel del {}".format(portchannel_name))
    st.config(nodes['leaf2'], 'sudo config vlan member del 10 {}'.format(vars.D5D6P1))
    st.config(nodes['leaf3'], 'sudo systemctl stop isc-dhcp-server')
    st.config(nodes['leaf3'], 'sudo config interface ip rem Vlan10 10.212.10.30/24')
    st.config(nodes['leaf3'], 'sudo config vlan member del 10 {}'.format(vars.D6D5P1))
    st.config(nodes['leaf3'], 'sudo config vlan del 10')
    st.config(nodes['leaf3'], 'sudo apt purge isc-dhcp-server -y')
    st.config(nodes['leaf3'], 'sudo apt purge policykit-1 -y')
    st.config(nodes['leaf3'], 'sudo rm -f /tmp/dhcp_server_conf.txt /tmp/dhcpd_conf.txt /tmp/dhcp_install.sh')


##########################################################################################################
#                                        +--------------------+                                          #
#                                        |       spine0       |                                          #
#                                    P1  |        SD3         | P5                                       #
#                            +-----------|                    |----------------------+                   #
#                            |       P2  +--------------------+ P6                   |                   #
#                            |                P3 |    | P4                           |                   #
#                            |                   |    |                              |                   #
#                         P1 | P2             P1 |    | P2                        P1 | P2                #
#                +-----------+------+     +------+----+-----------+             +----+-------------+     #
#                |    leaf0 SD1     |     |     leaf1  SD2        |             |    leaf2  SD5    |     #
#                +-----+----+-------+     +---------------+---+---+             +--+---------------+     #
#                      |    | P7                       P7 |   |              P5-P8 |         |           #
#                      |    |                             |   |                    |         |           #
#                      |    |                             |   |              P5-P8 |         |           #
#                      |    |      +----------------+     |   |         +--------------+     |           #
#                      |    +------| PXE_client(SD9)|-----+   |         |   Leaf3(SD6) |     |           #
#                      |      eth1 +----------------+ eth2    |         | DHCP Server  |     |           #
#                      |                                      |         +--------------+     |           #
#                      |                                      |                              |           #
#                      |                                      |                              |           #
#                      |                   +-----------------------------+                   |           #
#                      |                   |         IXIA                |                   |           #
#                      +-------------------|                             |-------------------+           #
#                                          | Ports 1/1 to 1/10 connected |                               #
#                                          +-----------------------------+                               #
#                                                                                                        #
# NOTE: These tests require the underlying EVPN + BGP infrastructure to be configured via the yaml       #
# configuration file. The vxlan_config_hooks fixture sets up this infrastructure.                        #
##########################################################################################################
def test_portchannel_fallback_ping(portchannel_fallback_ping_base_config):
    '''
    Verify ping from 'client' node to ixia hosts connected to other vteps
    when fallback is enabled on portchannel on 'leaf0' node connected to 'client' node.
    '''
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['client'] = vars.D9

    client_eth1_mac = None
    portchannel_name = "PortChannel1"

    try:
        # Verify IP assignment
        ip_output = st.config(nodes['client'], "ip addr show eth1", type="click", skip_error_check=True)
        st.log("Client eth1 IP configuration: {}".format(ip_output))
        if data.client_eth1_ip not in str(ip_output):
            st.log("Failed to assign IP {} to eth1".format(data.client_eth1_ip))
            report_fail("ip_assignment_failed", "Failed to assign IP {} to client eth1".format(data.client_eth1_ip))

        # Verify Portchannel state is up on 'leaf0' and 'down' on leaf1
        if not portchannel_obj.verify_portchannel_member_state(nodes['leaf0'], portchannel_name, vars.D1D9P1, "up"):
            st.report_fail("Portchannel state verification failed on nodes['leaf0']")
        if not portchannel_obj.verify_portchannel_member_state(nodes['leaf1'], portchannel_name, vars.D2D9P1, "down"):
            st.report_fail("Portchannel state verification failed on nodes['leaf1']")

        # Get MAC address of eth1 interface
        mac_output = st.config(nodes['client'], "cat /sys/class/net/eth1/address", type="click", skip_error_check=True)
        client_eth1_mac = mac_output.strip() if mac_output else None
        st.log("Client eth1 MAC address: {}".format(client_eth1_mac))

        # Perform ping tests to ixia hosts connected to leaf1 and leaf2
        # Host 10.212.10.5 is behind leaf1 and 10.212.10.3 is behind leaf2
        st.log("Pinging to 10.212.10.3")
        ping_result_1 = st.config(nodes['client'], "ping -c 3 10.212.10.3", type="click", skip_error_check=True)
        # Check if ping was successful
        if "3 received" in str(ping_result_1) or "0% packet loss" in str(ping_result_1):
            st.log("SUCCESS: Ping to 10.212.10.3 successful")
            ping_1_success = True
        else:
            st.log("FAILED: Ping to 10.212.10.3 failed")
            ping_1_success = False

        st.log("Pinging to 10.212.10.5")
        ping_result_2 = st.config(nodes['client'], "ping -c 3 10.212.10.5", type="click", skip_error_check=True)
        # Check if ping was successful
        if "3 received" in str(ping_result_2) or "0% packet loss" in str(ping_result_2):
            st.log("SUCCESS: Ping to 10.212.10.5 successful")
            ping_2_success = True
        else:
            st.log("FAILED: Ping to 10.212.10.5 failed")
            ping_2_success = False

        st.log("Verify MAC learning on leaf0 against portchannel interface")
        if (is_mac_exists_with_intf(nodes, "leaf0", client_eth1_mac, portchannel_name)):
            mac_learned = True
        else:
            mac_learned = False
            st.log("Failure: Host mac not learnt")

        st.log("Ping to 10.212.10.3: {}".format("SUCCESS" if ping_1_success else "FAILED"))
        st.log("Ping to 10.212.10.5: {}".format("SUCCESS" if ping_2_success else "FAILED"))
        st.log("MAC Learning on leaf0: {}".format("SUCCESS" if mac_learned else "FAILED"))

        # Final validation
        if ping_1_success and ping_2_success:
            st.report_pass('test_case_passed', 'LACP fallback ping between hosts and mac learning was successful')
        else:
            report_fail("test_case_failed", "LACP fallback ping between hosts and mac learning failed")

    except Exception as e:
        st.log("LACP fallback ping test failed with exception: {}".format(e))
        report_fail("", msg=str(e))


def test_portchannel_fallback_pxe_client(dhcp_server_base_config):
    """
    DHCP server is created on node SD9 connected to SD5(leaf2)
    'client' node acts as the PXE_client sending BOOTP/DHCP packet
    """
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D3
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['leaf2'] = vars.D5
    nodes['leaf3'] = vars.D6
    nodes['client'] = vars.D9
    portchannel_name = "PortChannel1"

    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        dhcp_server_install_file = os.path.join(current_dir, 'dhcp_server_install.sh')
        dhcp_server_conf_file = os.path.join(current_dir, 'dhcp_server_conf.txt')
        dhcpd_conf_file = os.path.join(current_dir, 'dhcpd_conf.txt')
        dhcp_trap_rule_clear_file = os.path.join(current_dir, 'dhcp_trap_rule_clear.py')

        utils_obj.copy_files_to_dut(nodes['leaf3'], [dhcp_server_install_file], '/tmp/')
        utils_obj.copy_files_to_dut(nodes['leaf3'], [dhcp_server_conf_file], '/tmp/')
        utils_obj.copy_files_to_dut(nodes['leaf3'], [dhcpd_conf_file], '/tmp/')
        utils_obj.copy_files_to_dut(nodes['leaf0'], [dhcp_trap_rule_clear_file], '/tmp/')
        utils_obj.copy_files_to_dut(nodes['leaf2'], [dhcp_trap_rule_clear_file], '/tmp/')

        st.config(nodes['leaf0'], 'python3 /tmp/dhcp_trap_rule_clear.py')
        st.config(nodes['leaf2'], 'python3 /tmp/dhcp_trap_rule_clear.py')
        st.config(nodes['leaf3'], 'chmod +x /tmp/dhcp_server_install.sh')
        output = st.config(nodes['leaf3'], 'bash /tmp/dhcp_server_install.sh')

        st.config(nodes['leaf3'], 'sudo cp /tmp/dhcp_server_conf.txt /etc/default/isc-dhcp-server')
        st.config(nodes['leaf3'], 'sudo cp /tmp/dhcpd_conf.txt /etc/dhcp/dhcpd.conf')

        st.config(nodes['leaf3'], 'sudo systemctl unmask isc-dhcp-server.service')
        st.config(nodes['leaf3'], 'sudo systemctl start isc-dhcp-server')
        status_output = st.show(nodes['leaf3'], 'sudo systemctl status isc-dhcp-server', skip_error_check=True)
        st.log("DHCP service status: {}".format(status_output))

        # Verify Portchannel state is up on 'leaf0' and 'down' on leaf1
        if not portchannel_obj.verify_portchannel_member_state(nodes['leaf0'], portchannel_name, vars.D1D9P1, "up"):
            st.report_fail("Portchannel state verification failed on nodes['leaf0']")
        if not portchannel_obj.verify_portchannel_member_state(nodes['leaf1'], portchannel_name, vars.D2D9P1, "down"):
            st.report_fail("Portchannel state verification failed on nodes['leaf1']")

        # Reboot client and check IP address on client's eth1 interface
        st.log("Reboot client node and wait for 120 secs")
        reboot_obj.dut_reboot(nodes['client'], max_time=120)
        st.log("Checking IP address on client's eth1 interface")
        ip_addr_output = st.config(nodes['client'], 'ip addr show eth1', skip_error_check=True)
        st.log("Client eth1 interface status: {}".format(ip_addr_output))

        # Check if an IP address is assigned
        if 'inet ' in ip_addr_output:
            st.log("IP address is assigned on client's eth1 interface")
        else:
            st.log("No IP address found on client's eth1 interface")
            st.report_fail('test_case_failed', 'LACP fallback with pxe boot failed')

        st.report_pass('test_case_passed', 'LACP fallback with pxe boot passed')
        return True

    except Exception as e:
        st.log("LACP fallback with pxe boot failed with exception: {}".format(e))
        return False
