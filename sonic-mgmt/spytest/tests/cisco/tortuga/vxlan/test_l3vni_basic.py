import os
import yaml
import pytest
from spytest import st
import apis.routing.bgp as bgpapi

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:1",  "D1D4:1", "D2D3:1",  "D2D4:1")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

# TODO: Parameterize the configs. For now, use static configs
CONFIGS_FILE = 'vxlan_l3vni_configs.yaml'

LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'
SPINE0_VXLAN_IP = '10.200.200.210'

LEAF0_BGP_RTRID = '2363073663'
LEAF1_BGP_RTRID = '2363033449'
SPINE0_BGP_RTRID = '2363070545'

def setup_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass

####################
#                  #
#    D1 = Leaf0    #
#    D2 = Leaf1    #
#    D3 = Spine0   #
#    D4 = Spine1   #
#                  #
####################

####################################################################
#                                                                  #
#   leaf0.Ethernet0-11.11.11.2  ---- spine0.Ethernet0-11.11.11.1   #
#   leaf1.Ethernet12-11.11.12.2 ---- spine0.Ethernet8-11.11.12.1   #
#                                                                  #
####################################################################
def test_l3vni_basic_config():
    VNI = '1000'

    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            setup_node(nodes[node], config['sonic'], '')
            setup_node(nodes[node], config['bgp'], 'vtysh')

    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    count = 5
    st.show(nodes['leaf0'], "sudo ping -c {} {} -q".format(count, '11.11.11.1'))
    st.show(nodes['leaf1'], "sudo ping -c {} {} -q".format(count, '11.11.12.1'))

    leaf0_vrf_prefix = '100.100.100.0'
    leaf1_vrf_prefix = '100.100.101.0'

    leaf0_output = st.show(nodes['leaf0'], "show bgp l2vpn evpn {}".format(leaf1_vrf_prefix), type="vtysh")

    leaf0_parsed = st.parse_show(nodes['leaf0'], "show bgp l2vpn evpn {}".format(leaf1_vrf_prefix),
                                 leaf0_output, "show_bgp_l2vpn_evpn_prefix.tmpl")

    leaf1_output = st.show(nodes['leaf1'], "show bgp l2vpn evpn {}".format(leaf0_vrf_prefix), type="vtysh")

    leaf1_parsed = st.parse_show(nodes['leaf1'], "show bgp l2vpn evpn {}".format(leaf0_vrf_prefix),
                                 leaf1_output, "show_bgp_l2vpn_evpn_prefix.tmpl")

    if len(leaf0_parsed) == 0:
        st.report_fail("Found no prefixes advertised to Leaf0")

    if len(leaf1_parsed) == 0:
        st.report_fail("Found no prefixes advertised to Leaf1")

    for path in leaf0_parsed:
        if path['valid'] != 'valid':
            st.report_fail("Invalid path found in leaf0")
        if path['pathevpntype'] != '5':
            st.report_fail("Invalid evpn type {} found in leaf0".format(path['evpntype']))
        if path['vni'] != '1000':
            st.report_fail("Incorrect vni found in leaf0")

    for path in leaf1_parsed:
        if path['valid'] != 'valid':
            st.report_fail("Invalid path found in leaf0")
        if path['pathevpntype'] != '5':
            st.report_fail("Invalid evpn type {} found in leaf0".format(path['evpntype']))
        if path['vni'] != '1000':
            st.report_fail("Incorrect vni found in leaf0")

    st.report_pass("Basic L3VNI test passed")
