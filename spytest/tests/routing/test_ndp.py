import pytest

from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan_obj
import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj

from utilities.common import filter_and_select

data = SpyTestDict()
data.vlan_1 = 64
data.count = 5
data.vlan_int_1 = "Vlan{}".format(data.vlan_1)
data.clear_parallel = False
data.local_ip6_addr = ["2001::1", "3001::1"]
data.local_ip6_addr_rt = ["2001::", "3001::", "4001::"]
data.neigh_ip6_addr_gw = ["2001::100", "3001::100", "4001::100"]
data.af_ipv6 = "ipv6"
data.tg_mac1 = '00:0a:01:01:23:01'
data.tg_mac2 = '00:0b:01:01:23:01'
data.tg_mac3 = '00:0c:01:01:23:01'

@pytest.fixture(scope="module", autouse=True)
def ndp_module_hooks(request):
    vars = st.ensure_min_topology("D1T1:2")

    # Initialize TG and TG port handlers
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2")
    tg = tg_handler["tg"]

    # Test setup details
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]

    # NDP module configuration
    st.log("NDP module configuration.")
    ip_obj.config_ip_addr_interface(dut1, vars.D1T1P1, data.local_ip6_addr[0], 64, family=data.af_ipv6)
    vlan_obj.create_vlan(dut1, data.vlan_1)
    vlan_obj.add_vlan_member(dut1, data.vlan_1, vars.D1T1P2, True)
    ip_obj.config_ip_addr_interface(dut1, data.vlan_int_1, data.local_ip6_addr[1], 64, family=data.af_ipv6)

    # TG ports reset
    st.log("Resetting the TG ports")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])

    # TG protocol interface creation
    st.log("TG protocol interface creation")
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config',
             ipv6_intf_addr=data.neigh_ip6_addr_gw[0],ipv6_prefix_length='64',
             ipv6_gateway=data.local_ip6_addr[0],src_mac_addr=data.tg_mac1,
             arp_send_req='1', count=data.count)
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',
             ipv6_intf_addr=data.neigh_ip6_addr_gw[1],ipv6_prefix_length='64',
             ipv6_gateway=data.local_ip6_addr[1],src_mac_addr=data.tg_mac2 ,
             arp_send_req='1', vlan_id=data.vlan_1, vlan=1, count=data.count)
    st.log("INTFCONF: " + str(h2))

    yield
    # NDP module cleanup
    st.log("NDP module cleanup.")
    ip_obj.clear_ip_configuration(dut1,family="ipv6",thread=data.clear_parallel)
    vlan_obj.clear_vlan_configuration(dut1,thread= data.clear_parallel)

@pytest.fixture(scope="function", autouse=True)
def ndp_func_hooks(request):
    # NDP function configuration
    yield
    # NDP function cleanup

@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_ipv6_neighbor_entry():
    ################# Author Details ################
    # Name: Raja Sekhar Uppara
    # Email: raja-sekhar.uppara@broadcom.com
    #################################################
    # Objective - 1.Verify that IPv6 neighbor entries are created successfully.
    #             2.Verify that Ipv6 Static neighbor entries are created successfully.
    #             3.'sudo sonic-clear ndp' flushes the existing dymanic entries
    ############### Test bed details ################
    #  TG1-----DUT-----TG2
    #################################################
    vars = st.get_testbed_vars()
    arp_obj.show_ndp(vars.D1)
    ndp_dut_count_initial = arp_obj.get_ndp_count(vars.D1)
    if ndp_dut_count_initial < 2*data.count:
        st.report_fail("ndp_dynamic_entry_fail")
    arp_obj.clear_ndp_table(vars.D1)
    ndp_dut_count_post_clear = int(arp_obj.get_ndp_count(vars.D1))
    if ndp_dut_count_post_clear > 2:
        out = arp_obj.show_ndp(vars.D1)
        entries = filter_and_select(out, [None], {'status': 'NOARP'})
        if not len(out) == len(entries):
            st.report_fail("ndp_entries_clearing_failed")
    arp_obj.config_static_ndp(vars.D1, data.neigh_ip6_addr_gw[2],data.tg_mac3, vars.D1T1P1)
    ndp_dut_count_static = int(arp_obj.get_ndp_count(vars.D1))
    if not ndp_dut_count_static:
        st.report_fail("static_ndp_create_fail")
    arp_obj.config_static_ndp(vars.D1, data.neigh_ip6_addr_gw[2], data.tg_mac3 , vars.D1T1P1, 'del')
    st.report_pass("test_case_passed")

