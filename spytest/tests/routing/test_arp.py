import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.arp as arp_obj
import apis.routing.ip as ip_obj
import apis.system.interface as interface_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac

data = SpyTestDict()
data.d1t1_ip_addr = "192.168.11.1"
data.t1d1_ip_addr = "192.168.11.2"
data.t1d1_mac_addr = "00:00:00:00:00:01"
data.d1t2_ip_addr = "192.168.12.1"
data.t2d1_ip_addr = "192.168.12.2"
data.t2d1_mac_addr = "00:00:00:00:00:02"
data.static_arp_ip_1 = "192.168.11.4"
data.static_arp_mac = "00:00:00:00:00:66"
data.static_arp_ip = "192.168.12.3"
data.static_arp_mac_1 = "00:00:00:00:00:77"
data.mask = "24"
data.vlan_1 = 64
data.vlan_int_1 = "Vlan{}".format(data.vlan_1)
data.clear_parallel = False

@pytest.fixture(scope="module", autouse=True)
def arp_module_hooks(request):
    global vars, tg_handler, tg, dut1, d1_mac_addr, h1, h2

    # Min topology verification
    vars = st.ensure_min_topology("D1T1:2")

    # Initialize TG and TG port handlers
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2")
    tg = tg_handler["tg"]

    # Test setup details
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]

    # Test variables
    d1_mac_addr = mac.get_sbin_intf_mac(dut1, "eth0")

    # ARP module configuration
    st.log("ARP module configuration.")
    ip_obj.config_ip_addr_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr, data.mask)
    vlan_obj.create_vlan(dut1, data.vlan_1)
    vlan_obj.add_vlan_member(dut1, data.vlan_1, vars.D1T1P2, True)
    ip_obj.config_ip_addr_interface(dut1, data.vlan_int_1, data.d1t2_ip_addr, data.mask)

    # TG ports reset
    st.log("Resetting the TG ports")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])

    # TG protocol interface creation
    st.log("TG protocol interface creation")
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config',
            intf_ip_addr=data.t1d1_ip_addr,gateway=data.d1t1_ip_addr,
            src_mac_addr=data.t1d1_mac_addr,arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',
            intf_ip_addr=data.t2d1_ip_addr,gateway=data.d1t2_ip_addr,
            src_mac_addr=data.t2d1_mac_addr,arp_send_req='1',vlan_id=data.vlan_1,vlan=1)
    st.log("INTFCONF: "+str(h2))

    yield
    # ARP module cleanup
    st.log("ARP module cleanup.")
    ip_obj.clear_ip_configuration(dut1,family="ipv4",thread=data.clear_parallel)
    vlan_obj.clear_vlan_configuration(dut1,thread= data.clear_parallel)

@pytest.fixture(scope="function", autouse=True)
def arp_func_hooks(request):
    # ARP function configuration
    yield
    # ARP function cleanup

def test_ft_arp_entry_link_failure():
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify an ARP table entry learned on port based routing interface is
    #               removed from ARP table after link failure on which that entry is learned.
    # Objective - Verify an ARP table entry learned on vlan based routing interface is
    #               removed from ARP table after link failure on which that entry is learned
    #
    ############### Test bed details ################
    #  DUT-----TG
    #################################################
    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'],
                     dst_ip=data.d1t1_ip_addr,ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_2"], dev_handle=h2['handle'],
                     dst_ip=data.d1t2_ip_addr,ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    # Verify dynamic arp entries
    st.log("Verifying the arp entries on the DUT.")
    if not arp_obj.verify_arp(dut1,data.t1d1_ip_addr,data.t1d1_mac_addr,vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t1d1_ip_addr, dut1)
    st.log("Verifying the arp entries on the DUT")
    if not arp_obj.verify_arp(dut1,data.t2d1_ip_addr,data.t2d1_mac_addr,vars.D1T1P2,data.vlan_1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t2d1_ip_addr, dut1)

    # Shutdown the routing interface link.
    st.log("Shutdown the routing interface links.")
    if not interface_obj.interface_operation(dut1, [vars.D1T1P1, vars.D1T1P2] , "shutdown"):
        st.report_fail('interface_admin_shut_down_fail', [vars.D1T1P1, vars.D1T1P2])

    # Verify dynamic arp entries
    st.log("Verifying the arp entries on the DUT.")
    if arp_obj.verify_arp(dut1,data.t1d1_ip_addr,data.t1d1_mac_addr,vars.D1T1P1):
        st.report_fail("ARP_dynamic_entry_removal_fail", data.t1d1_ip_addr, vars.D1T1P1)
    st.log("Verifying the arp entries on the DUT")
    if arp_obj.verify_arp(dut1,data.t2d1_ip_addr):
        st.report_fail("ARP_dynamic_entry_removal_fail", data.t2d1_ip_addr, vars.D1T1P2)

    # Startup the routing interface link.
    st.log("Startup the routing interface link.")
    if not interface_obj.interface_operation(dut1, [vars.D1T1P1, vars.D1T1P2], "startup"):
        st.report_fail('interface_admin_startup_fail', [vars.D1T1P1, vars.D1T1P2])

    st.wait(5)

    # Verify dynamic arp entries
    st.log("Verifying the arp entries on the DUT.")
    if not arp_obj.verify_arp(dut1,data.t1d1_ip_addr,data.t1d1_mac_addr,vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t1d1_ip_addr, dut1)
    st.log("Verifying the arp entries on the DUT")
    if not arp_obj.verify_arp(dut1,data.t2d1_ip_addr,data.t2d1_mac_addr,vars.D1T1P2,data.vlan_1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t2d1_ip_addr, dut1)

    st.report_pass("test_case_passed")

@pytest.fixture(scope="function")
def fixture_ft_arp_dynamic_renew_traffic_test(request):
    yield
    arp_obj.set_arp_ageout_time(dut1,60)

def test_ft_arp_dynamic_renew_traffic_test(fixture_ft_arp_dynamic_renew_traffic_test):
    ################## Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email: rakesh-kumar.vooturi@broadcom.com
    ##################################################
    #
    # Objective - Verify a dynamic ARP table entry can be created.
    # Objective - Verify that there is no data traffic loss during ARP dynamic review.
    #
    ############### Test bed details ################
    #  TG-----DUT-----TG
    #################################################
    # Set DUT values
    st.log("Setting the DUT values")
    arp_obj.set_arp_ageout_time(dut1,5)

    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'],
                     dst_ip=data.d1t1_ip_addr,ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_2"], dev_handle=h2['handle'],
                     dst_ip=data.d1t2_ip_addr,ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    # TG ports reset
    st.log("Resetting the TG ports")
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    #TG stream formation
    s1 = tg.tg_traffic_config(port_handle= tg_handler["tg_ph_2"],mode='create',rate_pps=10,
                    mac_src=data.t2d1_mac_addr,transmit_mode="continuous",mac_dst=d1_mac_addr,
                    l2_encap='ethernet_ii_vlan',l3_protocol="ipv4",ip_dst_addr=data.t1d1_ip_addr,
                    ip_src_addr=data.t2d1_ip_addr,vlan_id=data.vlan_1,vlan="enable")
    tg.tg_traffic_control(action="run", stream_handle=s1['stream_id'])

    # Waiting for more than arp ageout time
    st.wait(10)
    tg.tg_traffic_control(action="stop", stream_handle=s1['stream_id'])

    # Adding sleep
    st.wait(2)

    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
            '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.report_fail("traffic_verification_failed")
    else:
        st.log("traffic verification passed")
    st.report_pass("test_case_passed")


@pytest.fixture(scope="function")
def fixture_ft_arp_clear_cache_static_and_dynamic_entries(request):
    yield
    arp_obj.delete_static_arp(dut1, data.static_arp_ip)
    arp_obj.delete_static_arp(dut1, data.static_arp_ip_1)

@pytest.mark.community
@pytest.mark.community_pass
def test_ft_arp_clear_cache_static_and_dynamic_entries(fixture_ft_arp_clear_cache_static_and_dynamic_entries):
    ################## Author Details ###############
    # Name: Rakesh Kumar Vooturi
    # Email: rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify that the clearing the ARP cache,
    #             all dynamic entries are removed and static entries are not cleared.
    #
    ############### Test bed details ################
    #  TG-----DUT-----TG
    #################################################
    # Adding static arp entries
    arp_obj.add_static_arp(dut1, data.static_arp_ip_1, data.static_arp_mac_1, vars.D1T1P1)
    arp_obj.add_static_arp(dut1, data.static_arp_ip, data.static_arp_mac, data.vlan_int_1)

    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'],
                      dst_ip=data.d1t1_ip_addr,ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_2"], dev_handle=h2['handle'],
                      dst_ip=data.d1t2_ip_addr,ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    # Verify static and dynamic arp entries
    st.log("Verifying the arp entries on the DUT")
    if not arp_obj.verify_arp(dut1,data.t1d1_ip_addr,data.t1d1_mac_addr,vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t1d1_ip_addr, dut1)
    if not arp_obj.verify_arp(dut1,data.t2d1_ip_addr,data.t2d1_mac_addr,vars.D1T1P2,data.vlan_1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t2d1_ip_addr, dut1)
    if not arp_obj.verify_arp(dut1,data.static_arp_ip_1,data.static_arp_mac_1,vars.D1T1P1):
        st.report_fail("static_arp_create_fail", dut1)
    if not arp_obj.verify_arp(dut1,data.static_arp_ip,data.static_arp_mac,"",data.vlan_1):
        st.report_fail("static_arp_create_fail", dut1)

    st.banner("Start - Verifying dynamic and static arp entries behavior on issuing sonic-clear arp command *WITH* traffic flowing")

    # TG ports reset
    st.log("Resetting the TG ports")
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    #TG stream formation
    s1=tg.tg_traffic_config(port_handle= tg_handler["tg_ph_2"],mode='create',rate_pps=10,
        mac_src=data.t2d1_mac_addr,transmit_mode="continuous",mac_dst=d1_mac_addr,
        l2_encap='ethernet_ii_vlan',l3_protocol="ipv4",ip_dst_addr=data.t1d1_ip_addr,
        ip_src_addr=data.t2d1_ip_addr,vlan_id=data.vlan_1,vlan="enable")
    s2=tg.tg_traffic_config(port_handle= tg_handler["tg_ph_1"],mode='create',rate_pps=10,
        mac_src=data.t1d1_mac_addr,transmit_mode="continuous",mac_dst=d1_mac_addr,
        l2_encap='ethernet_ii_vlan',l3_protocol="ipv4",ip_dst_addr=data.t2d1_ip_addr,
        ip_src_addr=data.t1d1_ip_addr)

    tg.tg_traffic_control(action="run",stream_handle=[s1['stream_id'], s2['stream_id']])

    # Adding wait for traffic to flow.
    st.wait(5)

    # Issuing sonic-clear arp command and veryfying the entries behavior.
    arp_obj.clear_arp_table(dut1)

    # Adding wait for traffic to flow.
    st.wait(5)

    # Verify static and dynamic arp entries after clear arp
    st.log("Verifying the arp entries on the DUT after issuing sonic-clear arp command with traffic flowing.")
    if not arp_obj.verify_arp(dut1,data.t1d1_ip_addr,data.t1d1_mac_addr,vars.D1T1P1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t1d1_ip_addr, dut1)
    if not arp_obj.verify_arp(dut1,data.t2d1_ip_addr,data.t2d1_mac_addr,vars.D1T1P2,data.vlan_1):
        st.report_fail("ARP_entry_dynamic_entry_fail", data.t2d1_ip_addr, dut1)
    if not arp_obj.verify_arp(dut1,data.static_arp_ip_1,data.static_arp_mac_1,vars.D1T1P1):
        st.report_fail("static_arp_delete_fail", dut1)
    if not arp_obj.verify_arp(dut1,data.static_arp_ip,data.static_arp_mac,"",data.vlan_1):
        st.report_fail("static_arp_delete_fail", dut1)

    # Stop the traffic
    tg.tg_traffic_control(action="stop",stream_handle=[s1['stream_id'], s2['stream_id']])

    st.log("Verifying the TG stats")

    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.report_fail("traffic_verification_failed")
    else:
        st.log("traffic verification passed")

    st.banner("End - Verified dynamic and static arp entries behavior on issuing sonic-clear arp command *WITH* traffic flowing")

    st.banner("Start - Verifying dynamic and static arp entries behavior on issuing sonic-clear arp command *WITHOUT* traffic flowing")
    # Issuing sonic-clear arp command and veryfying the entries behavior.
    arp_obj.clear_arp_table(dut1)

    # Verify static and dynamic arp entries after clear arp
    st.log("Verifying the arp entries on the DUT after issuing sonic-clear arp command")
    if arp_obj.verify_arp(dut1,data.t1d1_ip_addr,data.t1d1_mac_addr,vars.D1T1P1):
        st.report_fail("ARP_dynamic_entry_clear_arp_fail", data.t1d1_ip_addr, dut1)
    if arp_obj.verify_arp(dut1,data.t2d1_ip_addr,data.t2d1_mac_addr,vars.D1T1P2,data.vlan_1):
        st.report_fail("ARP_dynamic_entry_clear_arp_fail", data.t2d1_ip_addr, dut1)
    if not arp_obj.verify_arp(dut1,data.static_arp_ip_1,data.static_arp_mac_1,vars.D1T1P1):
        st.report_fail("static_arp_delete_fail", dut1)
    if not arp_obj.verify_arp(dut1,data.static_arp_ip,data.static_arp_mac,"",data.vlan_1):
        st.report_fail("static_arp_delete_fail", dut1)

    st.banner("End - Verified dynamic and static arp entries behavior on issuing sonic-clear arp command *WITHOUT* traffic flowing")

    st.report_pass("test_case_passed")
