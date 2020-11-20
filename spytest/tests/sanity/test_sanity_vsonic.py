import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import utilities.utils as utils_obj
import apis.system.interface as intf_obj
import apis.common.asic as asicapi
import apis.routing.ip as ip_obj

vars = dict()

@pytest.fixture(scope="module", autouse=True)
def sanity_vsonic_module_hooks(request):
    yield

@pytest.fixture(scope="function", autouse=True)
def sanity_vsonic_func_hooks(request):
    global vars
    vars = st.get_testbed_vars()
    st.log("PRE TSET : Cleanup call are started.")
    ip_obj.clear_ip_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(),'ipv6')
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names())
    yield
    st.log("POST TSET : Cleanup call are started.")
    ip_obj.clear_ip_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(),'ipv6')
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names())



data = SpyTestDict()
data.vlan_id = str(random_vlan_list()[0])
data.portChannelName = "PortChannel005"
data.mac_addr_cnt = 100
data.source_mac = "00:00:02:00:00:01"
data.destination_mac = "00:00:01:00:00:01"
data.rate_pps = "100"
data.wait_post_port_channel_up = 10
data.clear_mac_table_wait_time= 3
data.post_wait_time_run = 5
data.post_wait_time_stop = 5
data.post_wait_time_clear = 1
data.post_wait_time_create = 2

#### For Vsonic we need to set skip_tg flag to 1
skip_tg = 1


@pytest.mark.base_test_sanity_vsonic
@pytest.mark.base_test_sanity_vsonic1
def test_base_line_L2_portchannel_tests():

    ## Sub test selection
    sub_test_1 = 1
    sub_test_2 = 1
    sub_test_3 = 1
    sub_test_4 = 1
    sub_test_5 = 1

    ## Global and Topology variable
    data.mac_addr_cnt = 2
    data.no_of_port_channel_create_and_delete = 1
    data.post_link_shutdown_wait_time = 1
    data.dut2_lag_members = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    data.dut1_lag_members = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]


    if not skip_tg:
        tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
        tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
        data.port_hand_list = [tg_ph_1,tg_ph_2]
    else:
        vars.D1T1P1 = st.get_free_ports(vars.D1)[0]
        vars.D2T1P1 = st.get_free_ports(vars.D2)[0]


    intf_obj.clear_interface_counters(vars.D1)
    intf_obj.clear_interface_counters(vars.D2)
    topology = {vars.D1: {"ports": data.dut1_lag_members, "TGports": vars.D1T1P1},
                vars.D2: {"ports": data.dut2_lag_members, "TGports": vars.D2T1P1}}

    if not skip_tg:
        st.log("Sending VLAN traffic and verifying the stats")
        tg1.tg_traffic_control(action='reset',port_handle =  data.port_hand_list)
        tg1.tg_traffic_control(action='clear_stats',port_handle = data.port_hand_list)
        s1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=data.rate_pps, mac_src=data.source_mac,
                                   mac_src_mode="increment",
                                   mac_src_count=data.mac_addr_cnt, transmit_mode="continuous",
                                   mac_src_step="00:00:00:00:00:01", mac_dst=data.destination_mac,
                                   mac_dst_mode="increment",
                                   mac_dst_count=data.mac_addr_cnt, mac_dst_step="00:00:00:00:00:01",
                                   l2_encap='ethernet_ii_vlan',
                                   vlan_id=data.vlan_id, vlan="enable")['stream_id']
        s2 = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_pps=data.rate_pps, mac_src=data.destination_mac,
                              mac_src_mode="increment",
                              mac_src_count=data.mac_addr_cnt, transmit_mode="continuous",
                              mac_src_step="00:00:00:00:00:01", mac_dst=data.source_mac, mac_dst_mode="increment",
                              mac_dst_count=data.mac_addr_cnt, mac_dst_step="00:00:00:00:00:01",
                              l2_encap='ethernet_ii_vlan',
                              vlan_id=data.vlan_id, vlan="enable")['stream_id']

    if sub_test_1:

        st.log("#"*40)
        st.log("############# Sub test 1: test_base_line_portchannel_create_delete - START  ################")
        st.log("#"*40)


        st.log("Verifing the oper status of ports and do shut and no shut - Initially")
        for dut in topology:
            all_ports = topology[dut]["ports"] + [topology[dut]["TGports"]]
            for each_port in all_ports:
                if not intf_obj.verify_interface_status(dut,each_port, 'oper', 'up'):
                    intf_obj.interface_shutdown(dut,each_port)
                    st.wait(data.post_link_shutdown_wait_time)
                    intf_obj.interface_noshutdown(dut,each_port)
                    if not intf_obj.verify_interface_status(dut, each_port, 'oper', 'up'):
                        st.report_fail('interface_is_down_on_dut',each_port)

        st.log("Config Vlan tagged and Portchannel on both DUTs")
        for dut in topology:
            portchannel_obj.create_portchannel(dut, data.portChannelName)
            portchannel_obj.add_portchannel_member(dut, data.portChannelName, topology[dut]["ports"])
            vlan_obj.create_vlan(dut, data.vlan_id)
            vlan_obj.add_vlan_member(dut, data.vlan_id, [topology[dut]["TGports"], data.portChannelName], True)

            assert vlan_obj.verify_vlan_config(dut, data.vlan_id, tagged=[topology[dut]["TGports"],data.portChannelName]), \
                st.report_fail("vlan_tagged_member_fail", [topology[dut]["TGports"],data.portChannelName], data.vlan_id)

        st.log("Verifing the Port channel status - Initially")
        for dut in topology:
            if not portchannel_obj.verify_portchannel_and_member_status(dut,data.portChannelName,topology[dut]["ports"],
                                                                        iter_count=6,iter_delay=1,state='up'):
                st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")

        for dut in topology:
            if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                st.log("Port channel is not {}".format('up'))
                st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")
        ## Port channle/member stabilization time for carrying the traffic.
        st.wait(data.wait_post_port_channel_up)

        if not skip_tg:
            st.log("Sending VLAN traffic and verifying the stats")

            tg1.tg_traffic_control(action='run', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_run )
            tg1.tg_traffic_control(action='stop', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_stop)

            stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
            total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
            total_rx_tg1 = int(stats_tg1['aggregate']['rx']['total_pkts']['max'])
            tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100


            stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
            total_tx_tg2 = int(stats_tg2['aggregate']['tx']['total_pkts']['max'])
            tx_tg2_95_precentage = (95 * int(total_tx_tg2)) / 100

            st.log('total_tx_tg1 = {}'.format(total_tx_tg1))
            st.log('tx_tg1_95_precentage = {}'.format(tx_tg1_95_precentage))
            st.log('total_rx_tg1 = {}'.format(total_rx_tg1))
            st.log('total_tx_tg2 = {}'.format(total_tx_tg2))
            st.log('tx_tg2_95_precentage = {}'.format(tx_tg2_95_precentage))
            st.log('total_rx_tg2 = {}'.format(total_rx_tg2))

            assert tx_tg1_95_precentage <= total_rx_tg2, st.report_fail("traffic_verification_failed")
            assert tx_tg2_95_precentage <= total_rx_tg1, st.report_fail("traffic_verification_failed")
            st.log("Traffic test passed..")

            st.log("Debug prints.....")
            for dut in topology:
                asicapi.dump_vlan(dut)
                asicapi.dump_l2(dut)
                asicapi.dump_trunk(dut)


            st.log("Validating MAC table..")
            dut1_mac_address_list = utils_obj.get_mac_address(data.source_mac,start=0,end=data.mac_addr_cnt )
            dut2_mac_address_list = utils_obj.get_mac_address(data.destination_mac,start=0,end=data.mac_addr_cnt )
            complete_mac_address_list = dut1_mac_address_list + dut2_mac_address_list

            assert mac_obj.verify_mac_address(vars.D1, data.vlan_id, complete_mac_address_list), \
                st.report_fail("mac_address_verification_fail")
            assert mac_obj.verify_mac_address(vars.D2, data.vlan_id, complete_mac_address_list), \
                st.report_fail("mac_address_verification_fail")
            st.log("MAC table validation passed..")

        st.log("Start Creating and delete the Portchannel")
        portchannel_list = []
        for i in range(6,data.no_of_port_channel_create_and_delete+6):
            portchannel_obj.create_portchannel(vars.D1, "PortChannel00{}".format(i))
            portchannel_obj.create_portchannel(vars.D2, "PortChannel00{}".format(i))
            portchannel_list.append("PortChannel00{}".format(i))
        dut1_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D1))
        assert int(dut1_portchannel_list) == int(data.no_of_port_channel_create_and_delete+1), \
            st.report_fail("portchannel_count_verification_fail", data.no_of_port_channel_create_and_delete+1,
                           dut1_portchannel_list)
        dut2_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D2))
        assert int(dut2_portchannel_list ) == int(data.no_of_port_channel_create_and_delete+1), \
            st.report_fail("portchannel_count_verification_fail", data.no_of_port_channel_create_and_delete+1,
                           dut2_portchannel_list)
        portchannel_obj.delete_portchannel(vars.D1, portchannel_list)
        portchannel_obj.delete_portchannel(vars.D2, portchannel_list)
        dut1_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D1))
        assert int(dut1_portchannel_list) == 1, \
            st.report_fail("portchannel_count_verification_fail", 1, dut1_portchannel_list)
        dut2_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D2))
        assert int(dut2_portchannel_list) == 1, \
            st.report_fail("portchannel_count_verification_fail", 1, dut2_portchannel_list)

        if not skip_tg:
            st.log("Traffic checking post port channel create and delete")
            tg1.tg_traffic_control(action='clear_stats',port_handle= data.port_hand_list)
            st.wait(data.post_wait_time_clear)

            tg1.tg_traffic_control(action='run', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_run)

            tg1.tg_traffic_control(action='stop', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_stop)

            stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
            total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
            total_rx_tg1 = int(stats_tg1['aggregate']['rx']['total_pkts']['max'])
            tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100

            stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
            total_tx_tg2 = int(stats_tg2['aggregate']['tx']['total_pkts']['max'])
            tx_tg2_95_precentage = (95 * int(total_tx_tg2)) / 100

            st.log('total_tx_tg1 = {}'.format(total_tx_tg1))
            st.log('tx_tg1_95_precentage = {}'.format(tx_tg1_95_precentage))
            st.log('total_rx_tg1 = {}'.format(total_rx_tg1))
            st.log('total_tx_tg2 = {}'.format(total_tx_tg2))
            st.log('tx_tg2_95_precentage = {}'.format(tx_tg2_95_precentage))
            st.log('total_rx_tg2 = {}'.format(total_rx_tg2))


            assert tx_tg1_95_precentage <= total_rx_tg2, st.report_fail("traffic_verification_failed")
            assert tx_tg2_95_precentage <= total_rx_tg1, st.report_fail("traffic_verification_failed")
            st.log("Traffic test passed..")

        st.log("Sub test 1 : PASSED")

        st.log("#"*40)
        st.log("############# Sub test 1: test_base_line_portchannel_create_delete - END  ################")
        st.log("#"*40)

    if not skip_tg:
        if sub_test_2:
            st.log("#"*40)
            st.log("############# Sub test 2: test_base_line_random_link_flap_portchannel  - START  ################")
            st.log("#"*40)

            st.log("Start performing the port channel member link flap")
            for i in range(1, 2):
                for interface in data.dut2_lag_members:
                    intf_obj.interface_shutdown(vars.D2, interface)
                    st.wait(3)
                    intf_obj.interface_noshutdown(vars.D2, interface)
            st.wait(2)
            st.log("Verifing the Port channel status - post flap members")
            for dut in topology:
                if not portchannel_obj.verify_portchannel_and_member_status(dut, data.portChannelName, topology[dut]["ports"],
                                                                            iter_count=6, iter_delay=1, state='up'):
                    st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")
            for dut in topology:
                if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                    st.log("Port channel is not {}".format('up'))
                    st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")

            st.log("Sub test 2 : PASSED")

            st.log("#"*40)
            st.log("############# Sub test 2: test_base_line_random_link_flap_portchannel  - END  ################")
            st.log("#"*40)


    if not skip_tg:
        if sub_test_3:

            st.log("#"*40)
            st.log("############# Sub test 3: test_base_line_l2_taggged_forwarding_with_portchannel after link - START  ################")
            st.log("#"*40)

            st.log("Verifing L2 tagged traffic forwarding on Port channel")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)

            tg1.tg_traffic_control(action='run', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_run )

            tg1.tg_traffic_control(action='stop', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_stop)

            stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
            total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
            total_rx_tg1 = int(stats_tg1['aggregate']['rx']['total_pkts']['max'])
            tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100

            stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
            total_tx_tg2 = int(stats_tg2['aggregate']['tx']['total_pkts']['max'])
            tx_tg2_95_precentage = (95 * int(total_tx_tg2)) / 100

            st.log('total_tx_tg1 = {}'.format(total_tx_tg1))
            st.log('tx_tg1_95_precentage = {}'.format(tx_tg1_95_precentage))
            st.log('total_rx_tg1 = {}'.format(total_rx_tg1))
            st.log('total_tx_tg2 = {}'.format(total_tx_tg2))
            st.log('tx_tg2_95_precentage = {}'.format(tx_tg2_95_precentage))
            st.log('total_rx_tg2 = {}'.format(total_rx_tg2))

            assert tx_tg1_95_precentage <= total_rx_tg2, st.report_fail("traffic_verification_failed")
            assert tx_tg2_95_precentage <= total_rx_tg1, st.report_fail("traffic_verification_failed")
            st.log("Traffic test passed..")

            st.log("Sub test 3 : PASSED")

            st.log("#"*40)
            st.log("############# Sub test 3: test_base_line_l2_taggged_forwarding_with_portchannel - END  ################")
            st.log("#"*40)

    if sub_test_4:

        st.log("#"*40)
        st.log("############# Sub test 4: test_base_line_vlan_port_association - START  ################")
        st.log("#"*40)

        st.log("Test clears the vlan and port-channel config ..")
        for dut in topology:
            vlan_obj.clear_vlan_configuration(dut)
        # portchannel_obj.clear_portchannel_configuration(dut)

        st.log("Config Vlan and Portchannel on both DUTs")
        for dut in topology:
            #portchannel_obj.create_portchannel(dut, data.portChannelName)
            #portchannel_obj.add_portchannel_member(dut, data.portChannelName, topology[dut]["ports"])
            vlan_obj.create_vlan(dut, data.vlan_id)
            vlan_obj.add_vlan_member(dut, data.vlan_id, [topology[dut]["TGports"], data.portChannelName], True)
            assert vlan_obj.verify_vlan_config(dut, data.vlan_id, tagged=[topology[dut]["TGports"],data.portChannelName]), \
                st.report_fail("vlan_tagged_member_fail", [topology[dut]["TGports"],data.portChannelName], data.vlan_id)

        st.log("Verifing the Port channel status")
        for dut in topology:
            if not portchannel_obj.verify_portchannel_and_member_status(dut,data.portChannelName,topology[dut]["ports"],
                                                                        iter_count=6,iter_delay=1,state='up'):
                st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")
        for dut in topology:
            if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                st.log("Port channel is not {}".format('up'))
                st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")

        st.wait(data.wait_post_port_channel_up)
        if not skip_tg:
            st.log("Sending VLAN traffic and verifying the stats")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)

            tg1.tg_traffic_control(action='run', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_run )

            tg1.tg_traffic_control(action='stop', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_stop)

            stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
            total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
            total_rx_tg1 = int(stats_tg1['aggregate']['rx']['total_pkts']['max'])
            tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100

            stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
            total_tx_tg2 = int(stats_tg2['aggregate']['tx']['total_pkts']['max'])
            tx_tg2_95_precentage = (95 * int(total_tx_tg2)) / 100

            st.log('total_tx_tg1 = {}'.format(total_tx_tg1))
            st.log('tx_tg1_95_precentage = {}'.format(tx_tg1_95_precentage))
            st.log('total_rx_tg1 = {}'.format(total_rx_tg1))
            st.log('total_tx_tg2 = {}'.format(total_tx_tg2))
            st.log('tx_tg2_95_precentage = {}'.format(tx_tg2_95_precentage))
            st.log('total_rx_tg2 = {}'.format(total_rx_tg2))

            assert tx_tg1_95_precentage <= total_rx_tg2, st.report_fail("traffic_verification_failed")
            assert tx_tg2_95_precentage <= total_rx_tg1, st.report_fail("traffic_verification_failed")
            st.log("Traffic test passed..")

            st.log("Debug prints.....")
            for dut in topology:
                asicapi.dump_vlan(dut)
                asicapi.dump_l2(dut)
                asicapi.dump_trunk(dut)


            st.log("Validating MAC table..")
            dut1_mac_address_list = utils_obj.get_mac_address(data.source_mac,start=0,end=data.mac_addr_cnt )
            dut2_mac_address_list = utils_obj.get_mac_address(data.destination_mac,start=0,end=data.mac_addr_cnt )
            complete_mac_address_list = dut1_mac_address_list + dut2_mac_address_list

            assert mac_obj.verify_mac_address(vars.D1, data.vlan_id, complete_mac_address_list), \
                st.report_fail("mac_address_verification_fail")
            assert mac_obj.verify_mac_address(vars.D2, data.vlan_id, complete_mac_address_list), \
                st.report_fail("mac_address_verification_fail")
            st.log("MAC table validation passed..")

        st.log("Sub test 4 : PASSED")
        st.log("#"*40)
        st.log("############# Sub test 4: test_base_line_vlan_port_association - END  ################")
        st.log("#"*40)

    if sub_test_5:
        st.log("#"*40)
        st.log("############# Sub test 5: test_base_line_port_move_from_vlan_a_to_vlan_b - START  ################")
        st.log("#"*40)

        st.log("Test clears the vlan and port-channel config ..")
        for dut in topology:
            vlan_obj.clear_vlan_configuration(dut)
        #portchannel_obj.clear_portchannel_configuration(dut)

        st.log("Config Vlan Untagged and Port-channel on both DUTs")
        for dut in topology:
            #portchannel_obj.create_portchannel(dut, data.portChannelName)
            #portchannel_obj.add_portchannel_member(dut, data.portChannelName, topology[dut]["ports"])
            vlan_obj.create_vlan(dut, data.vlan_id)
            vlan_obj.add_vlan_member(dut, data.vlan_id, [topology[dut]["TGports"], data.portChannelName], False)

            assert vlan_obj.verify_vlan_config(dut, data.vlan_id, untagged=[topology[dut]["TGports"],data.portChannelName]), \
                st.report_fail("vlan_tagged_member_fail", [topology[dut]["TGports"],data.portChannelName], data.vlan_id)

        st.log("Verifying the Port channel status")
        for dut in topology:
            if not portchannel_obj.verify_portchannel_and_member_status(dut,data.portChannelName,topology[dut]["ports"],
                                                                        iter_count=6,iter_delay=1,state='up'):
                st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")
        for dut in topology:
            if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                st.log("Port channel is not {}".format('up'))
                st.report_fail("portchannel_state_fail", data.portChannelName, dut, "up")

        st.wait(data.wait_post_port_channel_up)

        st.log("Debug prints.....")
        for dut in topology:
            asicapi.dump_vlan(dut)
            asicapi.dump_l2(dut)
            asicapi.dump_trunk(dut)

        if not skip_tg:
            st.log("Sending VLAN traffic and verifying the stats")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)

            tg1.tg_traffic_control(action='run', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_run)

            tg1.tg_traffic_control(action='stop', stream_handle= [s1, s2])
            st.wait(data.post_wait_time_stop)

            stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
            total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
            total_rx_tg1 = int(stats_tg1['aggregate']['rx']['total_pkts']['max'])
            tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100

            stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
            total_tx_tg2 = int(stats_tg2['aggregate']['tx']['total_pkts']['max'])
            tx_tg2_95_precentage = (95 * int(total_tx_tg2)) / 100

            st.log('total_tx_tg1 = {}'.format(total_tx_tg1))
            st.log('tx_tg1_95_precentage = {}'.format(tx_tg1_95_precentage))
            st.log('total_rx_tg1 = {}'.format(total_rx_tg1))
            st.log('total_tx_tg2 = {}'.format(total_tx_tg2))
            st.log('tx_tg2_95_precentage = {}'.format(tx_tg2_95_precentage))
            st.log('total_rx_tg2 = {}'.format(total_rx_tg2))

            assert tx_tg1_95_precentage <= total_rx_tg2, st.report_fail("traffic_verification_failed")
            assert tx_tg2_95_precentage <= total_rx_tg1, st.report_fail("traffic_verification_failed")
            st.log("Traffic test passed..")

            st.log("Debug prints.....")
            for dut in topology:
                asicapi.dump_vlan(dut)
                asicapi.dump_l2(dut)
                asicapi.dump_trunk(dut)

            st.log("Validating MAC table..")
            dut1_mac_address_list = utils_obj.get_mac_address(data.source_mac,start=0,end=data.mac_addr_cnt )
            dut2_mac_address_list = utils_obj.get_mac_address(data.destination_mac,start=0,end=data.mac_addr_cnt )
            complete_mac_address_list = dut1_mac_address_list + dut2_mac_address_list

            assert mac_obj.verify_mac_address(vars.D1, data.vlan_id, complete_mac_address_list), \
                st.report_fail("mac_address_verification_fail")
            assert mac_obj.verify_mac_address(vars.D2, data.vlan_id, complete_mac_address_list), \
                st.report_fail("mac_address_verification_fail")
            st.log("MAC table validation passed..")

        st.log("Sub test 5 : PASSED")
        st.log("#"*40)
        st.log("############# Sub test 5: test_base_line_port_move_from_vlan_a_to_vlan_b - END  ################")
        st.log("#"*40)

    st.report_pass("test_case_passed")

@pytest.mark.base_test_sanity_vsonic
@pytest.mark.base_test_sanity_vsonic2
def test_base_line_l2_forwarding_tests():

    # data.clear_mac_table_wait_time = 3
    # data.post_wait_time_run = 5
    # data.post_wait_time_stop = 10
    # data.post_wait_time_clear = 1
    # data.post_wait_time_create = 2

    ## Sub test selection
    sub_test_6 = 0	## this is covered in Sub test 5: test_base_line_port_move_from_vlan_a_to_vlan_b -  test_base_line_L2_portchannel_tests
    sub_test_7 = 0  ## this is covered in - sub test 1 of main test -  test_base_line_L2_portchannel_tests
    sub_test_8 = 1
    sub_test_9 = 0  ## this is covered in sub test 10 of main test - test_base_line_mac_move_single_vlan
    sub_test_10 = 1
    sub_test_11 = 1
    sub_test_12 = 0  ## mac aging test is taken out of dev sanity, included in regressions - bassed inputs from Ramakanth J

    # ## Cleanup
    # vlan_obj.clear_vlan_configuration(vars.D1)


    ## Global and Topology variable
    data.vlan_id_start=101
    data.vlan_id_end=101
    data.vlan_range = (data.vlan_id_end-data.vlan_id_start) + 1
    data.multicast_mac="01:00:5E:00:00:07"
    data.broacast_mac="FF:FF:FF:FF:FF:FF"
    data.unknown_mac="00:01:02:03:04:05"
    data.source_mac="00:56:78:98:09:45"
    data.destination_mac="00:56:78:98:10:55"
    data.rate_pps=100
    data.vlan = random_vlan_list()[0]
    data.vlan_1 = random_vlan_list()[0]
    data.tagged_members = [vars.D1T1P1, vars.D1T1P3]
    data.tagged_members_1 = [vars.D1T1P2, vars.D1T1P3]
    data.aging_time = 20
    data.age_out_mac_addr = "00:00:00:00:00:09"
    data.vlan_id = str(random_vlan_list()[0])
    data.mac_addr_cnt = 2
    data.tg_con_interface = [vars.D1T1P1,vars.D1T1P2,vars.D1T1P3]

    if not skip_tg:
        tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
        tg2, tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
        tg3, tg_ph_3 = tgapi.get_handle_byname("T1D1P3")
        data.port_hand_list = [tg_ph_1,tg_ph_2,tg_ph_3]
    else:
        vars.D1T1P1 = st.get_free_ports(vars.D1)[0]
        vars.D1T1P2 = st.get_free_ports(vars.D1)[1]
        vars.D1T1P3 = st.get_free_ports(vars.D1)[2]

    if sub_test_6:
        st.log("#"*40)
        st.log("############# Sub test 6: test_base_line_l2_forwarding_with_untagged - START  ################")
        st.log("#"*40)


        st.log('Clearing the DUT counters.')
        intf_obj.clear_interface_counters(vars.D1)

        st.log("Create and configure Vlan and adding member as untagged members.")
        vlan_obj.create_vlan(vars.D1, data.vlan_id)
        vlan_obj.add_vlan_member(vars.D1, data.vlan_id, data.tg_con_interface, False)
        assert vlan_obj.verify_vlan_config(vars.D1, data.vlan_id, untagged=data.tg_con_interface), \
            st.report_fail("vlan_tagged_member_fail", data.tg_con_interface, data.vlan_id)

        st.log("Creating the traffic streams..")
        tg1.tg_traffic_control(action='reset',port_handle=data.port_hand_list)
        tg1.tg_traffic_control(action='clear_stats',port_handle=data.port_hand_list)
        s3 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=data.rate_pps, mac_src=data.source_mac,
                                   mac_src_mode="increment",
                                   mac_src_count=data.mac_addr_cnt, transmit_mode="continuous",
                                   mac_src_step="00:00:00:00:00:01", mac_dst=data.destination_mac,
                                   mac_dst_mode="increment",
                                   mac_dst_count=data.mac_addr_cnt, mac_dst_step="00:00:00:00:00:01",
                                   l2_encap='ethernet_ii_vlan',
                                   vlan_id=data.vlan_id, vlan="enable")['stream_id']
        s4 = tg2.tg_traffic_config(port_handle=tg_ph_2, rate_pps=data.rate_pps, mac_src=data.destination_mac,
                                   mac_src_mode="increment", mode='create',
                                   mac_src_count=data.mac_addr_cnt, transmit_mode="continuous",
                                   mac_src_step="00:00:00:00:00:01", mac_dst=data.source_mac, mac_dst_mode="increment",
                                   mac_dst_count=data.mac_addr_cnt, mac_dst_step="00:00:00:00:00:01",
                                   l2_encap='ethernet_ii_vlan', vlan_id=data.vlan_id, vlan="enable")['stream_id']

        st.log("Sending VLAN traffic and verifying the stats")
        tg1.tg_traffic_control(action='run',port_handle=[tg_ph_1,tg_ph_2])
        st.wait(data.post_wait_time_run)
        tg1.tg_traffic_control(action='stop',port_handle=[tg_ph_1,tg_ph_2])
        st.wait(data.post_wait_time_stop)
        stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
        total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
        total_rx_tg1 = int(stats_tg1['aggregate']['rx']['total_pkts']['max'])
        tx_tg1_95_precentage = (95*int(total_tx_tg1))/100

        stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
        total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
        total_tx_tg2 = int(stats_tg2['aggregate']['tx']['total_pkts']['max'])
        tx_tg2_95_precentage = (95 * int(total_tx_tg2)) / 100

        st.log('total_tx_tg1 = {}'.format(total_tx_tg1))
        st.log('tx_tg1_95_precentage = {}'.format(tx_tg1_95_precentage))
        st.log('total_rx_tg1 = {}'.format(total_rx_tg1))
        st.log('total_tx_tg2 = {}'.format(total_tx_tg2))
        st.log('tx_tg2_95_precentage = {}'.format(tx_tg2_95_precentage))
        st.log('total_rx_tg2 = {}'.format(total_rx_tg2))

        assert tx_tg1_95_precentage <= total_rx_tg2, st.report_fail("traffic_verification_failed")
        assert tx_tg2_95_precentage <= total_rx_tg1, st.report_fail("traffic_verification_failed")
        st.log("Traffic test passed..")

        st.log("Debug prints.....")
        asicapi.dump_vlan(vars.D1)
        asicapi.dump_l2(vars.D1)
        asicapi.dump_trunk(vars.D1)

        st.log("Validating MAC table..")
        dut1_mac_address_list_1 = utils_obj.get_mac_address(data.source_mac,start=0,end=data.mac_addr_cnt)
        #dut1_mac_address_list_2 = utils_obj.get_mac_address(data.destination_mac,start=0,end=data.mac_addr_cnt)
        #complete_mac_address_list = dut1_mac_address_list_1 + dut1_mac_address_list_2

        assert mac_obj.verify_mac_address(vars.D1, data.vlan_id, dut1_mac_address_list_1), \
            st.report_fail("mac_address_verification_fail")
        st.log("MAC table validation passed..")


        st.log("#"*40)
        st.log("############# Sub test 6: test_base_line_l2_forwarding_with_untagged - END  ################")
        st.log("#"*40)


    if sub_test_7:
        st.log("#"*40)
        st.log("############# Sub test 7: test_base_line_l2_forwarding_with_tagged - START  ################")
        st.log("#"*40)

        st.log("Test clears the vlan config ..")
        vlan_obj.clear_vlan_configuration(vars.D1)

        st.log("Create and configure Vlan and adding member as tagged members.")
        vlan_obj.create_vlan(vars.D1, data.vlan_id)
        vlan_obj.add_vlan_member(vars.D1, data.vlan_id, data.tg_con_interface, True)
        assert vlan_obj.verify_vlan_config(vars.D1, data.vlan_id, tagged=data.tg_con_interface), \
            st.report_fail("vlan_tagged_member_fail", data.tg_con_interface, data.vlan_id)

        st.log("Sending VLAN tagged traffic and verifying the stats")
        tg2.tg_packet_control(action='start',port_handle=[tg_ph_2])
        tg1.tg_traffic_control(action='run', stream_handle=[s3, s4])
        st.wait(data.post_wait_time_run)
        tg1.tg_traffic_control(action='stop', stream_handle=[s3, s4])
        tg2.tg_packet_control(action='stop')
        st.wait(data.post_wait_time_run)
        stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
        total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
        total_rx_tg1 = int(stats_tg1['aggregate']['rx']['total_pkts']['max'])
        tx_tg1_95_precentage = (95 * int(total_tx_tg1)) / 100

        stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
        total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
        total_tx_tg2 = int(stats_tg2['aggregate']['tx']['total_pkts']['max'])
        tx_tg2_95_precentage = (95 * int(total_tx_tg2)) / 100

        st.log('total_tx_tg1 = {}'.format(total_tx_tg1))
        st.log('tx_tg1_95_precentage = {}'.format(tx_tg1_95_precentage))
        st.log('total_rx_tg1 = {}'.format(total_rx_tg1))
        st.log('total_tx_tg2 = {}'.format(total_tx_tg2))
        st.log('tx_tg2_95_precentage = {}'.format(tx_tg2_95_precentage))
        st.log('total_rx_tg2 = {}'.format(total_rx_tg2))

        assert tx_tg1_95_precentage <= total_rx_tg2, st.report_fail("traffic_verification_failed")
        assert tx_tg2_95_precentage <= total_rx_tg1, st.report_fail("traffic_verification_failed")
        st.log("Traffic test passed..")

        st.log("Debug prints.....")
        asicapi.dump_vlan(vars.D1)
        asicapi.dump_l2(vars.D1)
        asicapi.dump_trunk(vars.D1)


        st.log("Validating MAC table..")
        dut1_mac_address_list_1 = utils_obj.get_mac_address(data.source_mac, start=0, end=data.mac_addr_cnt)
        #dut1_mac_address_list_2 = utils_obj.get_mac_address(data.destination_mac, start=0, end=data.mac_addr_cnt)
        #complete_mac_address_list = dut1_mac_address_list_1 + dut1_mac_address_list_2

        assert mac_obj.verify_mac_address(vars.D1, data.vlan_id, dut1_mac_address_list_1), \
            st.report_fail("mac_address_verification_fail")
        st.log("MAC table validation passed..")


        st.log("#"*40)
        st.log("############# Sub test 7: test_base_line_l2_forwarding_with_tagged - END  ################")
        st.log("#"*40)


    if sub_test_8:

        st.log("#"*40)
        st.log("############# Sub test 8: test_base_line_vlan_create_delete_with_bum and test_base_line_mac_learning_with_bum - START  ################")
        st.log("#"*40)

        st.log("Create and configure Vlan and adding member as tagged members.")
        vlan_obj.create_vlan(vars.D1, data.vlan)
        vlan_obj.add_vlan_member(vars.D1, data.vlan, data.tg_con_interface, True)
        assert vlan_obj.verify_vlan_config(vars.D1, data.vlan, tagged=data.tg_con_interface), \
            st.report_fail("vlan_tagged_member_fail", data.tg_con_interface, data.vlan)

        if not skip_tg:

            st.log("Start testing the bum traffic ...")
            mac_addr_list = [data.broacast_mac, data.multicast_mac, data.unknown_mac]

            mac_addr_list = {"Broadcast":data.broacast_mac,"Multicast": data.multicast_mac,"Unknown": data.unknown_mac}
            mac_incr_cnt = 7
            final_total_tx_tg1 =0

            st.log("Clearing TG config ")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)

            for mac_addr in mac_addr_list:
                st.log("Start '{}' traffic test with destination MAC = {}".format(mac_addr,mac_addr_list[mac_addr]))
                new_src_mac = "00:00:00:00:09:4{}".format(mac_incr_cnt)
                if not skip_tg:
                    st.log("Reseting and creating the traffic stream.")
                    tg1.tg_traffic_control(port_handle=tg_ph_1 ,action='reset')
                    s5 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=data.rate_pps,
                                               mac_src=new_src_mac,
                                               transmit_mode="continuous", mac_dst=mac_addr_list[mac_addr],
                                               l2_encap='ethernet_ii_vlan',
                                               vlan_id=data.vlan, vlan="enable")['stream_id']

                    st.log("Sending traffic and verifying the stats")
                    tg1.tg_packet_control(action='start', port_handle=[tg_ph_2,tg_ph_3])
                    tg1.tg_traffic_control(handle=s5, action='run')
                    st.wait(data.post_wait_time_run)

                    tg1.tg_traffic_control(handle=s5, action='stop')
                    st.wait(data.post_wait_time_stop)

                    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode="aggregate")
                    total_tx_tg1 = int(stats_tg1['aggregate']['tx']['total_pkts']['max'])
                    final_total_tx_tg1 += total_tx_tg1
                    st.log("total_tx_tg1 = {}".format(total_tx_tg1))


                    # stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode="aggregate")
                    # total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
                    # stats_tg3 = tg3.tg_traffic_stats(port_handle=tg_ph_3,mode="aggregate")
                    # total_rx_tg3 = int(stats_tg3['aggregate']['rx']['total_pkts']['max'])
                    #
                    # st.log("total_tx_tg1 = {}".format(total_tx_tg1))
                    # st.log("tx_tg1_95_precentage = {}".format(tx_tg1_95_precentage))
                    # st.log("total_rx_tg2 = {}".format(total_rx_tg2))
                    # st.log("total_rx_tg3 = {}".format(total_rx_tg3))
                    #
                    # if not tx_tg1_95_precentage <= total_rx_tg2:
                    # 	st.report_fail("traffic_verification_failed")
                    # if not tx_tg1_95_precentage <= total_rx_tg3:
                    # 	st.report_fail("traffic_verification_failed")
                    # st.log("Traffic test passed..")

                    #print mac_obj.verify_mac_address_table(vars.D1,new_src_mac,port=vars.D1T1P1)
                    st.log('MAC address validation.')
                    if not mac_obj.verify_mac_address_table(vars.D1,new_src_mac,port=vars.D1T1P1):
                        st.log("MAC '{}' is failed to learn in port = {}".format(new_src_mac,vars.D1T1P1))
                        st.report_fail('mac_address_verification_fail')
                    st.log('MAC address validation passed.')

                mac_incr_cnt += 1

            tx_tg1_95_precentage = (95 * int(final_total_tx_tg1)) / 100
            stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode="aggregate")
            total_rx_tg2 = int(stats_tg2['aggregate']['rx']['total_pkts']['max'])
            stats_tg3 = tg3.tg_traffic_stats(port_handle=tg_ph_3,mode="aggregate")
            total_rx_tg3 = int(stats_tg3['aggregate']['rx']['total_pkts']['max'])

            st.log("final_total_tx_tg1 = {}".format(final_total_tx_tg1))
            st.log("tx_tg1_95_precentage = {}".format(tx_tg1_95_precentage))
            st.log("total_rx_tg2 = {}".format(total_rx_tg2))
            st.log("total_rx_tg3 = {}".format(total_rx_tg3))

            if not tx_tg1_95_precentage <= total_rx_tg2:
                st.report_fail("traffic_verification_failed")
            if not tx_tg1_95_precentage <= total_rx_tg3:
                st.report_fail("traffic_verification_failed")
            st.log("Traffic test passed..")

        st.log("#"*40)
        st.log("############# Sub test 8: test_base_line_vlan_create_delete_with_bum and test_base_line_mac_learning_with_bum - END  ################")
        st.log("#"*40)


    if sub_test_9:
        st.log("#"*40)
        st.log("############# Sub test 9: test_base_line_mac_learning_traffic - START  ################")
        st.log("#"*40)

        # st.log("Test clears the vlan config ..")
        # vlan_obj.clear_vlan_configuration(vars.D1)
        #
        # st.log("Create and configure Vlan and members.")
        # vlan_obj.create_vlan(vars.D1,data.vlan)
        # vlan_obj.add_vlan_member(vars.D1, data.vlan, data.tg_con_interface, False)
        # assert vlan_obj.verify_vlan_config(vars.D1, data.vlan, untagged=data.tg_con_interface), \
        # 	st.report_fail("vlan_tagged_member_fail", data.vlan, data.tg_con_interface)

        #Step 1
        #Test - Connect the IXIA ports to port1, Port2 and port3 of DUT as shown in the setup. Send continuous stream of rate 1 packet/Sec from IXIA1 with source Mac as """"000000000002"""".
        #Expected - FDB entry is made with the mac address """"000000000002"""" with the default age out time.
        st.log("Reseting ,creating and start the traffic stream on TG1.")
        tg1.tg_traffic_control(port_handle=tg_ph_1, action='reset')
        s6 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=1, mac_src='00:00:00:00:00:02',
                                   transmit_mode="continuous", mac_dst='00:00:00:00:00:22', l2_encap='ethernet_ii_vlan',
                                   vlan_id=data.vlan, vlan="enable")['stream_id']

        tg1.tg_traffic_control(handle=s6, action='run')
        st.wait(data.post_wait_time_run)

        tg1.tg_traffic_control(handle=s6, action='stop')
        st.wait(data.post_wait_time_stop)

        st.log("Validating MAC table..")
        #mac_entry = mac_obj.get_mac_all(vars.D1,data.vlan)
        #if mac_entry[0] != "00:00:00:00:00:02":
        if not mac_obj.verify_mac_address_table(vars.D1,"00:00:00:00:00:02",vlan=data.vlan):
            st.log("MAC {} is not fount in the mac table".format("00:00:00:00:00:02"))
            st.report_fail("mac_address_verification_fail")
        st.log("MAC table validation passed..")

        #Step 2
        #Test - Set bridge age time to 45 sec
        #Expected - The bridge ageout time is set to 45 sec.
        st.log('Configuring the MAC aging time')
        mac_obj.config_mac_agetime(vars.D1,45)
        retval = mac_obj.get_mac_agetime(vars.D1)
        if retval != 45:
            st.log("Failed to configure Mac aging time.")
            st.report_fail("mac_aging_time_failed_config")
        # st.wait(5)

        #Step 3
        #Test - Send packet continuous stream from IXIA2 to IXIA1 with src Mac as """"000000000001"""" and dst Mac as """"000000000002"""".
        #Expected - The traffic is unicasted to IXIA1 since FDB entry is there for reaching port1
        st.log("Reseting ,creating and start the traffic stream on TG2.")
        tg2.tg_traffic_control(port_handle=tg_ph_2, action='reset')
        s7 = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_pps=1, mac_src='00:00:00:00:00:01',
                                   transmit_mode="continuous", mac_dst='00:00:00:00:00:02', l2_encap='ethernet_ii_vlan',
                                   vlan_id=data.vlan, vlan="enable")['stream_id']

        #Step 4
        #Test - Check the Packets on port3 and port2 connected to IXIA1 and IXIA3
        #Expected - All packets should be received on Port1 connected to IXIA1. No packet should receive on the port P3 connected to IXIA3.
        tg1.tg_traffic_control(action='clear_stats',port_handle=data.port_hand_list)
        st.wait(data.post_wait_time_clear)

        tg1.tg_packet_control(action='start', port_handle=[tg_ph_1,tg_ph_3])

        tg2.tg_traffic_control(action='run', handle=s7)
        st.wait(data.post_wait_time_run)

        tg2.tg_traffic_control(action='stop', handle=s7)
        st.wait(data.post_wait_time_stop)

        stats1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
        total_rx1 = int(stats1['aggregate']['rx']['total_pkts']['max'])
        stats2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
        total_tx = int(stats2['aggregate']['tx']['total_pkts']['max'])
        stats3 = tg3.tg_traffic_stats(port_handle=tg_ph_3,mode='aggregate')
        total_rx3 = int(stats3['aggregate']['rx']['total_pkts']['max'])
        st.log("Sent Packets On Port 2: {} and Received Packets On Port 1: {} and Received Packets On Port 3: {}".format(total_tx, total_rx1, total_rx3))


        # stats verification
        if (int(total_tx) != 0) and (int(total_rx1) < int(total_tx) or int(total_rx3) >= int(total_tx)):
            st.log("Traffic verification failed : Traffic is forwarding to port which is not learnt in the mac table")
            st.report_fail("traffic_verification_failed")
        elif int(total_tx) == 0:
            st.log("Traffic verification failed: Traffic not initiated from IXIA.")
            st.report_fail("operation_failed")
        st.log("Traffic test passed..")

        st.log("#"*40)
        st.log("############# Sub test 9: test_base_line_mac_learning_traffic - END  ################")
        st.log("#"*40)

    if sub_test_10:

        ### TODO : Remove

        # st.log("Create and configure Vlan and adding member as tagged members.")
        # vlan_obj.create_vlan(vars.D1, data.vlan)
        # vlan_obj.add_vlan_member(vars.D1, data.vlan, data.tg_con_interface, True)
        # assert vlan_obj.verify_vlan_config(vars.D1, data.vlan, tagged=data.tg_con_interface), \
        # 	st.report_fail("vlan_tagged_member_fail", data.tg_con_interface, data.vlan)
        #



        st.log("#"*40)
        st.log("############# Sub test 10: test_base_line_mac_move_single_vlan - START  ################")
        st.log("#"*40)
        st.log("Clearing the MAC table entries.")
        mac_obj.clear_mac(vars.D1)
        st.wait(data.clear_mac_table_wait_time)
        st.log("Configuring the mac aging time - {}".format(0))
        mac_obj.config_mac_agetime(vars.D1, 0)
        if not skip_tg:
            # Step 2
            # Test - Start sending traffic from port 1 with mac address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1.
            st.log("Reseting ,creating and start the traffic stream on TG1.")
            tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
            s8 = tg1.tg_traffic_config(port_handle=tg_ph_1,mode='create', rate_pps=1, mac_src='00:00:00:00:11:11', transmit_mode="continuous",
                                  mac_dst='00:00:00:00:00:22', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")['stream_id']
            st.wait(data.post_wait_time_create)
            tg1.tg_traffic_control(action='run', handle=s8)
            st.wait(data.post_wait_time_run)

            st.log("Validating MAC table..")
            #mac_entry = mac_obj.get_mac_all_intf(vars.D1, vars.D1T1P1)
            #if mac_entry[0] != "00:00:00:00:11:11":
            if not mac_obj.verify_mac_address_table(vars.D1,"00:00:00:00:11:11",vlan=data.vlan):
                st.report_fail("mac_address_verification_fail")
            tg1.tg_traffic_control(action='stop', handle=s8)
            st.wait(data.post_wait_time_stop)

            # Step 3
            # Test - Now start sending traffic from port 2 with same MAC address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1 flushed out and learned on port 2"
            st.log("Reseting ,creating and start the traffic stream on TG2.")
            tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
            s9 = tg2.tg_traffic_config(port_handle=tg_ph_2,mode='create', rate_pps=1, mac_src='00:00:00:00:11:11', transmit_mode="continuous",
                                  mac_dst='00:00:00:00:00:22', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")['stream_id']
            st.wait(data.post_wait_time_create )
            tg2.tg_traffic_control(action='run', handle=s9)
            st.wait(data.post_wait_time_run)

            st.log("Validating MAC table..")
            mac_entry = mac_obj.get_mac_all_intf(vars.D1, vars.D1T1P1)
            if "00:00:00:00:11:11" in mac_entry:
                st.report_fail("failed_clear_mac_learned_on_port", 'first')

            mac_entry = mac_obj.get_mac_all_intf(vars.D1, vars.D1T1P2)
            if "00:00:00:00:11:11" not in mac_entry:
                st.report_fail("failed_to_learn_mac_after_move")

            tg2.tg_traffic_control(action='stop', handle=s9)
            st.wait(data.post_wait_time_stop)


            # Sending traffic to check if mac has moved or not.
            st.log("Reseting ,creating and start the traffic stream on TG3.")
            tg3.tg_traffic_control(action='reset',port_handle= tg_ph_3)
            s10 = tg3.tg_traffic_config(port_handle= tg_ph_3,mode='create', rate_pps=100, mac_dst='00:00:00:00:11:11', transmit_mode="continuous",
                                  mac_src='00:00:00:00:00:33', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")['stream_id']
            st.wait(data.post_wait_time_create)
            tg1.tg_traffic_control(action='clear_stats',port_handle= data.port_hand_list)
            st.wait(data.post_wait_time_clear)
            tg1.tg_packet_control(action='start',port_handle= [tg_ph_1,tg_ph_2])
            st.wait(data.post_wait_time_create)

            tg3.tg_traffic_control(action='run', handle=s10)
            st.wait(data.post_wait_time_run)
            tg3.tg_traffic_control(action='stop', handle=s10)
            tg1.tg_packet_control(action='stop',port_handle= [tg_ph_1,tg_ph_2])
            st.wait(data.post_wait_time_stop)

            # stats fetching
            stats1 = tg1.tg_traffic_stats(port_handle=tg_ph_1, mode='aggregate')
            total_rx1 = int(stats1['aggregate']['rx']['total_pkts']['max'])

            stats2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx2 = int(stats2['aggregate']['rx']['total_pkts']['max'])

            stats3 = tg3.tg_traffic_stats(port_handle=tg_ph_3,mode='aggregate')
            total_tx3 = int(stats3['aggregate']['tx']['total_pkts']['max'])

            st.log("Sent Packets On Port 3: {} and Received Packets On Port 1: {} and Received Packets On Port 2: {}".format(
                total_tx3, total_rx1, total_rx2))


            if total_tx3 == 0:
                st.log("Traffic verification failed: Traffic not initiated from IXIA TG3.")
                st.report_fail("traffic_verification_failed")

            ## This is for allowance towards control packets like LLDP etc..
            if (total_rx1 > 10):
                st.log("Traffic verification failed : Traffic should not be received on TG1, but received.")
                st.report_fail("traffic_verification_failed")

            if (total_rx2 < total_tx3):

                st.log("Traffic verification failed : Traffic from TG3 not fully received on TG2.")
                st.report_fail("traffic_verification_failed")

            st.log("Traffic test passed..")

        st.log("#"*40)
        st.log("############# Sub test 10: test_base_line_mac_move_single_vlan - END  ################")
        st.log("#"*40)

    if sub_test_11:

        ### TODO : Remove

        # st.log("Create and configure Vlan and adding member as tagged members.")
        # vlan_obj.create_vlan(vars.D1, data.vlan)
        # vlan_obj.add_vlan_member(vars.D1, data.vlan, data.tg_con_interface, True)
        # assert vlan_obj.verify_vlan_config(vars.D1, data.vlan, tagged=data.tg_con_interface), \
        # 	st.report_fail("vlan_tagged_member_fail", data.tg_con_interface, data.vlan)



        st.log("#"*40)
        st.log("############# Sub test 11: test_base_line_mac_move_across_vlans - START  ################")
        st.log("#"*40)

        # st.log("Test clears the vlan config ..")
        # vlan_obj.clear_vlan_configuration(vars.D1)

        # Step 1
        # Test - Configure VLAN 100 DUT and include two ports in VLAN 100
        # Expected - Verify that the configuration is successful
        st.log("Creating vlan config ")
        # vlan_obj.create_vlan(vars.D1, data.vlan)
        # vlan_obj.add_vlan_member(vars.D1, data.vlan, data.tagged_members, True)

        vlan_obj.create_vlan(vars.D1, data.vlan_1)
        vlan_obj.add_vlan_member(vars.D1, data.vlan_1, data.tagged_members_1, True)

        # if not vlan_obj.verify_vlan_config(vars.D1, data.vlan, tagged=data.tagged_members):
        # 	st.report_fail("vlan_tagged_member_fail", data.tagged_members, data.vlan)
        if not vlan_obj.verify_vlan_config(vars.D1, data.vlan_1, tagged=data.tagged_members_1):
            st.report_fail("vlan_tagged_member_fail", data.tagged_members_1, data.vlan_1)

        mac_obj.clear_mac(vars.D1)
        st.wait(data.clear_mac_table_wait_time)
        mac_obj.config_mac_agetime(vars.D1, 0)
        if not skip_tg:
            # Step 2
            # Test - Start sending traffic from port 1 with mac address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1.
            tg1.tg_traffic_control(action='reset',port_handle= tg_ph_1)
            s11 = tg1.tg_traffic_config(port_handle= tg_ph_1,mode='create', rate_pps=1, mac_src='00:00:00:00:11:11', transmit_mode="continuous",
                                  mac_dst='00:00:00:00:00:22', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")['stream_id']
            st.wait(data.post_wait_time_create)
            tg1.tg_traffic_control(action='run', handle=s11)
            st.wait(data.post_wait_time_run)

            mac_entry = mac_obj.get_mac_all_intf(vars.D1, vars.D1T1P1)
            if "00:00:00:00:11:11" not in mac_entry:
                st.report_fail("mac_failed_to_learn_on_firt_port")
            tg1.tg_traffic_control(action='stop', handle=s11)

            # Step 3
            # Test - Now start sending traffic from port 2 with same MAC address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1 flushed out and learned on port 2"
            tg2.tg_traffic_control(action='reset',port_handle= tg_ph_2)
            s12 = tg2.tg_traffic_config(port_handle= tg_ph_2,mode='create', rate_pps=1, mac_src='00:00:00:00:11:11', transmit_mode="continuous",
                                  mac_dst='00:00:00:00:00:22', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan_1, vlan="enable")['stream_id']
            st.wait(data.post_wait_time_create)
            tg2.tg_traffic_control(action='run', stream_handle=s12)
            st.wait(data.post_wait_time_run)

            mac_entry = mac_obj.get_mac_all_intf(vars.D1, vars.D1T1P1)
            if "00:00:00:00:11:11" not in mac_entry:
                st.report_fail("mac_address_not_clear")

            mac_entry = mac_obj.get_mac_all_intf(vars.D1, vars.D1T1P2)
            if "00:00:00:00:11:11" not in mac_entry:
                st.report_fail("mac_failed_to_learn_on_second_port")

            tg2.tg_traffic_control(action='stop', stream_handle=s12)

            # Sending traffic to check if mac has moved or not.
            tg3.tg_traffic_control(action='reset',port_handle=tg_ph_3)
            s13 = tg3.tg_traffic_config(port_handle=tg_ph_3,mode='create', rate_pps=10, mac_dst='00:00:00:00:11:11', transmit_mode="continuous",
                                  mac_src='00:00:00:00:00:33', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")['stream_id']
            st.wait(data.post_wait_time_create )
            tg1.tg_traffic_control(action='clear_stats',port_handle=data.port_hand_list)
            # st.wait(data.post_wait_time_clear)
            st.wait(data.post_wait_time_clear)
            tg1.tg_packet_control(action='start',port_handle=[tg_ph_1,tg_ph_2])

            tg3.tg_traffic_control(action='run', stream_handle=s13)
            st.wait(data.post_wait_time_run)
            tg3.tg_traffic_control(action='stop', stream_handle=s13)
            tg1.tg_packet_control(action='stop',port_handle=[tg_ph_1,tg_ph_2])
            st.wait(data.post_wait_time_stop)

            # stats fetching
            stats1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
            total_rx1 = int(stats1['aggregate']['rx']['total_pkts']['max'])

            stats2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx2 = int(stats2['aggregate']['rx']['total_pkts']['max'])

            stats3 = tg3.tg_traffic_stats(port_handle=tg_ph_3,mode='aggregate')
            total_tx3 = int(stats3['aggregate']['tx']['total_pkts']['max'])

            st.log("Sent Packets On Port 3: {} and Received Packets On Port 1: {} and Received Packets On Port 2: {}".format(
                total_tx3, total_rx1, total_rx2))

            # stats verification
            # if (total_tx3 != 0) and (total_rx1 < total_tx3 or total_rx2 >= total_tx3):
            # 	st.log("Traffic verification failed : Traffic is forwarding to port which is not learnt in the mac table")
            # 	st.report_fail("traffic_verification_failed")
            #
            # elif total_tx3 == 0:
            # 	st.log("Traffic verification failed: Traffic not initiated from IXIA.")
            # 	st.report_fail("traffic_verification_failed")
            #



            if total_tx3 == 0:
                st.log("Traffic verification failed: Traffic not initiated from IXIA TG3.")
                st.report_fail("traffic_verification_failed")

            ## This is for allowance towards control packets like LLDP etc..
            if (total_rx2 > 10):
                st.log("Traffic verification failed : Traffic should not be received on TG2, but received.")
                st.report_fail("traffic_verification_failed")

            if (total_rx1 < total_tx3):

                st.log("Traffic verification failed : Traffic from TG3 not fully received on TG1.")
                st.report_fail("traffic_verification_failed")

            st.log("Traffic test passed..")


            # Sending traffic to check if mac has moved or not.
            tg1.tg_traffic_control(action='clear_stats',port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)
            # st.wait(data.post_wait_time_clear)
            tg1.tg_packet_control(action='start', port_handle=[tg_ph_1,tg_ph_2])

            tg3.tg_traffic_control(action='reset',port_handle=tg_ph_3)
            s14 = tg3.tg_traffic_config(port_handle=tg_ph_3,mode='create', rate_pps=10, mac_dst='00:00:00:00:11:11', transmit_mode="continuous",
                                  mac_src='00:00:00:00:00:33', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan_1, vlan="enable")['stream_id']
            st.wait(data.post_wait_time_create)
            tg3.tg_traffic_control(action='run', stream_handle=s14)
            st.wait(data.post_wait_time_run)
            tg3.tg_traffic_control(action='stop', stream_handle=s14)
            tg1.tg_packet_control(action='stop',port_handle=[tg_ph_1,tg_ph_2])
            st.wait(data.post_wait_time_stop)

            # stats fetching
            stats1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
            total_rx1 = int(stats1['aggregate']['rx']['total_pkts']['max'])

            stats2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
            total_rx2 = int(stats2['aggregate']['rx']['total_pkts']['max'])

            stats3 = tg3.tg_traffic_stats(port_handle=tg_ph_3,mode='aggregate')
            total_tx3 = int(stats3['aggregate']['tx']['total_pkts']['max'])

            st.log("Sent Packets On Port 3: {} and Received Packets On Port 1: {} and Received Packets On Port 2: {}".format(
                total_tx3, total_rx1, total_rx2))

            # stats verification
            # if (total_tx3 != 0) and (total_rx2 < total_tx3 or total_rx1 >= total_tx3):
            # 	st.log("Traffic verification failed : Traffic is forwarding to port which is not learnt in the mac table")
            # 	st.report_fail("traffic_verification_failed")
            #
            # elif total_tx3 == 0:
            # 	st.log("Traffic verification failed: Traffic not initiated from IXIA.")
            # 	st.report_fail("traffic_verification_failed")

            if total_tx3 == 0:
                st.log("Traffic verification failed: Traffic not initiated from IXIA TG3.")
                st.report_fail("traffic_verification_failed")

            ## This is for allowance towards control packets like LLDP etc..
            if (total_rx1 > 10):
                st.log("Traffic verification failed : Traffic should not be received on TG1, but received.")
                st.report_fail("traffic_verification_failed")

            if (total_rx2 < total_tx3):

                st.log("Traffic verification failed : Traffic from TG3 not fully received on TG2.")
                st.report_fail("traffic_verification_failed")

            st.log("Traffic test passed..")

        st.log("#"*40)
        st.log("############# Sub test 11: test_base_line_mac_move_across_vlans - END  ################")
        st.log("#"*40)


    if sub_test_12:

        st.log("#"*40)
        st.log("############# Sub test 12: test_base_line_mac_aging - START  ################")
        st.log("#"*40)

        mac_obj.clear_mac(vars.D1)
        st.wait(data.clear_mac_table_wait_time)

        # configure FDB ageout time and Validate
        mac_obj.config_mac_agetime(vars.D1, data.aging_time)
        retval = mac_obj.get_mac_agetime(vars.D1)
        if retval != data.aging_time:
            st.log("Failed to configure Mac aging time.")
            st.report_fail("mac_aging_time_failed_config")


        # Expected - FDB entry is made with the mac address """"000000000002"""" with the non default mac age out time 60 sec.
        tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
        s15 = tg1.tg_traffic_config(port_handle=tg_ph_1,mode='create', rate_pps=1, mac_src=data.age_out_mac_addr, transmit_mode="continuous",
                              mac_dst='00:00:00:00:00:22', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")['stream_id']
        st.wait(data.post_wait_time_create)
        tg1.tg_traffic_control(action='run', stream_handle=s15)
        st.wait(data.post_wait_time_run)
        tg1.tg_traffic_control(action='stop', stream_handle=s15)


        if not mac_obj.verify_mac_address(vars.D1,data.vlan,data.age_out_mac_addr):
            st.report_fail("mac_address_verification_fail")

        st.log("Waiting for {} secs ,for MAC ageout".format(data.aging_time))
        st.wait(data.aging_time)
        iteration  = 1
        while True:
            if not mac_obj.verify_mac_address(vars.D1, data.vlan, data.age_out_mac_addr):
                st.log("Mac age is succesfull.")
                break
            if iteration > data.aging_time:
                st.report_fail("failed_to_clear_mac_after_ageout")
            st.wait(1)
            iteration +=1

        st.log("#"*40)
        st.log("############# Sub test 12: test_base_line_mac_aging - END  ################")
        st.log("#"*40)

    st.report_pass("test_case_passed")

