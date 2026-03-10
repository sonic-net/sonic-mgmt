import pytest

from spytest import st, tgapi, SpyTestDict

import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import utilities.utils as utils_obj
import apis.system.interface as intf_obj
import apis.common.asic as asicapi
import apis.routing.ip as ip_obj
from utilities.common import filter_and_select, sprint_vtable, random_vlan_list, make_list

@pytest.fixture(scope="module", autouse=True)
def sanity_l2_module_hooks(request):
    st.ensure_min_topology("D1D2:4", "D1T1:3", "D2T1:1")
    yield

@pytest.fixture(scope="function", autouse=True)
def sanity_l2_func_hooks(request):
    yield

base_line_final_result = {
    'test_base_line_portchannel_create_delete': 'NA',
    'test_base_line_random_link_flap_portchannel': 'NA',
    'test_base_line_l2_taggged_forwarding_with_portchannel': 'NA',
    'test_base_line_vlan_port_association': 'NA',
    'test_base_line_port_move_from_vlan_a_to_vlan_b': 'NA',
    'test_base_line_vlan_create_delete_and_mac_learning_with_bum': 'NA',
    'test_base_line_mac_move_single_vlan': 'NA',
    'test_base_line_mac_move_across_vlans': 'NA'
}

data = SpyTestDict()
data.vlan_id = str(random_vlan_list()[0])
data.portChannelName = "PortChannel5"
data.mac_addr_cnt = 100
data.source_mac = "00:00:02:00:00:01"
data.destination_mac = "00:00:01:00:00:01"
data.rate_pps = "100"
data.wait_post_port_channel_up = 10
data.clear_mac_table_wait_time = 3
data.post_wait_time_run = 5
data.post_wait_time_stop = 5
data.post_wait_time_clear = 1
data.post_wait_time_create = 2
data.clear_parallel = True

tg_info = dict()


def debug_cmds(dut_in=None):
    st.log("Debug prints.....")
    dut_list = dut_in or st.get_dut_names()
    for dut in make_list(dut_list):
        asicapi.dump_vlan(dut)
        asicapi.dump_l2(dut)
        asicapi.dump_trunk(dut)


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
@pytest.mark.community
@pytest.mark.community_pass
def test_base_line_portchannel_create_delete():

    vars = st.get_testbed_vars()
    # Sub test selection
    sub_test_1 = 1
    sub_test_2 = 1
    sub_test_3 = 1
    sub_test_4 = 1
    sub_test_5 = 1
    # Global and Topology variable
    data.mac_addr_cnt = 2
    data.no_of_port_channel_create_and_delete = 1
    data.post_link_shutdown_wait_time = 1
    data.dut2_lag_members = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    data.dut1_lag_members = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]

    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")

    data.port_hand_list = [tg_ph_1, tg_ph_2]

    intf_obj.clear_interface_counters(vars.D1)
    intf_obj.clear_interface_counters(vars.D2)
    topology = {vars.D1: {"ports": data.dut1_lag_members, "TGports": vars.D1T1P1},
                vars.D2: {"ports": data.dut2_lag_members, "TGports": vars.D2T1P1}}

    st.log("PRE TEST : Cleanup call are started.")
    ip_obj.clear_ip_configuration(st.get_dut_names(), thread=data.clear_parallel)
    ip_obj.clear_ip_configuration(st.get_dut_names(), 'ipv6', thread=data.clear_parallel)
    vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel)
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names(), thread=data.clear_parallel)

    st.log("Sending VLAN traffic and verifying the stats")
    tg1.tg_traffic_control(action='reset', port_handle=data.port_hand_list)
    tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
    rv = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=data.rate_pps, mac_src=data.source_mac,
                          mac_src_mode="increment",
                          mac_src_count=data.mac_addr_cnt, transmit_mode="continuous",
                          mac_src_step="00:00:00:00:00:01", mac_dst=data.destination_mac, mac_dst_mode="increment",
                          mac_dst_count=data.mac_addr_cnt, mac_dst_step="00:00:00:00:00:01",
                          l2_encap='ethernet_ii_vlan',
                          vlan_id=data.vlan_id, vlan="enable")
    tg_info['tg1_stream_id'] = rv['stream_id']
    rv_1 = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_pps=data.rate_pps, mac_src=data.destination_mac,
                          mac_src_mode="increment",
                          mac_src_count=data.mac_addr_cnt, transmit_mode="continuous",
                          mac_src_step="00:00:00:00:00:01", mac_dst=data.source_mac, mac_dst_mode="increment",
                          mac_dst_count=data.mac_addr_cnt, mac_dst_step="00:00:00:00:00:01",
                          l2_encap='ethernet_ii_vlan',
                          vlan_id=data.vlan_id, vlan="enable")
    tg_info['tg2_stream_id'] = rv_1['stream_id']
    stream_list = [tg_info['tg1_stream_id'], tg_info['tg2_stream_id']]
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        }
    }
    if sub_test_1:
        st.log("#"*90)
        st.log("############# Sub test 1: test_base_line_portchannel_create_delete - START  ################")
        st.log("#"*90)
        try:
            st.log("Verifying the oper status of ports and do shut and no shut - Initially")
            intf_obj.interface_noshutdown(vars.D1, topology[vars.D1]["ports"] + [topology[vars.D1]["TGports"]])
            intf_obj.interface_noshutdown(vars.D2, topology[vars.D2]["ports"] + [topology[vars.D2]["TGports"]])
            st.wait(5)
            for dut in topology:
                all_ports = topology[dut]["ports"] + [topology[dut]["TGports"]]
                for each_port in all_ports:
                    if not intf_obj.poll_for_interface_status(dut, each_port, 'oper', 'up', iteration=5, delay=1):
                        intf_obj.interface_shutdown(dut, each_port)
                        st.wait(data.post_link_shutdown_wait_time)
                        intf_obj.interface_noshutdown(dut, each_port)
                        if not intf_obj.poll_for_interface_status(dut, each_port, 'oper', 'up', iteration=5, delay=1):
                            st.error('{} interface is down on dut'.format(each_port))
                            assert False

            st.log("Config Vlan tagged and Port channel on both DUTs")
            for dut in topology:
                portchannel_obj.create_portchannel(dut, data.portChannelName)
                portchannel_obj.add_portchannel_member(dut, data.portChannelName, topology[dut]["ports"])
                vlan_obj.create_vlan(dut, data.vlan_id)
                vlan_obj.add_vlan_member(dut, data.vlan_id, [topology[dut]["TGports"], data.portChannelName], True)

                if not vlan_obj.verify_vlan_config(dut, data.vlan_id, tagged=[topology[dut]["TGports"],
                                                                              data.portChannelName]):
                    st.log("vlan tagged member fail on port {},vlan {}".format([topology[dut]["TGports"],
                                                                                data.portChannelName], data.vlan_id))
                    assert False

            st.log("Verifying the Port channel status - Initially")
            for dut in topology:
                if not portchannel_obj.verify_portchannel_and_member_status(dut, data.portChannelName,
                                                                            topology[dut]["ports"],
                                                                            iter_count=6, iter_delay=1, state='up'):
                    st.error("port channel {} on DUT {} state fail with {}".format(data.portChannelName, dut, "up"))
                    assert False

            for dut in topology:
                if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                    st.log("Port channel is not {}".format('up'))
                    st.error("port channel {} on dut {} state fail with {}".format(data.portChannelName, dut, "up"))
                    assert False
            st.wait(data.wait_post_port_channel_up)

            #Workaround added for intermittent issue seen on vSonic - when load on server is more
            if st.is_vsonic(vars.D1):
                st.log("Priming BCMSIM w/ traffic to enable mac learning")
                tg1.tg_traffic_control(action='run', stream_handle=stream_list)
                st.wait(data.post_wait_time_run)
                tg1.tg_traffic_control(action='stop', stream_handle=stream_list)
                st.wait(data.post_wait_time_stop)
                tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            #workaround end

            st.log("Sending VLAN traffic and verifying the stats")
            tg1.tg_traffic_control(action='run', stream_handle=stream_list)
            st.wait(data.post_wait_time_run)
            tg1.tg_traffic_control(action='stop', stream_handle=stream_list)

            if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                               comp_type='packet_count'):
                debug_cmds()
                st.report_fail("failed_traffic_verification")
            st.log("Traffic test passed..")
            st.log("Validating MAC table..")
            dut1_mac_address_list = utils_obj.get_mac_address(data.source_mac, start=0, end=data.mac_addr_cnt)
            dut2_mac_address_list = utils_obj.get_mac_address(data.destination_mac, start=0, end=data.mac_addr_cnt)
            complete_mac_address_list = dut1_mac_address_list + dut2_mac_address_list

            assert mac_obj.verify_mac_address(vars.D1, data.vlan_id, complete_mac_address_list), \
                st.log("mac_address_verification_fail")
            assert mac_obj.verify_mac_address(vars.D2, data.vlan_id, complete_mac_address_list), \
                st.log("mac_address_verification_fail")
            st.log("MAC table validation passed..")

            st.log("Start Creating and delete the Port channel")
            portchannel_list = []
            for i in range(6, data.no_of_port_channel_create_and_delete+6):
                portchannel_obj.create_portchannel(vars.D1, "PortChannel00{}".format(i))
                portchannel_obj.create_portchannel(vars.D2, "PortChannel00{}".format(i))
                portchannel_list.append("PortChannel00{}".format(i))
            dut1_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D1))
            assert int(dut1_portchannel_list) == int(data.no_of_port_channel_create_and_delete+1), \
                st.log("port channel count {} verification fail on port channel {}".format
                       (data.no_of_port_channel_create_and_delete+1, dut1_portchannel_list))
            dut2_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D2))
            assert int(dut2_portchannel_list ) == int(data.no_of_port_channel_create_and_delete+1), \
                st.log("port channel count {} verification fail on port channel {}".format
                       (data.no_of_port_channel_create_and_delete+1, dut2_portchannel_list))
            portchannel_obj.delete_portchannel(vars.D1, portchannel_list)
            portchannel_obj.delete_portchannel(vars.D2, portchannel_list)
            dut1_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D1))
            assert int(dut1_portchannel_list) == 1, \
                st.log("port channel count {} verification fail on port channel {}".format(1, dut1_portchannel_list))
            dut2_portchannel_list = len(portchannel_obj.get_portchannel_list(vars.D2))
            assert int(dut2_portchannel_list) == 1, \
                st.log("port channel count {} verification fail on port channel {}".format(1, dut2_portchannel_list))

            st.log("Traffic checking post port channel create and delete")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)
            tg1.tg_traffic_control(action='run', stream_handle=stream_list)
            st.wait(data.post_wait_time_run)
            tg1.tg_traffic_control(action='stop', stream_handle=stream_list)

            if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                               comp_type='packet_count'):
                debug_cmds()
                st.report_fail("failed_traffic_verification")

            st.log("Traffic test passed..")
            st.log("Sub test 1 : PASSED")
            base_line_final_result['test_base_line_portchannel_create_delete'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_portchannel_create_delete'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 1: test_base_line_portchannel_create_delete - END  ################")
        st.log("#"*90)

    if sub_test_2 and base_line_final_result['test_base_line_portchannel_create_delete'] == 'Pass':
        st.log("#"*90)
        st.log("############# Sub test 2: test_base_line_random_link_flap_portchannel  - START  ################")
        st.log("#"*90)
        try:
            st.log("Start performing the port channel member link flap")
            for i in range(1, 2):
                for interface in data.dut2_lag_members:
                    intf_obj.interface_shutdown(vars.D2, interface)
                    st.wait(3)
                    intf_obj.interface_noshutdown(vars.D2, interface)
            st.wait(2)
            st.log("Verifying the Port channel status - post flap members")
            for dut in topology:
                if not portchannel_obj.verify_portchannel_and_member_status(dut, data.portChannelName,
                                                                            topology[dut]["ports"],
                                                                            iter_count=6, iter_delay=1, state='up'):
                    st.error("port channel {} on DUT {} state fail with {}".format(data.portChannelName, dut, "up"))
                    assert False
            for dut in topology:
                if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                    st.log("Port channel is not {}".format('up'))
                    st.error("port channel {} on DUT {} state fail with {}".format(data.portChannelName, dut, "up"))
                    assert False

            st.log("Sub test 2 : PASSED")
            base_line_final_result['test_base_line_random_link_flap_portchannel'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_random_link_flap_portchannel'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 2: test_base_line_random_link_flap_portchannel  - END  ################")
        st.log("#"*90)

    if sub_test_3 and base_line_final_result['test_base_line_portchannel_create_delete'] == 'Pass':
        st.log("#"*90)
        st.log("############# Sub test 3: test_base_line_l2_taggged_forwarding_with_portchannel - START  "
               "################")
        st.log("#"*90)
        try:
            st.log("Verifying L2 tagged traffic forwarding on Port channel")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)
            tg1.tg_traffic_control(action='run', stream_handle=stream_list)
            st.wait(data.post_wait_time_run)
            tg1.tg_traffic_control(action='stop', stream_handle=stream_list)
            if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                               comp_type='packet_count'):
                debug_cmds()
                st.report_fail("failed_traffic_verification")
            st.log("Traffic test passed..")

            st.log("Sub test 3 : PASSED")
            base_line_final_result['test_base_line_l2_taggged_forwarding_with_portchannel'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_l2_taggged_forwarding_with_portchannel'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 3: test_base_line_l2_taggged_forwarding_with_portchannel - END "
               " ################")
        st.log("#"*90)

    if sub_test_4 and base_line_final_result['test_base_line_portchannel_create_delete'] == 'Pass':
        st.log("#"*90)
        st.log("############# Sub test 4: test_base_line_vlan_port_association - START  ################")
        st.log("#"*90)
        try:
            st.log("Test clears the vlan  config ..")
            vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel)

            st.log("Config Vlan and Port channel on both DUTs")
            for dut in topology:
                vlan_obj.create_vlan(dut, data.vlan_id)
                vlan_obj.add_vlan_member(dut, data.vlan_id, [topology[dut]["TGports"], data.portChannelName], True)
                if not vlan_obj.verify_vlan_config(dut, data.vlan_id, tagged=[topology[dut]["TGports"],
                                                                              data.portChannelName]):
                    st.log("vlan tagged member fail on port {} ,vlan {}".format([topology[dut]["TGports"],
                                                                                 data.portChannelName], data.vlan_id))
                    assert False

            st.log("Verifying the Port channel status")
            for dut in topology:
                if not portchannel_obj.verify_portchannel_and_member_status(dut, data.portChannelName,
                                                                            topology[dut]["ports"],
                                                                            iter_count=6, iter_delay=1, state='up'):
                    st.error("port channel {} on DUT {} state fail with {}".format(data.portChannelName, dut, "up"))
                    assert False
            for dut in topology:
                if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                    st.log("Port channel is not {}".format('up'))
                    st.error("port channel {} on DUT {} state fail with {}".format(data.portChannelName, dut, "up"))
                    assert False

            st.wait(data.wait_post_port_channel_up)
            st.log("Sending VLAN traffic and verifying the stats")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)
            tg1.tg_traffic_control(action='run', stream_handle=stream_list)
            st.wait(data.post_wait_time_run)
            tg1.tg_traffic_control(action='stop', stream_handle=stream_list)
            if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                               comp_type='packet_count'):
                debug_cmds()
                st.report_fail("failed_traffic_verification")
            st.log("Traffic test passed..")

            st.log("Validating MAC table..")
            dut1_mac_address_list = utils_obj.get_mac_address(data.source_mac, start=0, end=data.mac_addr_cnt)
            dut2_mac_address_list = utils_obj.get_mac_address(data.destination_mac, start=0, end=data.mac_addr_cnt)
            complete_mac_address_list = dut1_mac_address_list + dut2_mac_address_list

            if not mac_obj.verify_mac_address(vars.D1, data.vlan_id, complete_mac_address_list):
                st.log("mac_address_verification_fail")
                assert False
            if not mac_obj.verify_mac_address(vars.D2, data.vlan_id, complete_mac_address_list):
                st.log("mac_address_verification_fail")
                assert False
            st.log("MAC table validation passed..")

            st.log("Sub test 4 : PASSED")
            base_line_final_result['test_base_line_vlan_port_association'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_vlan_port_association'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 4: test_base_line_vlan_port_association - END  ################")
        st.log("#"*90)

    if sub_test_5 and base_line_final_result['test_base_line_portchannel_create_delete'] == 'Pass':
        st.log("#"*90)
        st.log("############# Sub test 5: test_base_line_port_move_from_vlan_a_to_vlan_b - START  ################")
        st.log("#"*90)
        try:
            st.log("Test clears the vlan  config ..")
            vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel)

            st.log("Config Vlan Untagged and Port-channel on both DUTs")
            for dut in topology:
                vlan_obj.create_vlan(dut, data.vlan_id)
                vlan_obj.add_vlan_member(dut, data.vlan_id, [topology[dut]["TGports"], data.portChannelName], False)
                if not vlan_obj.verify_vlan_config(dut, data.vlan_id, untagged=[topology[dut]["TGports"],
                                                                                data.portChannelName]):
                    st.log("vlan tagged member fail on port {} ,vlan {}".format([topology[dut]["TGports"],
                                                                                 data.portChannelName], data.vlan_id))
                    assert False

            st.log("Verifying the Port channel status")
            for dut in topology:
                if not portchannel_obj.verify_portchannel_and_member_status(dut, data.portChannelName,
                                                                            topology[dut]["ports"],
                                                                            iter_count=6, iter_delay=1, state='up'):
                    st.log("port channel {} on DUT {} state fail with {}".format(data.portChannelName, dut, "up"))
            for dut in topology:
                if not portchannel_obj.verify_portchannel_state(dut, data.portChannelName, 'up'):
                    st.log("Port channel is not {}".format('up'))
                    st.log("port channel {} on DUT {} state fail with {}".format(data.portChannelName, dut, "up"))
            st.wait(data.wait_post_port_channel_up)

            st.log("Sending VLAN traffic and verifying the stats")
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)
            tg1.tg_traffic_control(action='run', stream_handle=stream_list)
            st.wait(data.post_wait_time_run)
            tg1.tg_traffic_control(action='stop', stream_handle=stream_list)
            if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                               comp_type='packet_count'):
                debug_cmds()
                st.report_fail("failed_traffic_verification")
            st.log("Traffic test passed..")

            st.log("Validating MAC table..")
            dut1_mac_address_list = utils_obj.get_mac_address(data.source_mac, start=0, end=data.mac_addr_cnt)
            dut2_mac_address_list = utils_obj.get_mac_address(data.destination_mac, start=0, end=data.mac_addr_cnt)
            complete_mac_address_list = dut1_mac_address_list + dut2_mac_address_list

            if not mac_obj.verify_mac_address(vars.D1, data.vlan_id, complete_mac_address_list):
                st.log("mac_address_verification_fail")
                assert False
            if not mac_obj.verify_mac_address(vars.D2, data.vlan_id, complete_mac_address_list):
                st.log("mac_address_verification_fail")
                assert False
            st.log("MAC table validation passed..")

            st.log("Sub test 5 : PASSED")
            base_line_final_result['test_base_line_port_move_from_vlan_a_to_vlan_b'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_port_move_from_vlan_a_to_vlan_b'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 5: test_base_line_port_move_from_vlan_a_to_vlan_b - END  ################")
        st.log("#"*90)

    # Result printing
    st.log(sprint_vtable(['Test', 'Result'],
                         [[k, v] for k, v in filter_and_select([base_line_final_result],
                                                               ['test_base_line_portchannel_create_delete',
                                                                'test_base_line_random_link_flap_portchannel',
                                                                'test_base_line_l2_taggged_forwarding_with_portchannel',
                                                                'test_base_line_vlan_port_association',
                                                                'test_base_line_port_move_from_vlan_a_to_vlan_b']
                                                               )[0].items()], 0))

    st.log("POST TEST : Cleanup call are started.")
    ip_obj.clear_ip_configuration(st.get_dut_names(), thread=data.clear_parallel)
    ip_obj.clear_ip_configuration(st.get_dut_names(), 'ipv6', thread=data.clear_parallel)
    vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel)
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names(), thread=data.clear_parallel)

    out = base_line_final_result['test_base_line_portchannel_create_delete']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
@pytest.mark.depends("test_base_line_portchannel_create_delete")
@pytest.mark.community
@pytest.mark.community_pass
def test_base_line_random_link_flap_portchannel():
    out = base_line_final_result['test_base_line_random_link_flap_portchannel']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
@pytest.mark.depends("test_base_line_portchannel_create_delete")
@pytest.mark.community
@pytest.mark.community_pass
def test_base_line_l2_taggged_forwarding_with_portchannel():
    out = base_line_final_result['test_base_line_l2_taggged_forwarding_with_portchannel']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
@pytest.mark.depends("test_base_line_portchannel_create_delete")
@pytest.mark.community
@pytest.mark.community_pass
def test_base_line_vlan_port_association():
    out = base_line_final_result['test_base_line_vlan_port_association']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
@pytest.mark.depends("test_base_line_portchannel_create_delete")
def test_base_line_port_move_from_vlan_a_to_vlan_b():
    out = base_line_final_result['test_base_line_port_move_from_vlan_a_to_vlan_b']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
def test_base_line_vlan_create_delete_and_mac_learning_with_bum():

    vars = st.get_testbed_vars()
    # Sub test selection
    sub_test_8 = 1
    sub_test_10 = 1
    sub_test_11 = 1
    # Global and Topology variable
    data.vlan_id_start = 101
    data.vlan_id_end = 101
    data.vlan_range = (data.vlan_id_end-data.vlan_id_start) + 1
    data.multicast_mac = "01:00:5E:00:00:07"
    data.broacast_mac = "FF:FF:FF:FF:FF:FF"
    data.unknown_mac = "00:01:02:03:04:05"
    data.source_mac = "00:56:78:98:09:45"
    data.destination_mac = "00:56:78:98:10:55"
    data.rate_pps = 100
    data.vlan = random_vlan_list()[0]
    data.vlan_1 = random_vlan_list()[0]
    data.tagged_members = [vars.D1T1P1, vars.D1T1P3]
    data.tagged_members_1 = [vars.D1T1P2, vars.D1T1P3]
    data.aging_time = 20
    data.age_out_mac_addr = "00:00:00:00:00:09"
    data.vlan_id = str(random_vlan_list()[0])
    data.mac_addr_cnt = 2
    data.tg_con_interface = [vars.D1T1P1, vars.D1T1P2, vars.D1T1P3]

    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    tg3, tg_ph_3 = tgapi.get_handle_byname("T1D1P3")

    data.port_hand_list = [tg_ph_1, tg_ph_2, tg_ph_3]

    st.log("PRE TEST : Cleanup call are started.")
    ip_obj.clear_ip_configuration(st.get_dut_names(), thread=data.clear_parallel)
    ip_obj.clear_ip_configuration(st.get_dut_names(), 'ipv6', thread=data.clear_parallel)
    vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel)
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names(), thread=data.clear_parallel)

    intf_obj.clear_interface_counters(vars.D1)

    if sub_test_8:
        st.log("#"*90)
        st.log("############# Sub test 8: test_base_line_vlan_create_delete_and_mac_learning_with_bum - START  "
               "################")
        st.log("#"*90)
        try:
            st.log("Create and configure Vlan and adding member as tagged members.")
            vlan_obj.create_vlan(vars.D1, data.vlan)
            vlan_obj.add_vlan_member(vars.D1, data.vlan, data.tg_con_interface, True)
            if not vlan_obj.verify_vlan_config(vars.D1, data.vlan, tagged=data.tg_con_interface):
                st.log("vlan tagged member fail on port {} ,vlan {}".format(data.tg_con_interface, data.vlan))
                assert False

            st.log("Start testing the bum traffic ...")
            mac_addr_list = {"Broadcast": data.broacast_mac, "Multicast": data.multicast_mac,
                             "Unknown": data.unknown_mac}
            mac_incr_cnt = 7
            tg_info = {}
            result = True
            if st.is_soft_tgen():
                for mac_addr in mac_addr_list:
                    st.log(
                        "Start '{}' traffic test with destination MAC = {}".format(mac_addr, mac_addr_list[mac_addr]))
                    new_src_mac = ("00:00:00:00:09:4{}".format(mac_incr_cnt))
                    tg1.tg_traffic_control(action='reset')
                    rv = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=data.rate_pps,
                                               mac_src=new_src_mac, vlan_id=data.vlan, vlan="enable",
                                               transmit_mode="continuous", mac_dst=mac_addr_list[mac_addr],
                                               l2_encap='ethernet_ii_vlan')
                    tg_info[mac_addr] = rv['stream_id']
                    mac_incr_cnt += 1
                    tg1.tg_traffic_control(action='clear_stats')
                    st.log("Sending traffic and verifying the stats")
                    tg1.tg_traffic_control(stream_handle=tg_info[mac_addr], action='run')
                    st.wait(data.post_wait_time_run)
                    tg1.tg_traffic_control(stream_handle=tg_info[mac_addr], action='stop')
                    traffic_details = {
                        '1': {
                            'tx_ports': [vars.T1D1P1],
                            'tx_obj': [tg1],
                            'exp_ratio': [1],
                            'rx_ports': [vars.T1D1P2, vars.T1D1P3],
                            'rx_obj': [tg1, tg1]
                        }
                    }
                    intf_obj.show_specific_interface_counters(vars.D1, vars.D1T1P1)
                    intf_obj.show_specific_interface_counters(vars.D1, vars.D1T1P2)
                    intf_obj.show_specific_interface_counters(vars.D1, vars.D1T1P3)
                    st.log('MAC address validation.')
                    if not mac_obj.verify_mac_address_table(vars.D1, new_src_mac, port=vars.D1T1P1):
                        st.error("MAC '{}' is failed to learn in port = {}".format(new_src_mac, vars.D1T1P1))
                        assert False
                    st.log('MAC address validation passed.')
                    result1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                                          comp_type='packet_count')
                    result = result and result1
                    if result1:
                        st.log("Traffic successfully forwarded for the traffic type {}".format(mac_addr))
                    else:
                        st.error("Traffic failed to forwarded for the traffic type {}".format(mac_addr))
            else:
                new_src_mac = []
                st.log("Reseting and creating the traffic stream.")
                tg1.tg_traffic_control(port_handle=tg_ph_1, action='reset')
                for mac_addr in mac_addr_list:
                    st.log(
                        "Start '{}' traffic test with destination MAC = {}".format(mac_addr, mac_addr_list[mac_addr]))
                    new_src_mac.append("00:00:00:00:09:4{}".format(mac_incr_cnt))
                    rv = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=data.rate_pps,
                                               mac_src=new_src_mac[-1], vlan_id=data.vlan, vlan="enable",
                                               transmit_mode="continuous", mac_dst=mac_addr_list[mac_addr],
                                               l2_encap='ethernet_ii_vlan', port_handle2=[tg_ph_1, tg_ph_2, tg_ph_3])
                    tg_info[mac_addr] = rv['stream_id']
                    mac_incr_cnt += 1
                st.log("Sending traffic and verifying the stats")
                tg1.tg_traffic_control(action='clear_stats', stream_handle=tg_info.values())
                tg1.tg_traffic_control(stream_handle=tg_info.values(), action='run')
                st.wait(data.post_wait_time_run)
                tg1.tg_traffic_control(stream_handle=tg_info.values(), action='stop')
                traffic_details = {
                    '1': {
                        'tx_ports': [vars.T1D1P1],
                        'tx_obj': [tg1],
                        'exp_ratio': [2],
                        'rx_ports': [vars.T1D1P2, vars.T1D1P3],
                        'rx_obj': [tg1, tg1],
                        'stream_list': [[tg_info['Unknown']]]
                    },
                    '2': {
                        'tx_ports': [vars.T1D1P1],
                        'tx_obj': [tg1],
                        'exp_ratio': [2],
                        'rx_ports': [vars.T1D1P2, vars.T1D1P3],
                        'rx_obj': [tg1, tg1],
                        'stream_list': [[tg_info['Broadcast']]]
                    },
                    '3': {
                        'tx_ports': [vars.T1D1P1],
                        'tx_obj': [tg1],
                        'exp_ratio': [2],
                        'rx_ports': [vars.T1D1P2, vars.T1D1P3],
                        'rx_obj': [tg1, tg1],
                        'stream_list': [[tg_info['Multicast']]]
                    }
                }
                intf_obj.show_specific_interface_counters(vars.D1, vars.D1T1P1)
                intf_obj.show_specific_interface_counters(vars.D1, vars.D1T1P2)
                intf_obj.show_specific_interface_counters(vars.D1, vars.D1T1P3)
                st.log('MAC address validation.')
                for mac in new_src_mac:
                    if not mac_obj.verify_mac_address_table(vars.D1, mac, port=vars.D1T1P1):
                        st.error("MAC '{}' is failed to learn in port = {}".format(mac, vars.D1T1P1))
                        assert False
                st.log('MAC address validation passed.')
                # Sending BUM traffic from one port and verifying on other two ports. Providing rx_ports as a input to port_handle2 param, the rx count would be double the tx count
                result_all = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock',
                                                         comp_type='packet_count', return_all=1)
                for result1, traffic_type in zip(result_all[1], ['Unknown', 'Broadcast', 'Multicast']):
                    result = result and result1
                    if result1:
                        st.log("Traffic successfully forwarded for the traffic type {}".format(traffic_type))
                    else:
                        st.error("Traffic failed to forwarded for the traffic type {}".format(traffic_type))
            if not result:
                st.error("traffic_verification_failed")
                assert False
            st.log("Traffic test passed..")

            base_line_final_result['test_base_line_vlan_create_delete_and_mac_learning_with_bum'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_vlan_create_delete_and_mac_learning_with_bum'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 8: test_base_line_vlan_create_delete_and_mac_learning_with_bum - END "
               " ################")
        st.log("#"*90)

    if sub_test_10 and base_line_final_result['test_base_line_vlan_create_delete_and_mac_learning_with_bum'] == 'Pass':
        st.log("#"*90)
        st.log("############# Sub test 10: test_base_line_mac_move_single_vlan - START  ################")
        st.log("#"*90)
        try:
            st.log("Clearing the MAC table entries.")
            mac_obj.clear_mac(vars.D1)
            st.wait(data.clear_mac_table_wait_time)
            st.log("Configuring the mac aging time - {}".format(0))
            mac_obj.config_mac_agetime(vars.D1, 0)
            intf_obj.show_interface_counters_all(vars.D1)
            # Step 2
            # Test - Start sending traffic from port 1 with mac address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1.
            st.log("Reseting ,creating and start the traffic stream on TG1.")
            tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
            rv = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', mac_src='00:00:00:00:11:11',
                                  transmit_mode="single_pkt", mac_dst='00:00:00:00:00:22',
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")
            tg_info['tg1_stream_id'] = rv['stream_id']
            st.wait(data.post_wait_time_create)
            tg1.tg_traffic_control(action='run', stream_handle=tg_info['tg1_stream_id'])
            st.wait(data.post_wait_time_run)
            intf_obj.show_interface_counters_all(vars.D1)
            st.log("Validating MAC table..")
            if not mac_obj.verify_mac_address_table(vars.D1, "00:00:00:00:11:11", vlan=data.vlan, port=vars.D1T1P1):
                st.log("mac_address_verification_fail")
                assert False
            st.log("MAC address validation passed.")
            tg1.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])
            st.wait(data.post_wait_time_stop)

            # Step 3
            # Test - Now start sending traffic from port 2 with same MAC address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1 flushed out and learned on port 2"
            st.log("Reseting ,creating and start the traffic stream on TG2.")
            tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)
            rv_1 = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', mac_src='00:00:00:00:11:11',
                                  transmit_mode="single_pkt", mac_dst='00:00:00:00:00:22',
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")
            tg_info['tg2_stream_id'] = rv_1['stream_id']
            st.wait(data.post_wait_time_create)
            tg2.tg_traffic_control(action='run', stream_handle=tg_info['tg2_stream_id'])
            st.wait(data.post_wait_time_run)
            st.log("Validating MAC table..")
            intf_obj.show_interface_counters_all(vars.D1)
            st.log("Checking the stats for tx TG")
            tgapi.get_traffic_stats(tg1, port_handle=tg_ph_2, mode="aggregate", direction='tx')

            if mac_obj.verify_mac_address_table(vars.D1, "00:00:00:00:11:11", vlan=data.vlan, port=vars.D1T1P1):
                st.error("failed_clear_mac_learned_on first port")
                assert False
            if not mac_obj.verify_mac_address_table(vars.D1, "00:00:00:00:11:11", vlan=data.vlan, port=vars.D1T1P2):
                st.error("failed_to_learn_mac_after_move")
                assert False
            st.log("MAC address validation passed.")
            tg2.tg_traffic_control(action='stop', stream_handle=tg_info['tg2_stream_id'])
            st.wait(data.post_wait_time_stop)

            # Sending traffic to check if mac has moved or not.
            st.log("Reseting ,creating and start the traffic stream on TG3.")
            tg3.tg_traffic_control(action='reset', port_handle=tg_ph_3)
            rv_2 = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create', rate_pps=100, mac_dst='00:00:00:00:11:11',
                                  transmit_mode="continuous", mac_src='00:00:00:00:00:33',
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")
            tg_info['tg3_stream_id'] = rv_2['stream_id']
            st.wait(data.post_wait_time_create)
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)
            tg3.tg_traffic_control(action='run', stream_handle=tg_info['tg3_stream_id'])
            st.wait(data.post_wait_time_run)
            tg3.tg_traffic_control(action='stop', stream_handle=tg_info['tg3_stream_id'])
            st.wait(data.post_wait_time_stop)
            intf_obj.show_interface_counters_all(vars.D1)
            # stats fetching
            stats1 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_1, mode="aggregate")
            total_rx1 = stats1.rx.total_packets
            stats2 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_2, mode="aggregate")
            total_rx2 = stats2.rx.total_packets
            stats3 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_3, mode="aggregate", direction='tx')
            total_tx3 = stats3.tx.total_packets
            st.log("Sent Packets On Port 3: {} and Received Packets On Port 1: {} and Received Packets "
                   "On Port 2: {}".format(total_tx3, total_rx1, total_rx2))

            if total_tx3 == 0:
                st.error("Traffic verification failed: Traffic not initiated from  TG3.")
                assert False
            # This is for allowance towards control packets like LLDP etc..
            if total_rx1 > 10:
                st.error("Traffic verification failed : Traffic should not be received on TG1, but received.")
                assert False
            if total_rx2 < total_tx3:
                st.error("Traffic verification failed : Traffic from TG3 not fully received on TG2.")
                assert False

            st.log("Traffic test passed..")
            base_line_final_result['test_base_line_mac_move_single_vlan'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_mac_move_single_vlan'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 10: test_base_line_mac_move_single_vlan - END  ################")
        st.log("#"*90)

    if sub_test_11 and base_line_final_result['test_base_line_vlan_create_delete_and_mac_learning_with_bum'] == 'Pass'\
            and base_line_final_result['test_base_line_mac_move_single_vlan'] == 'Pass':
        st.log("#"*90)
        st.log("############# Sub test 11: test_base_line_mac_move_across_vlans - START  ################")
        st.log("#"*90)
        try:
            st.log("Creating second vlan config ")
            vlan_obj.create_vlan(vars.D1, data.vlan_1)
            vlan_obj.add_vlan_member(vars.D1, data.vlan_1, data.tagged_members_1, True)
            if not vlan_obj.verify_vlan_config(vars.D1, data.vlan_1, tagged=data.tagged_members_1):
                st.error("vlan tagged member fail on port {} ,vlan {}".format(data.tagged_members_1, data.vlan_1))
                assert False

            mac_obj.clear_mac(vars.D1)
            st.wait(data.clear_mac_table_wait_time)
            mac_obj.config_mac_agetime(vars.D1, 0)
            intf_obj.show_interface_counters_all(vars.D1)
            # Step 2
            # Test - Start sending traffic from port 1 with mac address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1.
            tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
            rv = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', mac_src='00:00:00:00:11:11',
                                  transmit_mode="single_pkt", mac_dst='00:00:00:00:00:22',
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")
            tg_info['tg1_stream_id'] = rv['stream_id']
            st.wait(data.post_wait_time_create)
            tg1.tg_traffic_control(action='run', stream_handle=tg_info['tg1_stream_id'])
            st.wait(data.post_wait_time_run)

            st.log("Validating MAC table..")
            intf_obj.show_interface_counters_all(vars.D1)
            if not mac_obj.verify_mac_address_table(vars.D1, "00:00:00:00:11:11", vlan=data.vlan, port=vars.D1T1P1):
                st.error("mac_failed_to_learn_on_firt_port")
                assert False
            st.log("MAC address validation passed.")
            tg1.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])

            # Step 3
            # Test - Now start sending traffic from port 2 with same MAC address 00:00:00:00:11:11.
            # Expected - Verify that MAC address 00:00:00:00:11:11 learned on port 1 flushed out and learned on port 2"
            tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)
            rv_1 = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', mac_src='00:00:00:00:11:11',
                                  transmit_mode="single_pkt", mac_dst='00:00:00:00:00:22',
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan_1, vlan="enable")
            tg_info['tg2_stream_id'] = rv_1['stream_id']
            st.wait(data.post_wait_time_create)
            tg2.tg_traffic_control(action='run', stream_handle=tg_info['tg2_stream_id'])
            st.wait(data.post_wait_time_run)

            st.log("Validating MAC table..")
            intf_obj.show_interface_counters_all(vars.D1)
            st.log("Checking the stats for tx TG")
            tgapi.get_traffic_stats(tg1, port_handle=tg_ph_2, mode="aggregate", direction='tx')

            if not mac_obj.verify_mac_address_table(vars.D1, "00:00:00:00:11:11", vlan=data.vlan, port=vars.D1T1P1):
                st.error("mac_address_not_clear")
                assert False
            st.log("MAC address validation passed.")

            st.log("Validating MAC table..")
            if not mac_obj.verify_mac_address_table(vars.D1, "00:00:00:00:11:11", vlan=data.vlan_1, port=vars.D1T1P2):
                st.error("mac_failed_to_learn_on_second_port")
                assert False
            st.log("MAC address validation passed.")
            tg2.tg_traffic_control(action='stop', stream_handle=tg_info['tg2_stream_id'])

            # Sending traffic to check if mac has moved or not.
            tg3.tg_traffic_control(action='reset', port_handle=tg_ph_3)
            rv_2 = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create', rate_pps=10, mac_dst='00:00:00:00:11:11',
                                  transmit_mode="continuous", mac_src='00:00:00:00:00:33',
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, vlan="enable")
            tg_info['tg3_stream_id'] = rv_2['stream_id']
            st.wait(data.post_wait_time_create)
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)

            st.wait(data.post_wait_time_clear)
            tg3.tg_traffic_control(action='run', stream_handle=tg_info['tg3_stream_id'])
            st.wait(data.post_wait_time_run)
            tg3.tg_traffic_control(action='stop', stream_handle=tg_info['tg3_stream_id'])
            st.wait(data.post_wait_time_stop)
            intf_obj.show_interface_counters_all(vars.D1)
            # stats fetching
            stats1 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_1, mode="aggregate")
            total_rx1 = stats1.rx.total_packets
            stats2 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_2, mode="aggregate")
            total_rx2 = stats2.rx.total_packets
            stats3 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_3, mode="aggregate", direction='tx')
            total_tx3 = stats3.tx.total_packets

            st.log("Sent Packets On Port 3: {} and Received Packets On Port 1: {} and Received Packets On"
                   " Port 2: {}".format(total_tx3, total_rx1, total_rx2))

            if total_tx3 == 0:
                st.error("Traffic verification failed: Traffic not initiated from  TG3.")
                assert False
            # This is for allowance towards control packets like LLDP etc..
            if total_rx2 > 10:
                st.error("Traffic verification failed : Traffic should not be received on TG2, but received.")
                assert False
            if total_rx1 < total_tx3:
                st.error("Traffic verification failed : Traffic from TG3 not fully received on TG1.")
                assert False
            st.log("Traffic test passed..")

            # Sending traffic to check if mac has moved or not.
            tg1.tg_traffic_control(action='clear_stats', port_handle=data.port_hand_list)
            st.wait(data.post_wait_time_clear)

            tg3.tg_traffic_control(action='reset', port_handle=tg_ph_3)
            rv_2 = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create', rate_pps=10, mac_dst='00:00:00:00:11:11',
                                  transmit_mode="continuous", mac_src='00:00:00:00:00:33',
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan_1, vlan="enable")
            tg_info['tg3_stream_id'] = rv_2['stream_id']
            st.wait(data.post_wait_time_create)
            tg3.tg_traffic_control(action='run', stream_handle=tg_info['tg3_stream_id'])
            st.wait(data.post_wait_time_run)
            tg3.tg_traffic_control(action='stop', stream_handle=tg_info['tg3_stream_id'])
            st.wait(data.post_wait_time_stop)
            intf_obj.show_interface_counters_all(vars.D1)
            # stats fetching
            stats1 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_1, mode="aggregate")
            total_rx1 = stats1.rx.total_packets
            stats2 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_2, mode="aggregate")
            total_rx2 = stats2.rx.total_packets
            stats3 = tgapi.get_traffic_stats(tg1, port_handle=tg_ph_3, mode="aggregate", direction='tx')
            total_tx3 = stats3.tx.total_packets

            st.log("Sent Packets On Port 3: {} and Received Packets On Port 1: {} and Received Packets "
                   "On Port 2: {}".format(total_tx3, total_rx1, total_rx2))
            if total_tx3 == 0:
                st.error("Traffic verification failed: Traffic not initiated from  TG3.")
                assert False
            # This is for allowance towards control packets like LLDP etc..
            if total_rx1 > 10:
                st.error("Traffic verification failed : Traffic should not be received on TG1, but received.")
                assert False
            if total_rx2 < total_tx3:
                st.error("Traffic verification failed : Traffic from TG3 not fully received on TG2.")
                assert False
            st.log("Traffic test passed..")

            base_line_final_result['test_base_line_mac_move_across_vlans'] = 'Pass'
        except Exception as e:
            st.log(e)
            base_line_final_result['test_base_line_mac_move_across_vlans'] = 'Fail'

        st.log("#"*90)
        st.log("############# Sub test 11: test_base_line_mac_move_across_vlans - END  ################")
        st.log("#"*90)

    st.log(
        sprint_vtable(['Test', 'Result'],
                      [[k, v] for k, v in
                       filter_and_select([base_line_final_result],
                                         ['test_base_line_vlan_create_delete_and_mac_learning_with_bum',
                                          'test_base_line_mac_move_single_vlan',
                                          'test_base_line_mac_move_across_vlans']
                                         )[0].items()], 0))

    st.log("POST TEST : Cleanup call are started.")
    ip_obj.clear_ip_configuration(st.get_dut_names(), thread=data.clear_parallel)
    ip_obj.clear_ip_configuration(st.get_dut_names(), 'ipv6', thread=data.clear_parallel)
    vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=data.clear_parallel)
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names(), thread=data.clear_parallel)

    out = base_line_final_result['test_base_line_vlan_create_delete_and_mac_learning_with_bum']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
@pytest.mark.depends("test_base_line_vlan_create_delete_and_mac_learning_with_bum")
def test_base_line_mac_move_single_vlan():
    out = base_line_final_result['test_base_line_mac_move_single_vlan']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")


@pytest.mark.base_test_sanity
@pytest.mark.base_test_sanity_optimize
@pytest.mark.depends("test_base_line_vlan_create_delete_and_mac_learning_with_bum")
def test_base_line_mac_move_across_vlans():
    out = base_line_final_result['test_base_line_mac_move_across_vlans']
    if out == 'Pass':
        st.report_pass("test_case_passed")
    elif out == 'Fail':
        st.report_fail("test_case_failed")
    else:
        st.report_fail("test_case_not_executed")

