import json
import random

from spytest import st, tgapi
from spytest.utils import random_vlan_list
from spytest.utils import exec_all
from spytest.utils import poll_wait

import apis.switching.pvst as stp
import apis.switching.pvst_elasticity_wrapper as stp_wrap
import apis.switching.portchannel as portchannel
import apis.switching.vlan as vlan
import apis.system.interface as intf
import apis.system.basic as basic
import apis.system.port as port
import apis.switching.mac as mac
import apis.system.lldp as lldp
import apis.system.logging as slog
import apis.system.reboot as reboot
import apis.system.rest as rest_obj
import apis.system.gnmi as gnmi_obj
from apis.system.basic import cmd_validator

import utilities.utils as utils
import utilities.common as common_obj

stp_dict = {"pvst": {"stp_wait_time": 40, "non_fwd_state": "BLOCKING"}, "rpvst": {"non_fwd_state": "DISCARDING"}}

def init_cli_type():
   global stp_cli_type
   stp_cli_type = st.get_ui_type()

def config_max_age_and_edge_port(vars, stp_ela, stp_protocol):
    global stp_dict
    dut_list = stp_wrap.get_dut_list(vars)

    if len(dut_list) <= 6:
        max_age = 6
    else:
        max_age = len(dut_list)

    for dut in dut_list:
        slog.clear_logging(dut)
        for vlan_id in stp_wrap.complete_data["vlan_data"]["vlan_list"]:
            stp.config_stp_vlan_parameters(dut, vlan_id, max_age=max_age)
        for interf in stp_ela[dut]['tg_links']:
            stp.config_port_type(dut, interf[0], stp_type=stp_protocol, port_type='edge', no_form=False)

    hold_time = 6
    buffer = 4
    wait_time = hold_time + max_age + buffer
    stp_dict["rpvst"]["stp_wait_time"] = wait_time
    stp_dict["rpvst"]["stp_max_age"] = max_age
    st.log("stp_dict : {}".format(stp_dict))

def config_untagged_vlan_members_to_device(vlan_data, thread=True, mode="add"):
    utils.banner_log("Configuring VLAN members in all the DUT's")
    st.log("printing vlan data.. {}".format(vlan_data))
    params = list()
    if vlan_data:
        for index, members in vlan_data.items():
            vlan_list = new_vlan
            if index != "vlan_list":
                if mode=="add":
                    params.append([vlan.config_vlan_members, index, vlan_list,members, "add", False])
                else:
                    if stp_cli_type == "click":
                        params.append([vlan.config_vlan_members, index, vlan_list,members, "del", True])
                    else:
                        params.append([vlan.config_vlan_members, index, vlan_list, members, "del", False])
        exec_all(thread, params)
        return True
    st.log("Invalid data provided....")
    return False

def lib_stp_general_verification(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    dut_list = stp_wrap.get_dut_list(vars)
    st.log("Getting dut list : {}" . format(dut_list))
    if not dut_list:
        st.log("DUT LIST NOT FOUND")
        st.report_fail("dut_list_not_found")

    pass_cnt+=4
    st.report_tc_pass('ft_{}_cli'.format(stp_protocol),'test_case_passed')
    st.report_tc_pass('ft_{}_nondefault_bridge_priority'.format(stp_protocol),'test_case_passed')
    st.report_tc_pass('ft_{}_multiple_instances_convergence'.format(stp_protocol),'test_case_passed')
    st.report_tc_pass('ft_{}_portchannel_convergence'.format(stp_protocol),'test_case_passed')

    randon_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(randon_vlan))

    root_bridge = stp_ela['states'][randon_vlan]['root']
    st.log("Topology root bridge:  {}".format(root_bridge))

    stp.config_stp_vlan_parameters_parallel(dut_list, vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"], priority=[32768]*len(dut_list))
    stp.config_stp_vlan_parameters_parallel([root_bridge]*len(dut_list), False, vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"], priority=[0]*len(dut_list))

    utils.banner_log("Checking {} convergence".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])
    for (dut_test, vlan_test) in zip([root_bridge]*len(dut_list), stp_wrap.complete_data["vlan_data"]["vlan_list"]):
        if stp.poll_for_root_switch(dut_test, vlan_test, iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut_test, vlan_test))
        else:
            st.error("{} is not root switch for vlan {}".format(dut_test, vlan_test))

    root_ph_port = stp_wrap.get_physical_link_with_partner(root_bridge)[root_bridge][0]['local']
    st.log("Root port:  {}".format(root_ph_port))

    blocking_bridge_info = stp_ela['states'][randon_vlan]['non_root']['highest_mac']
    st.log("blocking_bridge_info: {}".format(blocking_bridge_info))

    if not 'name' in blocking_bridge_info:
        fail_cnt+=1
        st.error("Did not get the name of {} switch.".format(stp_dict[stp_protocol]["non_fwd_state"]))
        st.report_tc_fail('ft_{}_blocked_switch'.format(stp_protocol),'test_case_failed')
    else:
        pass_cnt+=1
        st.log("Got the name of {} switch.".format(stp_dict[stp_protocol]["non_fwd_state"]))
        st.report_tc_pass('ft_{}_blocked_switch'.format(stp_protocol),'test_case_passed')

        res = 1
        blocking_bridge = blocking_bridge_info['name']
        st.log("{} bridge : {}".format(stp_dict[stp_protocol]["non_fwd_state"],blocking_bridge))

        block_ph_port = blocking_bridge_info['blocking_links'][0]
        st.log("{} port : {}".format(stp_dict[stp_protocol]["non_fwd_state"],block_ph_port))

        tx_count_on_blk_port_1 = intf.get_interface_counters(blocking_bridge, block_ph_port, "tx_ok")
        st.log("tx_count_on_blk_port_1: {}".format(tx_count_on_blk_port_1))

        blk_port_1_tx_count_1 = 0
        if tx_count_on_blk_port_1 and len(tx_count_on_blk_port_1) >= 1:
            if "tx_ok" in tx_count_on_blk_port_1[0] and tx_count_on_blk_port_1[0]["tx_ok"] != 'N/A':
                blk_port_1_tx_count_1 = int(tx_count_on_blk_port_1[0]["tx_ok"].replace(',',''))
                st.log("TX_OK counters first iteration {}".format(blk_port_1_tx_count_1))
            else:
                res = 0
                st.error("tx_count_on_blk_port_1 variable not having expected data .. FAILED !!")
        else:
            res = 0
            st.error("tx_count_on_blk_port_1 variable is empty .. FAILED !!")

        mac.get_mac_all_dut(dut_list)

        #############################################################################################
        utils.banner_log("Verify that end to end learned unicast traffic forwarding is fine. -- STARTED")
        #############################################################################################
        if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
            pass_cnt+=1
            st.log("Learned unicast traffic test PASSED")
            st.report_tc_pass('ft_{}_learnt_traffic'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.error("Learned unicast traffic test FAILED !!")
            st.report_tc_fail('ft_{}_learnt_traffic'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verify that end to end learned unicast traffic forwarding is fine. -- COMPLETED")
        #############################################################################################

        mac.get_mac_all_dut(dut_list)

        #############################################################################################
        utils.banner_log("Verify that end to end unlearnt unicast traffic forwarding is fine. -- STARTED")
        #############################################################################################
        if stp_wrap.verify_traffic('unknown', stp_wrap.tg_info):
            pass_cnt+=1
            st.log("Unlearnt unicast traffic test PASSED")
            st.report_tc_pass('ft_{}_unlearnt_unicast_traffic'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.error("Unlearnt unicast traffic test FAILED !!")
            st.report_tc_fail('ft_{}_unlearnt_unicast_traffic'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verify that end to end unlearnt unicast traffic forwarding is fine. -- COMPLETED")
        #############################################################################################

        mac.get_mac_all_dut(dut_list)

        tx_count_on_blk_port_2 = intf.get_interface_counters(blocking_bridge, block_ph_port, "tx_ok")
        st.log("tx_count_on_blk_port_2: {}".format(tx_count_on_blk_port_2))

        blk_port_1_tx_count_2 = 0
        if tx_count_on_blk_port_2 and len(tx_count_on_blk_port_2) >= 1:
            if "tx_ok" in tx_count_on_blk_port_2[0] and tx_count_on_blk_port_2[0]["tx_ok"] != 'N/A':
                blk_port_1_tx_count_2 = int(tx_count_on_blk_port_2[0]["tx_ok"].replace(',',''))
                st.log("TX_OK counters second iteration {}".format(blk_port_1_tx_count_2))
            else:
                res = 0
                st.error("tx_count_on_blk_port_2 variable not having expected data .. FAILED !!")
        else:
            res = 0
            st.error("tx_count_on_blk_port_2 variable is empty .. FAILED !!")

        #############################################################################################
        utils.banner_log("Verification of traffic on {} ports -- STARTED".format(stp_dict[stp_protocol]["non_fwd_state"]))
        #############################################################################################
        st.log("Due to TG streams enabling and disabling delay, there will be additional BPDU sent so increasing below check to 100")
        if (blk_port_1_tx_count_2 - blk_port_1_tx_count_1) > 100:
            res = 0

        if res:
            pass_cnt+=1
            st.log("blk_port_1_tx_count_2 : {} blk_port_1_tx_count_1 : {}".format(blk_port_1_tx_count_2, blk_port_1_tx_count_1))
            st.log("{} port is not forwarding the traffic. PASS.".format(stp_dict[stp_protocol]["non_fwd_state"]))
            st.report_tc_pass('ft_{}_fdb_blockingport'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.error("{} port is forwarding the traffic. FAIL.".format(stp_dict[stp_protocol]["non_fwd_state"]))
            st.report_tc_fail('ft_{}_fdb_blockingport'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verification of traffic on {} ports -- COMPLETED".format(stp_dict[stp_protocol]["non_fwd_state"]))
        #############################################################################################

        #############################################################################################
        utils.banner_log("Verification of TX and RX BPDU stats on physical port before and after issuing clear stats -- STARTED")
        #############################################################################################
        res = 1
        bpdu_tx_cnt = stp.get_stp_stats(root_bridge, randon_vlan, root_ph_port, "st_bpdutx")
        bpdu_rx_cnt = stp.get_stp_stats(blocking_bridge, randon_vlan, block_ph_port, "st_bpdurx")
        if bpdu_tx_cnt == 0 or bpdu_rx_cnt == 0:
            res = 0
            st.error("operation_failed_msg - BPDU counters are not incremented")
        else:
            st.log("BPDU counters incremented successfuly..")

        stp.stp_clear_stats(root_bridge, vlan=randon_vlan)
        stp.stp_clear_stats(blocking_bridge, vlan=randon_vlan)
        st.wait(10)

        bpdu_cntr_result = 0
        if not stp.get_stp_stats(root_bridge, randon_vlan, root_ph_port, "st_bpdutx") >= 1:
            st.error("operation_failed_msg -  BPDU TX counters are not cleared")
            bpdu_cntr_result = 1
        if not stp.get_stp_stats(blocking_bridge, randon_vlan, block_ph_port, "st_bpdurx") >= 1:
            st.error("operation_failed_msg - BPDU RX counters are not cleared")
            bpdu_cntr_result = 1

        if bpdu_cntr_result == 0:
            st.log("BPDU TX RX clear counter verification successful")
        else:
            res = 0
            st.error("BPDU TX RX clear counter verification failed")

        if res:
            pass_cnt+=1
            st.report_tc_pass('ft_{}_bpdu'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.report_tc_fail('ft_{}_bpdu'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verification of TX and RX BPDU stats on physical port after issuing clear stats -- COMPLETED")
        #############################################################################################

        st.log("Clearing stats before sending traffic ...")
        tgapi.traffic_action_control(stp_wrap.tg_info['tg_info'], actions=['clear_stats'])
        st.wait(5)
        tg = stp_wrap.tg_info['tg_info']['tg']
        tg_ph_1 = stp_wrap.tg_info['tg_info']["tg_ph_1"]
        tg_ph_2 = stp_wrap.tg_info['tg_info']["tg_ph_2"]
        tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_percent=1,mac_src="00:00:00:00:00:21",mac_src_mode="increment",transmit_mode="continuous",mac_dst="00:00:00:00:00:22", mac_dst_mode="fixed",l2_encap='ethernet_ii_vlan',vlan_id=randon_vlan, vlan="enable")
        stream_id_1 = tg_1['stream_id']
        tg_2 = tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_percent=1,mac_src="00:00:00:00:00:22",mac_src_mode="increment",transmit_mode="continuous",mac_dst="00:00:00:00:00:21", mac_dst_mode="fixed",l2_encap='ethernet_ii_vlan',vlan_id=randon_vlan, vlan="enable")
        stream_id_2 = tg_2['stream_id']
        tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_unknown'])
        tg.tg_traffic_config(mode='enable', stream_id=stream_id_1)
        tg.tg_traffic_config(mode='enable', stream_id=stream_id_2)
        mac.get_mac_all_dut(dut_list)
        stream_list = [stream_id_1, stream_id_2]
        tg.tg_traffic_control(action='run', stream_handle = stream_list)

        #############################################################################################
        utils.banner_log("Verification of shut and no shut of {} port does not impact the port {} state and traffic -- STARTED".format(stp_dict[stp_protocol]["non_fwd_state"],stp_dict[stp_protocol]["non_fwd_state"]))
        #############################################################################################
        intf.interface_shutdown(blocking_bridge, block_ph_port)
        st.wait(5)
        intf.interface_noshutdown(blocking_bridge, block_ph_port)
        if not stp.poll_for_stp_status(blocking_bridge, randon_vlan, block_ph_port, stp_dict[stp_protocol]["non_fwd_state"], iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            fail_cnt+=1
            st.error("Interface is not moved to {} state ..".format(stp_dict[stp_protocol]["non_fwd_state"]))
            st.report_tc_fail('ft_{}_blockedport_shut_noshut'.format(stp_protocol),'test_case_failed')
        else:
            pass_cnt+=1
            st.log("Verification of {} Interface successful".format(stp_dict[stp_protocol]["non_fwd_state"]))
            st.report_tc_pass('ft_{}_blockedport_shut_noshut'.format(stp_protocol),'test_case_passed')

        tg.tg_traffic_control(action='stop', stream_handle = stream_list)
        tg.tg_traffic_config(mode='disable', stream_id=stream_id_1)
        tg.tg_traffic_config(mode='disable', stream_id=stream_id_2)
        st.wait(10)

        stat1 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_1)
        stat2 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_2)
        tx_tg1_99_precentage = (99 * int(stat1.tx.total_packets)) / 100
        tx_tg2_99_precentage = (99 * int(stat2.tx.total_packets)) / 100
        if not (stat2.rx.total_packets >= tx_tg1_99_precentage and stat1.rx.total_packets >= tx_tg2_99_precentage):
            fail_cnt+=1
            st.error("Traffic verification for unicast failed ...")
            st.report_tc_fail('ft_{}_blockedport_shut_traffic'.format(stp_protocol),'test_case_failed')
        else:
            pass_cnt+=1
            st.log("Unicast traffic verification on {} interface is successful".format(stp_dict[stp_protocol]["non_fwd_state"]))
            st.report_tc_pass('ft_{}_blockedport_shut_traffic'.format(stp_protocol),'test_case_passed')
        #############################################################################################
        utils.banner_log("Verification of shut and no shut of {} port does not impact the port {} state and traffic -- COMPLETED".format(stp_dict[stp_protocol]["non_fwd_state"],stp_dict[stp_protocol]["non_fwd_state"]))
        #############################################################################################

        mac.get_mac_all_dut(dut_list)

    #############################################################################################
    utils.banner_log("Verification of BPDU stats on port channel before any trigger -- STARTED")
    #############################################################################################
    res = 1
    st.log("Get local and remote DUTs for port channel; and get port channel name")
    portchannel_data = stp_wrap.get_portchannel_details()
    for key,value in portchannel_data.items():
        port_channel_name = key
        local_dut_for_po  = value["partners"][0]
        remote_dut_for_po  = value["partners"][1]
        st.log(st.get_links(local_dut_for_po,remote_dut_for_po))

    st.log("Verify BPDU RX counters are incrementing when port channel is in {} state".format(stp_dict[stp_protocol]["non_fwd_state"]))

    if stp.verify_stp_ports_by_state(local_dut_for_po, randon_vlan, stp_dict[stp_protocol]["non_fwd_state"], port_channel_name):
        if not stp.get_stp_stats(local_dut_for_po, randon_vlan, port_channel_name, "st_bpdurx") >= 1:
            res = 0
            st.error("operation_failed_msg - BPDU RX counters are not incrementing")
        else:
            st.log("BPDU RX counters are incrementing correctly")
    elif stp.verify_stp_ports_by_state(remote_dut_for_po, randon_vlan, stp_dict[stp_protocol]["non_fwd_state"], port_channel_name):
        if not stp.get_stp_stats(remote_dut_for_po, randon_vlan, port_channel_name, "st_bpdurx") >= 1:
            res = 0
            st.error("operation_failed_msg - BPDU RX counters are not incrementing")
        else:
            st.log("BPDU RX counters are incrementing correctly")

    if res:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_portchannel_bpdu'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_portchannel_bpdu'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of BPDU stats on port channel before any trigger -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of TX and RX TCN stats, next best root port by shut and no shut of interface -- STARTED")
    #############################################################################################
    res1 = 1
    res2 = 1

    root_neigh = stp_wrap.get_dut_neighbors_with_required_links(root_bridge, min_link=2, nodes=1)[0]
    st.log("Root bridge Neighbor {}".format(root_neigh))

    root_neigh_root_port = stp.get_stp_root_port(root_neigh,randon_vlan)
    st.log("root_neigh_root_port {}".format(root_neigh_root_port))
    if not root_neigh_root_port:
        st.error("root_neigh_root_port not found on {} for vlan {}".format(root_neigh, randon_vlan))
    else:
        st.log("Verification of BPDU stats is successful")

    root_neigh_next_root_port = stp.get_stp_next_root_port(root_neigh,randon_vlan)
    st.log("root_neigh_next_root_port {}".format(root_neigh_next_root_port))
    if not root_neigh_next_root_port:
        st.error("root_neigh_next_root_port not found on {} for vlan {}".format(root_neigh, randon_vlan))
        res1 = 0
        res2 = 0
    else:
        st.log("Verification of NEXT root port on neighbor is successful")

        st.log("Initiate trigger ..shut")
        intf.interface_shutdown(root_neigh, root_neigh_root_port)

        st.wait(stp_dict[stp_protocol]["stp_wait_time"])
        if stp_protocol == "pvst":
            if not stp.get_stp_stats(root_neigh, randon_vlan, root_neigh_next_root_port, "st_tcntx") >= 1:
                res2 = 0
                st.error("operation_failed_msg - TX TCN counters are not incremented")
            else:
                st.log("On root's nbr bridge ..on new root port, TX TCN counters are incrementing correctly")
        else:
            if stp.get_stp_stats(root_neigh, randon_vlan, root_neigh_next_root_port, "st_tcntx") != 0:
                res2 = 0
                st.error("operation_failed_msg - TX TCN counters are incremented")
            else:
                st.log("On root's nbr bridge ..on new root port, TX TCN counters are not incrementing as expected")

        root_next_root_port = stp_wrap.get_dut_links_remote(root_bridge, root_neigh, root_neigh_next_root_port)
        st.log("root_next_root_port : {}".format(root_next_root_port))

        if stp_protocol == "pvst":
            if not stp.get_stp_stats(root_bridge, randon_vlan, root_next_root_port, "st_tcnrx") >= 1:
                res2 = 0
                st.error("operation_failed_msg - RX TCN counters are not incremented")
            else:
                st.log("On root's nbr bridge ..on new root port, RX TCN counters are incrementing correctly")
        else:
            if stp.get_stp_stats(root_bridge, randon_vlan, root_next_root_port, "st_tcnrx") != 0:
                res2 = 0
                st.error("operation_failed_msg - RX TCN counters are incremented")
            else:
                st.log("On root's nbr bridge ..on new root port, RX TCN counters are not incrementing as expected")

        # Verification of ROOT port
        st.log("Verify on root's nbr bridge , whether next best port becomes root port and go to FWDing state")
        if stp.get_stp_root_port(root_neigh,randon_vlan) == root_neigh_next_root_port:
            st.log("On root's nbr bridge, next best port became the root port correctly !!")
        else:
            res1 = 0
            st.error("On root's nbr bridge, next best port did not become the root port. This is WRONG !!")

        ### Verification of FWDing state
        if stp.verify_stp_ports_by_state(root_neigh, randon_vlan, "FORWARDING", root_neigh_next_root_port):
            st.log("On root's nbr bridge, next best port went to FORWARDING correctly !!")
        else:
            res1 = 0
            st.error("On root's nbr bridge, next best port did not go into forwarding. This is WRONG !!")

        intf.interface_noshutdown(root_neigh, root_neigh_root_port)
        st.log("After no shut of Root port, verify that old root port becomes new root port again")
        st.wait(stp_dict[stp_protocol]["stp_wait_time"])

        if stp.get_stp_root_port(root_neigh,randon_vlan) == root_neigh_root_port:
            st.log("On root's nbr bridge, old root port became the root port again after shut no shut. PASS")
        else:
            res1 = 0
            st.error("On root's nbr bridge, old root port did not become the root port again after shut no shut. FAIL !!")

    if res1:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_port_shut_noshut'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_port_shut_noshut'.format(stp_protocol),'test_case_failed')

    if res2:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_statistics'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_statistics'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of TX and RX TCN stats, next best root port by shut and no shut of interface -- COMPLETED")
    #############################################################################################

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))

    stp.config_stp_vlan_parameters_parallel([root_bridge] * len(stp_wrap.get_dut_list(vars)), False,vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"],priority=[32768] * len(stp_wrap.get_dut_list(vars)))
    stp.config_stp_vlan_parameters_parallel(stp_wrap.get_dut_list(vars),vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"],priority=[0] * len(stp_wrap.get_dut_list(vars)))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars),stp_wrap.complete_data["vlan_data"]["vlan_list"],stp_wrap.complete_data["dut_vlan_data"])
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_port_actions(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    random_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(random_vlan))

    root_bridge = stp_ela['states'][random_vlan]['root']
    st.log("Topology root bridge:  {}".format(root_bridge))

    root_ph_port = stp_wrap.get_physical_link_with_partner(root_bridge)[root_bridge][0]['local']
    st.log("Root port:  {}".format(root_ph_port))

    st.log("Displaying the spanning tree out on {} in vlan : {}".format(root_bridge, random_vlan))
    stp.show_stp_vlan(root_bridge, random_vlan)

    st.log("Getting details of a DUT with TG connected port")
    dut_tg_info  = stp_wrap.get_random_dut_tg_interface(no_of_duts=3,no_of_links=1)
    st.log("dut_tg: {} ".format(dut_tg_info))

    st.log("Device with Tg")
    dut_tg = dut_tg_info['dut']
    st.log("DUT with TG is : {}".format(dut_tg))

    st.log("Getting Tg link info")
    dut_tglink = dut_tg_info['physical_link']
    st.log("Physical link connected to tg is : {} ".format(dut_tglink))

    #############################################################################################
    utils.banner_log("Verification of portfast enabled port is immediately moved to Forwarding state after shut and no shut -- STARTED")
    #############################################################################################
    if stp_protocol == "pvst":
        res = 1
        utils.banner_log("Enabling port fast config on TG link")
        stp.config_stp_interface_params(dut_tg, dut_tglink, portfast="enable")
        st.wait(2)
        if stp.get_stp_port_param(dut_tg, random_vlan, dut_tglink, "port_portfast") == "Y":
            st.log("Port fast is enabled on TG link.")
        else:
            res = 0
            st.error("Port fast is no enabled on TG link.")

        intf.interface_shutdown(dut_tg, dut_tglink)
        if not stp.poll_for_stp_status(dut_tg,random_vlan,dut_tglink,'DISABLED',iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
            res = 0
            st.error("Interface {} did not move to DISABLED state".format(dut_tglink))
            intf.interface_noshutdown(dut_tg, dut_tglink)
        else:
            st.log("Interface {} moved to DISABLED state as expected".format(dut_tglink))

        intf.interface_noshutdown(dut_tg, dut_tglink)
        if not stp.poll_for_stp_status(dut_tg, random_vlan, dut_tglink, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            res = 0
            st.error("Interface {} is not moving to Forwarding state immediately".format(dut_tglink))
        else:
            st.log("Interface {} is moving to Forwarding state immediately".format(dut_tglink))

        if res:
            pass_cnt+=1
            st.report_tc_pass('ft_{}_portfast'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.report_tc_fail('ft_{}_portfast'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of portfast enabled port is immediately moved to Forwarding state after shut and no shut -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of interface level disable and enable of STP protocol -- STARTED")
    #############################################################################################
    res = 1
    utils.banner_log("root bridge is : {}".format(root_bridge))
    utils.banner_log("Root port is  : {}".format(root_ph_port))
    dut_partner_details = stp_wrap.get_dut_partner_details_by_dut_interface(root_bridge, root_ph_port)
    st.log("partner_details: {}".format(dut_partner_details))

    if root_ph_port in dut_partner_details[root_bridge]:
        local_interface_index = dut_partner_details[root_bridge].index(root_ph_port)
    else:
        local_interface_index = None
    st.log("Local Interface Index: {}".format(local_interface_index))

    dut_nonroot_list = list()
    partner_dut = ''
    for dut in dut_partner_details:
        if dut != root_bridge:
            dut_nonroot_list.append(dut)

    st.log("List of DUTs excluding current root bridge is {}".format(dut_nonroot_list))
    partner_dut = stp.get_default_root_bridge(dut_nonroot_list)
    st.log("Next root bridge is {}".format(partner_dut))

    if partner_dut and local_interface_index!=None:
        remote_interface = dut_partner_details[partner_dut][local_interface_index]
        next_root_remote = stp.get_stp_next_root_port(partner_dut, random_vlan)

        st.log("Disabling {} at interface level on {}".format(stp_protocol,partner_dut))
        stp.config_stp_enable_interface(partner_dut, remote_interface, mode="disable")
        if not poll_wait(stp.verify_stp_intf_status, 40, partner_dut, random_vlan, next_root_remote, 'FORWARDING'):
            res = 0
            st.error("Next root port on {} did not move to Forwarding state".format(partner_dut))
            stp.config_stp_enable_interface(partner_dut, remote_interface, mode="enable")
        else:
            st.log("Next root port on {} moved to Forwarding state as expected".format(partner_dut))

        st.log("Enabling {} at interface level on {}".format(stp_protocol,partner_dut))
        stp.config_stp_enable_interface(partner_dut, remote_interface, mode="enable")
        st.wait(5)
        if not poll_wait(stp.verify_stp_intf_status, 40 ,partner_dut, random_vlan, remote_interface, 'FORWARDING'):
            res = 0
            st.error("Previous root port on {} did not move to Forwarding state. FAIL".format(partner_dut))
        else:
            st.log("Previous root port on {} moved to Forwarding state. PASS".format(partner_dut))

    if res:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_interface_{}_disable_enable'.format(stp_protocol, stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_interface_{}_disable_enable'.format(stp_protocol, stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of interface level disable and enable of STP protocol -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of Root guard functinality -- STARTED")
    #############################################################################################
    res, res1 = 1, 1
    st.log("Getting the dut list excluding the root and next root and removing them from stp by disabling stp on vlan")
    dut_list = stp_wrap.get_dut_list(vars)
    st.log("DUT LIST : {}".format(dut_list))
    dut_list_excluding_root_and_non_root = dut_list
    dut_list_excluding_root_and_non_root.remove(root_bridge)
    dut_list_excluding_root_and_non_root.remove(partner_dut)
    st.log("DUT LIST AFTER EXCLUDING ROOT AND NEXT BEST ROOT: {}".format(dut_list_excluding_root_and_non_root))

    for d in dut_list_excluding_root_and_non_root:
        stp.config_spanning_tree(d, feature=stp_protocol, mode="disable", vlan=random_vlan)

    st.log("Disabling {} on root switch for vlan {} on root switch {}".format(stp_protocol,random_vlan, root_bridge))
    stp.config_spanning_tree(root_bridge, feature=stp_protocol, mode="disable", vlan=random_vlan)
    st.wait(3)
    st.log("Configuring non root switch interface with root guard")
    intflist = stp.get_stp_port_list(partner_dut, random_vlan, exclude_port="")
    for i in intflist:
        stp.config_stp_interface_params(partner_dut, i, root_guard="enable")
    if not stp.check_rg_current_state(partner_dut, random_vlan, remote_interface):
        res = 0
        st.error("Interface on non root bride is not in consistent state")

    rootguard_incon_count1 = slog.get_logging_count(partner_dut, severity="INFO",filter_list=["Root Guard interface {}, VLAN {} inconsistent (Received superior BPDU)".format(remote_interface, random_vlan)])
    rootguard_con_count1 = slog.get_logging_count(partner_dut, severity="INFO",filter_list=["Root Guard interface {} VLAN {} consistent (Timeout)".format(remote_interface, random_vlan)])

    st.log("Enabling {} on root switch for vlan {} on root switch {}".format(stp_protocol,random_vlan, root_bridge))
    stp.config_spanning_tree(root_bridge, feature=stp_protocol, mode="enable", vlan=random_vlan)
    st.wait(5)
    if stp.check_rg_current_state(partner_dut, random_vlan, remote_interface):
        res = 0
        st.error("Interface is not in inconsistent state on receiving superior BPDU")
    else:
        st.log("Interface enabled with root guard moved to inconsistent state as expected")

    st.wait(3)
    rootguard_incon_count2 = slog.get_logging_count(partner_dut, severity="INFO",filter_list=["Root Guard interface {}, VLAN {} inconsistent (Received superior BPDU)".format(remote_interface, random_vlan)])
    if not rootguard_incon_count2 > rootguard_incon_count1:
        res1 = 0
        st.error("Root guard syslog generated count {} is not correct".format(rootguard_incon_count2))
    else:
        st.log("Root guard syslog generated count {} is correct".format(rootguard_incon_count2))

    if not stp.get_stp_port_param(partner_dut, random_vlan, remote_interface, 'port_state') == "ROOT-INC":
        res = 0
        st.error("Interface {} did not move to ROOT-INC state".format(remote_interface))
    else:
        st.log("Interface {} moved to ROOT-INC state as expected".format(remote_interface))

    rg_timeout = stp.get_root_guard_details(partner_dut, rg_param="rg_timeout")
    stp.config_spanning_tree(root_bridge, feature=stp_protocol, mode="disable", vlan=random_vlan)
    st.wait(3)
    st.log("waiting to verify the port moving to consistent state after expiry of root guard timeout")
    if not poll_wait(stp.check_rg_current_state, rg_timeout, partner_dut, random_vlan, remote_interface):
        res = 0
        st.error("Interface is not in consistent state even after root guard timeout")
    else:
        st.log("Interface moved to consistent state as expected after root guard timeout expiry")

    st.log("removing root guard on partner device  interface")
    stp.show_stp(partner_dut, sub_cmd="root_guard")
    rootguard_con_count2 = slog.get_logging_count(partner_dut, severity="INFO",filter_list=["Root Guard interface {} VLAN {} consistent (Timeout)".format(remote_interface, random_vlan)])
    if not rootguard_con_count2 > rootguard_con_count1:
        res1 = 0
        st.error("Root guard syslog generated count {} is not correct".format(rootguard_con_count2))
    else:
        st.log("Root guard syslog generated count {} is correct".format(rootguard_con_count2))

    for i in intflist:
        stp.config_stp_interface_params(partner_dut, i, root_guard="disable")
    stp.config_spanning_tree(root_bridge, feature=stp_protocol, mode="enable", vlan=random_vlan)
    for d in dut_list_excluding_root_and_non_root:
        stp.config_spanning_tree(d, feature=stp_protocol, mode="enable", vlan=random_vlan)
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    if res:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_rootguard'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_rootguard'.format(stp_protocol),'test_case_failed')

    if res1:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_log_events'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_log_events'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of Root guard functinality -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of BPDU guard functinality -- STARTED")
    #############################################################################################
    res = 1
    st.log("Configuring non root switch interface with bpdu guard with no shutdown action")
    stp.config_stp_interface_params(partner_dut, remote_interface, bpdu_guard="enable")
    if not stp.check_bpdu_guard_action(partner_dut, remote_interface, config_shut="No", opr_shut="NA"):
        res = 0
        st.error("Interface {} is not enabled with proper BPDU guard parameters".format(remote_interface))
    else:
        st.log("Interface {} is configured with proper BPDU guard options when shutdown is not configured".format(remote_interface))

    st.log("Verifying BPDU guard syslog is generated fine...")
    bpduguard_log_count1 = slog.get_logging_count(partner_dut, severity = "INFO", filter_list = ["{} disabled due to BPDU guard trigger".format(remote_interface)])

    stp.config_stp_interface_params(partner_dut, remote_interface, bpdu_guard_action="--shutdown")
    st.wait(5)
    if not stp.check_bpdu_guard_action(partner_dut, remote_interface, config_shut="Yes", opr_shut="Yes"):
        res=0
        st.error("Interface {} is not enabled with BPDU guard shutdown parameters".format(remote_interface))
    else:
        st.log("Interface {} is enabled with BPDU guard shutdown option".format(remote_interface))

    if not stp.get_stp_port_param(partner_dut, random_vlan, remote_interface, "port_state") == "BPDU-DIS":
        res=0
        st.error("Interface {} did not move to disabled state when BPDU shutdown action is configured and DUT received a BPDU".format(remote_interface))
    else:
        st.log("Interface {} moved to BPDU-DIS state as expected".format(remote_interface))

    bpduguard_log_count2 = slog.get_logging_count(partner_dut, severity="INFO",filter_list=["{} disabled due to BPDU guard trigger".format(remote_interface)])
    if not bpduguard_log_count2 > bpduguard_log_count1:
        res=0
        st.error("BPDU guard syslog generated count {} is not correct".format(bpduguard_log_count2))
    else:
        st.log("BPDU guard syslog generated count {} is correct".format(bpduguard_log_count2))

    st.log("Disabling spanning tree on {} interface connected towards {} so that no BPDUs are received".format(root_bridge, partner_dut))
    stp.config_stp_enable_interface(root_bridge, root_ph_port, mode="disable")
    intf.interface_shutdown(partner_dut, remote_interface)
    st.wait(1)
    intf.interface_noshutdown(partner_dut, remote_interface)
    st.wait(5)
    if stp.get_stp_port_param(partner_dut,random_vlan, remote_interface, "port_state") == "BPDU-DIS":
        res=0
        st.error("Interface {} is still disabled due to BPDU guard".format(remote_interface))
    else:
        st.log("Interface {} is not in BPDU-DIS state as expected".format(remote_interface))

    st.log("Removing BPDU guard config")
    stp.config_stp_interface_params(partner_dut, remote_interface, bpdu_guard="disable")
    st.log("Enabling STP back on interface")
    stp.config_stp_enable_interface(root_bridge, root_ph_port, mode="enable")

    if res:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_bpduguard'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_bpduguard'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of BPDU guard functinality -- COMPLETED")
    #############################################################################################

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_portchannel(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    random_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(random_vlan))

    st.log("Get local and remote DUTs for port channel; and get port channel name")
    portchannel_data = stp_wrap.get_portchannel_details()
    for key, value in portchannel_data.items():
        port_channel_name = key
        local_dut_for_po = value["partners"][0]
        remote_dut_for_po = value["partners"][1]

    st.log(st.get_links(local_dut_for_po, remote_dut_for_po))

    path_cost_initial = stp.get_stp_port_param(local_dut_for_po, random_vlan, port_channel_name,'port_pathcost')
    portchannel_interfaces = stp_wrap.get_portchannel_interfaces(local_dut_for_po, remote_dut_for_po)
    st.log("portchannel_interfaces : {} ".format(portchannel_interfaces))

    st.log("Clearing stp statistics")
    stp.stp_clear_stats(local_dut_for_po, vlan=random_vlan)

    st.log("Getting random interface")
    portchannel_member_port = random.choice(portchannel_interfaces[local_dut_for_po])

    portchannel.delete_portchannel_member(local_dut_for_po,port_channel_name,portchannel_member_port)
    if not portchannel.verify_portchannel_member(local_dut_for_po,port_channel_name,portchannel_member_port,flag='del'):
        st.error("portchannel member is {} not deleted".format(portchannel_member_port))
    else:
        st.log("portchannel member deletion successful")

    #############################################################################################
    utils.banner_log("Verification of port channel member path cost after deleting it from port channel -- STARTED")
    #############################################################################################
    path_cost_after= stp.get_stp_port_param(local_dut_for_po, random_vlan, port_channel_name, 'port_pathcost')
    if not path_cost_initial == path_cost_after:
        fail_cnt+=1
        st.error("Path cost of portchannel got changed after deleting a member. FAILED")
        st.report_tc_fail('ft_{}_portchannel_cost_member_remove_add'.format(stp_protocol),'test_case_failed')
    else:
        pass_cnt+=1
        st.log("Path cost of porthannel did not change after deletion of member port. PASS")
        st.report_tc_pass('ft_{}_portchannel_cost_member_remove_add'.format(stp_protocol),'test_case_passed')
    #############################################################################################
    utils.banner_log("Verification of port channel member path cost after deleting it from port channel -- COMPLETED")
    #############################################################################################

    portchannel.add_portchannel_member(local_dut_for_po, port_channel_name, portchannel_member_port)
    if not portchannel.verify_portchannel_member(local_dut_for_po,port_channel_name,portchannel_member_port,flag='add'):
        st.error("portchannel member is {} not added".format(portchannel_member_port))
    else:
        st.log("Portchannel member is successfully added back")

    st.wait(5)
    #############################################################################################
    utils.banner_log("Verification of no TCN when port channel member is deleted and added back -- STARTED")
    #############################################################################################
    if not stp.get_stp_stats(local_dut_for_po, random_vlan, port_channel_name, "st_tcntx") == 0:
        fail_cnt+=1
        st.error("operation_failed_msg - TX TCN counters are incremented when portchannel member is deleted and added. FAIL")
        st.report_tc_fail('ft_{}_portchannel_no_tc_member_del_add'.format(stp_protocol),'test_case_failed')
    else:
        pass_cnt+=1
        st.log("TCN counters are not incremented on portchannel on deleting and adding a member as expected. PASS")
        st.report_tc_pass('ft_{}_portchannel_no_tc_member_del_add'.format(stp_protocol),'test_case_passed')
    #############################################################################################
    utils.banner_log("Verification of no TCN when port channel member is deleted and added back -- COMPLETED")
    #############################################################################################

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_traffic(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    dut_list = stp_wrap.get_dut_list(vars)

    #############################################################################################
    utils.banner_log("Verification of end to end Multicast traffic -- STARTED")
    #############################################################################################
    mac.get_mac_all_dut(dut_list)
    if stp_wrap.verify_traffic('multicast', stp_wrap.tg_info):
       pass_cnt+=1
       st.log("Multicast traffic test PASSED")
    else:
       fail_cnt+=1
       st.error("Multicast traffic verification test FAILED !!")
    #############################################################################################
    utils.banner_log("Verification of end to end Multicast traffic -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of end to end Broadcast traffic -- STARTED")
    #############################################################################################
    mac.get_mac_all_dut(dut_list)
    if stp_wrap.verify_traffic('broadcast', stp_wrap.tg_info):
       pass_cnt+=1
       st.log("Broadcast traffic verification test PASSED")
    else:
       fail_cnt+=1
       st.error("Broadcast traffic verification test FAILED !!")
    #############################################################################################
    utils.banner_log("Verification of end to end Broadcast traffic -- COMPLETED")
    #############################################################################################

    mac.get_mac_all_dut(dut_list)

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_default_convergence(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    global new_vlan
    dut_nonroot_list=list()

    dut_list = stp_wrap.get_dut_list(vars)
    st.log("Dut list : {}".format(dut_list))

    vlan_list = stp_wrap.complete_data["vlan_data"]["vlan_list"]
    st.log("Existig vlan_list is : {}".format(vlan_list))

    st.log("Creating a new vlan")
    new_vlan = random_vlan_list(count=1,exclude=vlan_list)
    st.log("new_vlan is :{}".format(new_vlan))

    st.log("creating new vlan in all dut_lists")
    stp_wrap.config_all_vlan_in_all_duts(dut_list,new_vlan,thread=True,action="add")

    st.log("adding untagged member to vlan {} which is newly created".format(new_vlan))
    config_untagged_vlan_members_to_device(stp_wrap.complete_data["vlan_data"],thread=True,mode="add")

    stp_wrap.show_vlan_breif_on_all_duts(dut_list)
    new_vlan = int(new_vlan[0])

    # This block of code has to be removed ONLY if defect "SONIC-24567 : Sonic - SONIC_3.1.0 - STP OCYANG : STP is not enabled on the new vlan created via REST." is fixed
    if stp_cli_type in ["rest-put", "rest-patch"]:
        st.log("Disabling {} on all the duts".format(stp_protocol))
        stp.config_stp_in_parallel(stp_wrap.get_dut_list(vars), feature=stp_protocol, mode="disable")
        st.wait(5)
        st.log("Enabling {} on all the duts".format(stp_protocol))
        stp.config_stp_in_parallel(stp_wrap.get_dut_list(vars), feature=stp_protocol, mode="enable")
        st.wait(5)

        stp.config_stp_vlan_parameters_parallel(stp_wrap.get_dut_list(vars), vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"], priority=[0]*len(stp_wrap.get_dut_list(vars)))

        if stp_protocol == "rpvst":
            dut_list = stp_wrap.get_dut_list(vars)
            for dut in dut_list:
                for vlan_id in stp_wrap.complete_data["vlan_data"]["vlan_list"]:
                    stp.config_stp_vlan_parameters(dut, vlan_id, max_age=stp_dict["rpvst"]["stp_max_age"])
                for interf in stp_ela[dut]['tg_links']:
                    stp.config_port_type(dut, interf[0], stp_type='rpvst', port_type='edge', no_form=False)

        st.log("Waiting for {} to converge".format(stp_protocol))
        st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    st.log("Getting device with lowest mac which should become the root switch when priority is default")
    default_root_bridge = stp.get_default_root_bridge(dut_list)
    st.log("{} is the root bridge when priority is not configured".format(default_root_bridge))
    if default_root_bridge is None:
        fail_cnt+=4
        st.error("Did not find default root bridge in the topology")
    else:
        #############################################################################################
        utils.banner_log("Verification of default convergence in random vlan -- STARTED")
        #############################################################################################
        if not stp.poll_for_root_switch(default_root_bridge, new_vlan, iteration=30, delay=1):
            fail_cnt+=3
            st.error("{} is not root switch for vlan {}".format(default_root_bridge, new_vlan))
        else:
            pass_cnt+=3
            st.log("{} is root switch for vlan {}".format(default_root_bridge, new_vlan))

        st.log("getting list of duts excluding root switch")
        for dut in dut_list:
            if dut != default_root_bridge:
                dut_nonroot_list.append(dut)

        st.log("dut list is: {} and non root switch list is: {}".format(dut_list, dut_nonroot_list))
        non_root =random.choice(dut_nonroot_list)

        st.log("Non root switch {} is checked for convergence".format(non_root))
        if stp.poll_for_root_switch(non_root, new_vlan, iteration=5, delay=1):
            fail_cnt+=1
            st.error("{} is also root switch for vlan {} which is not expected".format(non_root, new_vlan))
        else:
            pass_cnt+=1
            st.log("{} is not root switch for vlan {} as expected".format(non_root, new_vlan))
        #############################################################################################
        utils.banner_log("Verification of default convergence in random vlan -- COMPLETED")
        #############################################################################################

    st.log("unconfiguring new vlan config and bringing back to module config")
    config_untagged_vlan_members_to_device(stp_wrap.complete_data["vlan_data"], thread=True, mode="del")

    st.log("Unconfiguring new vlan {} in all DUTs".format(new_vlan))
    stp_wrap.config_all_vlan_in_all_duts(dut_list, new_vlan, thread=True, action="del")

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_cost_priority(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    src_mac = stp_wrap.src_tg1_vlan_inc_mac_fix_unknown
    st.log("src_mac is : {}".format(src_mac))

    random_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(random_vlan))

    dut_list = stp_wrap.get_dut_list(vars)
    vlan_list = stp_wrap.complete_data["vlan_data"]["vlan_list"]
    st.log("Existig vlan_list is : {}".format(vlan_list))

    st.log("Getting vlan list excluding the {}".format(random_vlan))
    new_vlan_list = list()
    for vlan in vlan_list:
        if vlan != random_vlan:
            new_vlan_list.append(vlan)
    st.log("new_vlan list is : {}".format(new_vlan_list))

    st.log("getting new vlan from vlan list")
    new_vlan = new_vlan_list[0]

    st.log("Clearing stats before sending traffic ...")
    tgapi.traffic_action_control(stp_wrap.tg_info['tg_info'], actions=['clear_stats'])
    st.wait(5)
    tg = stp_wrap.tg_info['tg_info']['tg']
    tg_ph_1 = stp_wrap.tg_info['tg_info']["tg_ph_1"]
    tg_ph_2 = stp_wrap.tg_info['tg_info']["tg_ph_2"]
    tg_ph_3 = stp_wrap.tg_info['tg_info']["tg_ph_3"]
    tg_rate_pps = 10000
    tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_percent=1,mac_src="00:00:00:00:10:00", rate_pps=tg_rate_pps,mac_src_mode="increment",transmit_mode="continuous",mac_dst="00:00:00:00:10:01", mac_dst_mode="fixed",l2_encap='ethernet_ii_vlan',vlan_id=new_vlan, vlan="enable")
    stream_id_1 = tg_1['stream_id']
    tg_2 = tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_percent=1,mac_src="00:00:00:00:10:01", rate_pps=tg_rate_pps,mac_src_mode="increment",transmit_mode="continuous",mac_dst="00:00:00:00:10:00", mac_dst_mode="fixed",l2_encap='ethernet_ii_vlan',vlan_id=new_vlan, vlan="enable")
    stream_id_2 = tg_2['stream_id']
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_unicast'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_unknown'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_multicast'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_broadcast'])
    tg.tg_traffic_config(mode='enable', stream_id=stream_id_1)
    tg.tg_traffic_config(mode='enable', stream_id=stream_id_2)
    stream_list = [stream_id_1, stream_id_2]

    st.log("Getting a pair of nodes with one DUT having one Fwding and one {} port".format(stp_dict[stp_protocol]["non_fwd_state"]))
    port_states = stp_wrap.get_blocking_brigde_with_interfaces(random_vlan, stp_protocol)
    st.log("port_states output is {}".format(port_states))

    dut_blocking = ""
    dut_forwarding = ""
    for key in port_states:
        if len(port_states[key]['forwarding']) == 1:
            dut_blocking = key
        else:
            dut_forwarding = key

    st.log("DUT having {} port is {} and DUT having all forwarding ports is {}".format(stp_dict[stp_protocol]["non_fwd_state"],dut_blocking, dut_forwarding))
    if not dut_blocking:
        fail_cnt+=6
        st.error("{} interface not found on either of the devices.".format(stp_dict[stp_protocol]["non_fwd_state"]))
    else:
        blocked_port = port_states[dut_blocking]['blocking'][0]
        forwarding_port = port_states[dut_blocking]['forwarding'][0]
        if not stp.get_stp_port_param(dut_blocking, random_vlan, blocked_port, "port_state") == stp_dict[stp_protocol]["non_fwd_state"]:
            st.error("Interface under test {} is not in {} state".format(blocked_port,stp_dict[stp_protocol]["non_fwd_state"]))
        else:
            st.log("Interface under test {} is in {} state as expected".format(blocked_port,stp_dict[stp_protocol]["non_fwd_state"]))

        if not stp.get_stp_port_param(dut_blocking, random_vlan, forwarding_port, "port_state") == "FORWARDING":
            st.error("Interface under test {} is not in Forwarding state".format(forwarding_port))
        else:
            st.log("Interface under test {} is in Forwarding state as expected".format(forwarding_port))

        #############################################################################################
        utils.banner_log("Verification of lowering cost on a {} port will move it to FORWARDING state. -- STARTED".format(stp_dict[stp_protocol]["non_fwd_state"]))
        #############################################################################################
        res = 1
        old_cost = stp.get_stp_port_param(dut_blocking, random_vlan, blocked_port, 'port_pathcost')
        new_cost = 10

        mac.get_mac_all_dut(dut_list)

        tg.tg_traffic_control(action='run', stream_handle = stream_list)
        st.wait(5)
        tg.tg_traffic_control(action='stop', stream_handle = stream_list)
        mac.get_mac_all_dut(dut_list)
        tgapi.traffic_action_control(stp_wrap.tg_info['tg_info'], actions=['clear_stats'])
        st.wait(5)
        tg.tg_traffic_control(action='run', stream_handle = stream_list)

        stp.config_stp_vlan_interface(dut_blocking, random_vlan, blocked_port, new_cost, mode='cost')
        st.wait(6)
        if not int(stp.get_stp_port_param(dut_blocking, random_vlan, blocked_port, 'port_pathcost')) == new_cost:
            res = 0
            st.error("Cost is not configured properly on interface {} in vlan {} on dut {}".format(blocked_port,random_vlan,dut_blocking))
        else:
            st.log("Cost is configured fine on interface {} in vlan {} on dut {}".format(blocked_port, random_vlan,dut_blocking))

        if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            res = 0
            st.error("Interface {} on {} in vlan {} is not moved to Forwarding state when lower cost is configured..".format(blocked_port, dut_blocking, random_vlan))
        else:
            st.log("Interface {} on {} in vlan {} is moved to Forwarding state when lower cost is configured..".format(blocked_port,dut_blocking, random_vlan))

        tg.tg_traffic_control(action='stop', stream_handle = stream_list)
        tg.tg_traffic_config(mode='disable', stream_id=stream_id_1)
        tg.tg_traffic_config(mode='disable', stream_id=stream_id_2)
        st.wait(10)
        stat1 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_1)
        stat2 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_2)
        tx_tg1_99_precentage = (99 * int(stat1.tx.total_packets)) / 100
        tx_tg2_99_precentage = (99 * int(stat2.tx.total_packets)) / 100
        if not (stat2.rx.total_packets >= tx_tg1_99_precentage and stat1.rx.total_packets >= tx_tg2_99_precentage):
            res = 0
            st.error("Traffic verification in vlan {} failed ...".format(new_vlan))
        else:
            st.log("Traffic verification in vlan {} is not impacted when cost is changed in vlan {}".format(new_vlan,random_vlan))

        mac.get_mac_all_dut(dut_list)

        st.log("changing the cost back to original value:")
        stp.config_stp_vlan_interface(dut_blocking, random_vlan, blocked_port, old_cost, mode='cost')
        if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, stp_dict[stp_protocol]["non_fwd_state"], iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            res = 0
            st.error("Interface under test {} is not in {} state".format(blocked_port,stp_dict[stp_protocol]["non_fwd_state"]))
        else:
            st.log("Interface under test {} is in {} state as expected".format(blocked_port,stp_dict[stp_protocol]["non_fwd_state"]))

        if res:
            pass_cnt+=1
            st.report_tc_pass('ft_{}_portcost_in_single_instance'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.report_tc_fail('ft_{}_portcost_in_single_instance'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verification of lowering cost on a {} port will move it to FORWARDING state. -- COMPLETED".format(stp_dict[stp_protocol]["non_fwd_state"]))
        #############################################################################################

        #############################################################################################
        utils.banner_log("Verification of link add delete. -- STARTED")
        #############################################################################################
        res = 1
        st.log("Disabling stp on interface {} in Fwding state on {}".format(forwarding_port, dut_blocking))
        stp.config_stp_enable_interface(dut_blocking, forwarding_port, mode="disable")
        if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            res = 0
            st.error("Dut {} with {} port {} did not move to Forwarding state on disabling stp on Fwding port".format(dut_blocking, stp_dict[stp_protocol]["non_fwd_state"], blocked_port))
        else:
            st.log("Dut {} with {} port {} moved to Forwarding state as expected on disabling stp on Fwding port".format(dut_blocking, stp_dict[stp_protocol]["non_fwd_state"], blocked_port))

        st.log("Enabling back stp on interface {} on DUT {} ".format(forwarding_port, dut_blocking))
        stp.config_stp_enable_interface(dut_blocking, forwarding_port, mode="enable")
        st.wait(5)
        if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            res = 0
            st.error("Previous root port on {} did not move to Forwarding state. FAIL".format(dut_blocking))
        else:
            st.log("Previous root port on {} moved to Forwarding state. PASS".format(dut_blocking))

        if res:
            pass_cnt+=1
            st.report_tc_pass('ft_{}_link_add_del'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.report_tc_fail('ft_{}_link_add_del'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verification of link add delete. -- COMPLETED")
        #############################################################################################

        dut_partner_details = stp_wrap.get_dut_partner_details_by_dut_interface(dut_blocking, blocked_port)
        st.log("partner_details: {}".format(dut_partner_details))

        local_interface_index = dut_partner_details[dut_blocking].index(blocked_port)
        partner_dut = ''
        for key in dut_partner_details:
            if key != dut_blocking:
                partner_dut = key

        if partner_dut:
            #############################################################################################
            utils.banner_log("Verification of port priority. -- STARTED")
            #############################################################################################
            res = 1
            remote_interface = dut_partner_details[partner_dut][local_interface_index]
            old_priority = stp.get_stp_port_param(partner_dut,random_vlan,remote_interface,'port_priority')
            new_priority = 16

            stp.config_stp_vlan_interface(partner_dut, random_vlan,remote_interface, new_priority, mode='priority')
            st.wait(5)
            if not int(stp.get_stp_port_param(partner_dut, random_vlan, remote_interface, 'port_priority')) == new_priority:
                res = 0
                st.error("Priority is not configured properly on interface {} in vlan {} on dut {}".format(partner_dut, random_vlan,remote_interface))
            else:
                st.log("Priority is configured fine on interface {} in vlan {} on dut {}".format(partner_dut, random_vlan,remote_interface))

            if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
                res = 0
                st.error("Interface {} on {} is not moved to Forwarding state when lower priority is configured..".format(blocked_port, dut_blocking))
            else:
                st.log("Interface {} on {} is moved to Forwarding state when lower priority is configured..".format(blocked_port, dut_blocking))

            st.log("changing the priority back to original value:")
            stp.config_stp_vlan_interface(partner_dut, random_vlan, remote_interface, old_priority, mode='priority')
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, stp_dict[stp_protocol]["non_fwd_state"],iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                res = 0
                st.error("Interface under test {} is not in {} state after reverting back the original priority on peer DUT".format(blocked_port,stp_dict[stp_protocol]["non_fwd_state"]))
            else:
                st.log("Interface under test {} is in {} state as expected".format(blocked_port,stp_dict[stp_protocol]["non_fwd_state"]))

            if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, "FORWARDING",iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
                res = 0
                st.error("Interface {} is not in Forwarding state after reverting back the original priority on peer DUT".format(forwarding_port))
            else:
                st.log("Interface under test {} is in {} state as expected".format(blocked_port,stp_dict[stp_protocol]["non_fwd_state"]))

            if res:
                pass_cnt+=1
                st.report_tc_pass('ft_{}_portpriority'.format(stp_protocol),'test_case_passed')
            else:
                fail_cnt+=1
                st.report_tc_fail('ft_{}_portpriority'.format(stp_protocol),'test_case_failed')
            #############################################################################################
            utils.banner_log("Verification of port priority. -- COMPLETED")
            #############################################################################################

            #############################################################################################
            utils.banner_log("Verification of fdb flush is happening when cost is changed in interface level. -- STARTED")
            #############################################################################################
            res = 1
            stp_wrap.verify_traffic('vlan_inc_mac_fix_unknown', stp_wrap.tg_info, skip_traffic_verify=True)
            tg = stp_wrap.tg_info['tg_info']['tg']
            tg_ph_1 = stp_wrap.tg_info['tg_info']["tg_ph_1"]
            mac.get_mac_all_dut(dut_list)

            st.log("Test scenario to verify that failure on a root will impact traffic on vlans")
            tg.tg_traffic_control(action='run', stream_handle= stp_wrap.tg_info['tg1_vlan_inc_mac_fix_unknown'])
            st.wait(5)
            tg.tg_traffic_control(action='stop', stream_handle= stp_wrap.tg_info['tg1_vlan_inc_mac_fix_unknown'])

            total_mac_cnt = len(mac.get_mac_address_list(dut_blocking, mac=src_mac, vlan=random_vlan))
            st.log("MAC entries with smac {} in vlan {} learnt on dut {} before change of cost is : {}".format(src_mac, random_vlan, dut_blocking, total_mac_cnt))

            st.log("Changing the interface cost")
            stp.config_stp_interface_params(dut_blocking, blocked_port, cost=new_cost)

            st.log("Wait for mac address  to flush")
            st.wait(stp_dict[stp_protocol]["stp_wait_time"])

            st.log("Test scenario to verify that lowering cost on a {} port will move it to Fwding state".format(stp_dict[stp_protocol]["non_fwd_state"]))
            if not int(stp.get_stp_port_param(dut_blocking, random_vlan, blocked_port, 'port_pathcost')) == new_cost:
                res = 0
                st.error("Cost is not configured properly on interface {} in vlan {} on dut {}".format(blocked_port,random_vlan,dut_blocking))
            else:
                st.log("Cost is configured fine on interface {} in vlan {} on dut {}".format(blocked_port, random_vlan,dut_blocking))

            if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
                res = 0
                st.error("Interface {} on {} in vlan {} is not moved to Forwarding state when lower cost is configured..".format(blocked_port, dut_blocking, random_vlan))
            else:
                st.log("Interface {} on {} in vlan {} is moved to Forwarding state when lower cost is configured..".format(blocked_port,dut_blocking, random_vlan))

            stp.get_stp_port_param(dut_blocking, random_vlan, forwarding_port, "port_state")
            mac.get_mac(dut_blocking)

            if stp_protocol == "rpvst":
                edge_port_mac_cnt = 0
                for iface in stp_ela[dut_blocking]['tg_links']:
                    mlist = mac.get_mac_address_list(dut_blocking, mac=src_mac, vlan=random_vlan, port=iface[0])
                    st.log("mlist: {}".format(mlist))
                    if len(mlist):
                        st.log("MAC entries with smac {} in vlan {} learnt on edge port {} of dut {}".format(src_mac, random_vlan, iface[0], dut_blocking))
                        edge_port_mac_cnt = edge_port_mac_cnt+1
                    else:
                        st.log("MAC entries with smac {} in vlan {} are not found on edge port {} of dut {}".format(src_mac, random_vlan, iface[0], dut_blocking))

                st.log("MAC entries with smac {} in vlan {} learnt on edge ports of dut {} after change of cost  is : {}".format(src_mac, random_vlan, dut_blocking, edge_port_mac_cnt))

                total_mac_cnt = len(mac.get_mac_address_list(dut_blocking, mac=src_mac, vlan=random_vlan))
                st.log("MAC entries with smac {} in vlan {} learnt on dut {} after change of cost is : {}".format(src_mac, random_vlan, dut_blocking, total_mac_cnt))

                if total_mac_cnt-edge_port_mac_cnt == 0:
                    st.log("MAC entries {} are flushed fine in vlan {} on DUT {}".format(src_mac, random_vlan, dut_blocking))
                else:
                    res = 0
                    st.error("MAC entries {} are not flushed fine in vlan {} on DUT {}".format(src_mac, random_vlan, dut_blocking))
            else:
                if not mac.verify_mac_address(dut_blocking, random_vlan, src_mac):
                    st.log("MAC entries {} are flushed fine in vlan {} on DUT {}".format(src_mac, random_vlan, dut_blocking))
                else:
                    res = 0
                    st.error("MAC entries {} are not flushed fine in vlan {} on DUT {}".format(src_mac, random_vlan, dut_blocking))

            st.log("Configuring back the cost to previous value")
            stp.config_stp_interface_params(dut_blocking, blocked_port, cost=old_cost)
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, "FORWARDING", iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
                res = 0
                st.error("Interface {} is not in Forwarding state after reverting back the original priority on peer DUT".format(forwarding_port))
            else:
                st.log("Interface under test {} is in forwarding state as expected".format(forwarding_port))

            if res:
                pass_cnt+=2
                st.report_tc_pass('ft_{}_tc_single_instance_fdb_flush'.format(stp_protocol),'test_case_passed')
                st.report_tc_pass('ft_{}_int_cost_fdb_flush'.format(stp_protocol),'test_case_passed')
            else:
                fail_cnt+=2
                st.report_tc_fail('ft_{}_tc_single_instance_fdb_flush'.format(stp_protocol),'test_case_failed')
                st.report_tc_fail('ft_{}_int_cost_fdb_flush'.format(stp_protocol),'test_case_failed')
            #############################################################################################
            utils.banner_log("Verification of fdb flush is happening when cost is changed in interface level. -- COMPLETED")
            #############################################################################################

            if stp_protocol == 'pvst':
                #############################################################################################
                utils.banner_log("Verification of uplink fast is working fine. -- STARTED")
                #############################################################################################
                res = 1
                st.log("Configuring uplink fast on {} port {} on DUT {}".format(stp_dict[stp_protocol]["non_fwd_state"],blocked_port, dut_blocking))
                stp.config_stp_interface_params(dut_blocking, blocked_port, uplink_fast="enable")
                st.wait(stp_dict[stp_protocol]["stp_wait_time"])

                st.log("Verify that uplink fast is enabled fine on interface {}".format(blocked_port))
                if not stp.get_stp_port_param(dut_blocking, random_vlan, blocked_port, 'port_uplinkfast') == "Y":
                    res = 0
                    st.error("Uplink fast is not enabled on {} in vlan {}".format(random_vlan, blocked_port))
                else:
                    st.log("Uplink fast is enabled on {} in vlan {}".format(random_vlan, blocked_port))
                    st.log("Shutdown the forwarding port so that uplinkfast enabled port becomes forwarding immediately")
                    st.log("Sending continuous traffic ....")
                    tgapi.traffic_action_control(stp_wrap.tg_info['tg_info'], actions=['clear_stats'])
                    st.wait(5)
                    tg.tg_traffic_control(action='run', stream_handle= stp_wrap.tg_info['tg1_vlan_inc_mac_fix_unknown'])
                    st.wait(10)
                    intf.interface_shutdown(dut_blocking, forwarding_port)
                    st.wait(3)
                    st.log("Verify that interface {} moved to Forwarding immediately as uplinkfast is enabled".format(blocked_port))
                    if not stp.get_stp_port_param(dut_blocking, random_vlan, blocked_port,"port_state") == "FORWARDING":
                        res = 0
                        st.error("Interface under test {} is not in Forwarding state immediately when uplinkfast enabled".format(blocked_port))
                    else:
                        st.log("Interface under test {} is in Forwarding state as expected".format(blocked_port))

                    st.log("verify traffic is immediately switched to new forwarding port")
                    tg.tg_traffic_control(action='stop', stream_handle= stp_wrap.tg_info['tg1_vlan_inc_mac_fix_unknown'])

                    st.log("Unshutting the previous shutdown port")
                    intf.interface_noshutdown(dut_blocking, forwarding_port)
                    st.wait(10)
                    stat1 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_1)
                    stat2 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_2)
                    stat3 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_3)
                    rate_pps = 10000
                    convergence_time = 3
                    mac.get_mac_all_dut(dut_list)

                    st.log("stat1 tx pkts: {}  stat2 rx pkts: {} stat3 rx pkts {}".format(stat1.tx.total_packets, stat2.rx.total_packets,stat3.rx.total_packets))
                    stat2_convergence = round((int(stat1.tx.total_packets)-int(stat2.rx.total_packets))/(int(rate_pps)*1.0),1)
                    stat3_convergence = round((int(stat1.tx.total_packets)-int(stat3.rx.total_packets))/(int(rate_pps)*1.0),1)
                    st.log("Convergence time on TG2 port is {} and covergence time on TG3 port is {}".format(stat2_convergence, stat3_convergence))
                    if stat2_convergence > convergence_time or stat3_convergence > convergence_time:
                        res = 0
                        st.error("Convergence times are not within acceptable limit when uplinkfast is enabled")
                    else:
                        st.log("convergence time is within acceptable limit when uplink fast is enabled")

                    st.log("removing uplinkfast config")
                    stp.config_stp_interface_params(dut_blocking, blocked_port, uplink_fast="disable")
                    st.wait(2)
                    if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, "FORWARDING",iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                        res = 0
                        st.error("Interface under test {} is not in Forwarding state".format(forwarding_port))
                    else:
                        st.log("Interface under test {} is in Forwarding state as expected".format(forwarding_port))

                if res:
                    pass_cnt+=1
                    st.report_tc_pass('ft_{}_uplinkfast_fdb'.format(stp_protocol),'test_case_passed')
                else:
                    fail_cnt+=1
                    st.report_tc_fail('ft_{}_uplinkfast_fdb'.format(stp_protocol),'test_case_failed')
                #############################################################################################
                utils.banner_log("Verification of uplink fast is working fine. -- COMPLETED")
                #############################################################################################
        else:
            fail_cnt+=4
            st.error("Partner dut not found..")

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_minlink_lldp(vars, stp_ela, stp_protocol):
    result =1
    global pc_members
    global pc_mem_len
    pass_cnt = 0
    fail_cnt= 0
    mgmt_int = 'eth0'
    random_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(random_vlan))
    st.log("Getting a pair of nodes with one DUT having one Fwding and one {} port".format(stp_dict[stp_protocol]["non_fwd_state"]))
    port_states = stp_wrap.get_blocking_brigde_with_interfaces(random_vlan,stp_protocol)
    st.log("port_states output is {}".format(port_states))
    dut_blocking = ""
    dut_forwarding = ""
    for key in port_states:
        if len(port_states[key]['forwarding']) == 1:
            dut_blocking = key
        else:
            dut_forwarding = key
    st.log("DUT having {} port is {} and DUT having all forwarding ports is {}".format(stp_dict[stp_protocol]["non_fwd_state"], dut_blocking, dut_forwarding))
    if not dut_blocking:
        st.error("{} interface not found on either of the devices.".format(stp_dict[stp_protocol]["non_fwd_state"]))
        result = 0
    else:
        blocked_port = port_states[dut_blocking]['blocking'][0]
        forwarding_port = port_states[dut_blocking]['forwarding'][0]
        if "PortChannel" in blocked_port:
            old_cost = stp.get_stp_port_param(dut_blocking, random_vlan, blocked_port, 'port_pathcost')
            new_cost = 10
            stp.config_stp_vlan_interface(dut_blocking, random_vlan, blocked_port, new_cost, mode='cost')
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not moved to Forwarding state when lower cost is configured..".format(blocked_port, dut_blocking))
                result = 0
            else:
                st.log("Interface {} on {} is moved to Forwarding state when lower cost is configured..".format(blocked_port, dut_blocking))
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, stp_dict[stp_protocol]["non_fwd_state"], iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not in {} state when lower cost is configured on other interface {}".format(forwarding_port, dut_blocking, stp_dict[stp_protocol]["non_fwd_state"], blocked_port))
                result = 0
            else:
                st.log("Interface {} on {} is moved to {} state as expected..".format(forwarding_port, dut_blocking,stp_dict[stp_protocol]["non_fwd_state"]))

            st.log("###############Testcase to verify LLDP entries on {} port  ##############".format(stp_dict[stp_protocol]["non_fwd_state"]))

            utils.banner_log("forwarding_port which is in {} state is  : {}".format(stp_dict[stp_protocol]["non_fwd_state"],forwarding_port))
            utils.banner_log("blocked port which is in forwarding state is  : {}".format(blocked_port))
            st.log("Getting {} port partner details to check lldp entries on it".format(stp_dict[stp_protocol]["non_fwd_state"]))
            dut_partner_details = stp_wrap.get_dut_partner_details_by_dut_interface(dut_blocking, forwarding_port)
            st.log("partner_details: {}".format(dut_partner_details))
            local_interface_index = dut_partner_details[dut_blocking].index(forwarding_port)
            partner_dut = ''
            for key in dut_partner_details:
                if key != dut_blocking:
                    partner_dut = key
            if partner_dut:
                remote_interface = dut_partner_details[partner_dut][local_interface_index]
                ipaddress_d2 = basic.get_ifconfig_inet(partner_dut, mgmt_int)
                lldp_value = lldp.get_lldp_neighbors(dut_blocking, forwarding_port)
                lldp_value_remote = lldp.get_lldp_neighbors(partner_dut, remote_interface)
                st.log(" LLDP Neighbors value is: {} ".format(lldp_value))
                st.log(" Remote LLDP Neighbors value is: {} ".format(lldp_value_remote))
                if not lldp_value:
                    st.error("No lldp entries are available")
                    lldp_value = ""
                    lldp_value_gran = ""
                else:
                    lldp_value = lldp_value[0]
                    lldp_value_gran = lldp_value['chassis_mgmt_ip']
                if not lldp_value_remote:
                    st.error(" No lldp entries are available in Remote")

                if not ipaddress_d2[0] == lldp_value_gran:
                    st.error("LLDP info IP and device IP are not matching")
                    result = 0
                    fail_cnt += 1
                else:
                    st.log("##############Verification of LLDP entries on {} port is completed#################".format(stp_dict[stp_protocol]["non_fwd_state"]))
                    pass_cnt += 1
            st.log("Now Portchannel {} is moved to Fwding state after changing the cost".format(blocked_port))
            st.log("Getting the list of member ports in portchannel {} on dut {}".format(blocked_port, dut_blocking))
            pc_members = portchannel.get_portchannel_members(dut_blocking, blocked_port)
            pc_mem_len= len(pc_members)
            st.log("shutdown all members on portchannel {} and verify the other interface {} is moving to Fwding state".format(blocked_port, forwarding_port))
            port.shutdown(dut_blocking, pc_members)
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not in FORWARDING state when all members on portchannel {} are shut..".format(forwarding_port, dut_blocking, blocked_port))
                result = 0
            else:
                st.log("Interface {} on {} is moved to Forwarding state as expected..".format(forwarding_port, dut_blocking))
            st.log("Bringup only one member port on portchannel {}".format(blocked_port))
            member_port= pc_members[0]
            member_other_port= pc_members[1:pc_mem_len]
            st.log("member port unshut is {}".format(member_port))
            intf.interface_noshutdown(dut_blocking,member_port)
            st.log("Verify that with only one member up, portchannel {} comes up and is moved to Forwarding state".format(blocked_port))
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not in FORWARDING state when one member port of portchannel is unshut..".format(blocked_port, dut_blocking))
                result = 0
            else:
                st.log("Interface {} on {} is moved to Forwarding state as expected..".format(blocked_port, dut_blocking))
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, stp_dict[stp_protocol]["non_fwd_state"], iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not in {} state when one member port of portchannel is unshut..".format(
                    forwarding_port, dut_blocking,stp_dict[stp_protocol]["non_fwd_state"]))
                result = 0
                fail_cnt+=1
            else:
                st.log("Interface {} on {} is moved to {} state as expected..".format(forwarding_port, dut_blocking, stp_dict[stp_protocol]["non_fwd_state"]))
                st.log("####Verification of minlink functionality is completed######")
                pass_cnt+=1
            st.log("unshut other members prots of portchannel..")
            port.noshutdown(dut_blocking, member_other_port)
            st.wait(1)
            st.log("changing the cost back to original value:")
            stp.config_stp_vlan_interface(dut_blocking, random_vlan, blocked_port, old_cost, mode='cost')
        else:
            st.log("###############Testcase to verify LLDP entries on {} port ##############".format(stp_dict[stp_protocol]["non_fwd_state"]))
            dut_partner_details = stp_wrap.get_dut_partner_details_by_dut_interface(dut_blocking, forwarding_port)
            st.log("partner_details: {}".format(dut_partner_details))
            local_interface_index = dut_partner_details[dut_blocking].index(forwarding_port)
            partner_dut = ''
            for key in dut_partner_details:
                if key != dut_blocking:
                    partner_dut = key
            if partner_dut:
                remote_interface = dut_partner_details[partner_dut][local_interface_index]
                ipaddress_d2 = basic.get_ifconfig_inet(partner_dut, mgmt_int)
                lldp_value = lldp.get_lldp_neighbors(dut_blocking, forwarding_port)
                lldp_value_remote = lldp.get_lldp_neighbors(partner_dut, remote_interface)
                st.log(" LLDP Neighbors value is: {} ".format(lldp_value))
                st.log(" Remote LLDP Neighbors value is: {} ".format(lldp_value_remote))
                if not lldp_value:
                    st.error("No lldp entries are available")
                    lldp_value = ""
                    lldp_value_gran = ""
                else:
                    lldp_value = lldp_value[0]
                    lldp_value_gran = lldp_value['chassis_mgmt_ip']
                if not lldp_value_remote:
                    st.error(" No lldp entries are available in Remote")

                if not ipaddress_d2[0] == lldp_value_gran:
                    st.error("LLDP info IP and device IP are not matching")
                    result = 0
                    fail_cnt += 1
                else:
                    st.log("######Verification of LLDP entries on {} port is completed###########".format(stp_dict[stp_protocol]["non_fwd_state"]))
                    pass_cnt += 1
            st.log("shutdown all members on portchannel {} and verify the other interface {} is moving to Fwding state".format(blocked_port, forwarding_port))
            port.shutdown(dut_blocking, pc_members)
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not in FORWARDING state when all members on portchannel {} are shut..".format(forwarding_port, dut_blocking, blocked_port))
                result = 0
            else:
                st.log("Interface {} on {} is moved to Forwarding state as expected..".format(forwarding_port,dut_blocking))

            st.log("Bringup only one member port on portchannel {}".format(blocked_port))
            member_port = pc_members[0]
            member_other_port = pc_members[1:pc_mem_len]
            intf.interface_noshutdown(dut_blocking, member_port)
            st.log("Verify that with only one member up, portchannel {} comes up and is moved to Forwarding state".format(blocked_port))
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, blocked_port, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not in FORWARDING state when one member port of portchannel is unshut..".format(blocked_port, dut_blocking))
                result = 0
            else:
                st.log("Interface {} on {} is moved to Forwarding state as expected..".format(blocked_port, dut_blocking))
            if not stp.poll_for_stp_status(dut_blocking, random_vlan, forwarding_port, stp_dict[stp_protocol]["non_fwd_state"], iteration=stp_dict[stp_protocol]["stp_wait_time"],delay=1):
                st.error("Interface {} on {} is not in {} state when one member port of portchannel is unshut..".format(forwarding_port, dut_blocking, stp_dict[stp_protocol]["non_fwd_state"]))
                result = 0
                fail_cnt+=1
            else:
                st.log("Interface {} on {} is moved to {} state as expected..".format(forwarding_port, dut_blocking, stp_dict[stp_protocol]["non_fwd_state"]))
                st.log("####Verification of minlink functionality is completed######")
                pass_cnt+=1
            st.log("unshut other members prots of portchannel..")
            port.noshutdown(dut_blocking, member_other_port)
            st.wait(1)
        st.log("Verification of min link fucntionality on portchannel with stp enabled is completed####")
    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    return(result)

def lib_stp_rootswitch_trigger(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    random_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(random_vlan))

    dut_list = stp_wrap.get_dut_list(vars)
    st.log("list of duts is {}".format(dut_list))

    root_bridge = stp_ela['states'][random_vlan]['root']
    st.log("Root bridge for vlan {} is {}".format(random_vlan, root_bridge))

    dut_nonroot_list = list()
    for dut in dut_list:
        if dut != root_bridge:
            dut_nonroot_list.append(dut)

    st.log("List of DUTs excluding current root bridge is {}".format(dut_nonroot_list))
    st.log("verify who will be the next root if current root {} fails".format(root_bridge))
    next_root_bridge = stp.get_default_root_bridge(dut_nonroot_list)
    st.log("Next root bridge is {}".format(next_root_bridge))

    next_root_bid = stp.get_stp_bridge_param(next_root_bridge, random_vlan, 'br_id')
    st.log("next root bridge id: {} for vlan: {}".format(next_root_bid, random_vlan))

    root_bid = stp.get_stp_bridge_param(root_bridge, random_vlan, 'br_id')
    st.log("root bridge id: {} for vlan: {}".format(root_bid, random_vlan))

    #############################################################################################
    utils.banner_log("Verification of next eliglible switch becomes root when STP is disabled on vlan on rootswitch. -- STARTED")
    #############################################################################################
    res = 1
    st.log("Disabling spanning tree on root switch for vlan {}".format(random_vlan))
    stp.config_spanning_tree(root_bridge, feature=stp_protocol, mode="disable", vlan=random_vlan)

    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    st.log("Verify that next eligible switch {} becomes root when {} is disabled on root switch {}".format(next_root_bridge,stp_protocol,root_bridge))
    if not stp.poll_for_root_switch(next_root_bridge,random_vlan,iteration=30,delay=1):
        res = 0
        st.error("{} is not root in vlan {}".format(next_root_bridge,random_vlan))
    else:
        st.log("{} is the new root switch in vlan {}".format(next_root_bridge,random_vlan))

    st.log("Verify that topology converges fine with new root switch {}".format(next_root_bridge))
    if not stp.verify_root_bridge_on_stp_instances(dut_nonroot_list, random_vlan, next_root_bid):
        res = 0
        st.error("Topology did not converge fine when {} is disabled on root switch {} in vlan {}".format(stp_protocol,root_bridge,random_vlan))
    else:
        st.log("Topology converged fine when {} is disabled on root switch {} in vlan {}".format(stp_protocol,root_bridge,random_vlan))

    st.log("Reconfiguring back to module config")
    stp.config_spanning_tree(root_bridge, feature=stp_protocol, mode="enable", vlan=random_vlan)
    stp.config_stp_vlan_parameters(root_bridge,random_vlan,priority=0)

    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    st.log("Verify that initial switch {} becomes root again".format(root_bridge))
    if not stp.poll_for_root_switch(root_bridge,random_vlan,iteration=30,delay=1):
        res = 0
        st.error("{} is not root in {}".format(root_bridge,dut_nonroot_list))
    else:
        st.log("{} is the new root switch in vlan {}".format(root_bridge,random_vlan))

    if res:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_rootswitch_disable'.format(stp_protocol),'test_case_passed')
        if stp_protocol == "rpvst":
            st.report_tc_pass('ft_{}_rootswitch_disable_rpvst'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_rootswitch_disable'.format(stp_protocol),'test_case_failed')
        if stp_protocol == "rpvst":
            st.report_tc_fail('ft_{}_rootswitch_disable_rpvst'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of next eliglible switch becomes root when STP is disabled on vlan on rootswitch. -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of next eliglible switch becomes root when all ports on root switch are shut. -- STARTED")
    #############################################################################################
    res = 1
    root_bd_ports = stp.get_stp_port_list(root_bridge,random_vlan,exclude_port=[])
    st.log("root bridge {} ports are : {}".format(root_bridge,root_bd_ports))

    st.log("shutting down all ports on root switch {}".format(root_bridge))
    port.shutdown(root_bridge,root_bd_ports)

    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    st.log("verify that next eligible switch becomes root when all ports on rootswitch are shut")
    if not stp.poll_for_root_switch(next_root_bridge,random_vlan,iteration=30,delay=1):
        res = 0
        st.error("{} is not root in vlan {}".format(next_root_bridge,random_vlan))
    else:
        st.log("{} is the new root switch in vlan {}".format(next_root_bridge,random_vlan))

    st.log("Verify that topology is converged fine with new root switch {}".format(next_root_bridge))
    if not stp.verify_root_bridge_on_stp_instances(dut_nonroot_list, random_vlan, next_root_bid):
        res = 0
        st.error("Topology did not converge fine when all ports on root switch {} are shut".format(root_bridge))
    else:
        st.log("Topology converged fine when all ports on root switch {} are shut".format(root_bridge))

    st.log("unshutting all ports in root bridge")
    port.noshutdown(root_bridge, root_bd_ports)

    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    st.log("Verify that new root switch {} will not continue as root as initial root {} has come back UP ".format(next_root_bridge, root_bridge))
    if stp.poll_for_root_switch(next_root_bridge,random_vlan,iteration=5,delay=1):
        res = 0
        st.error("{} is root in vlan {} which is not expected".format(next_root_bridge,random_vlan))
    else:
        st.log("{} is not root switch in vlan {} as expected".format(next_root_bridge,random_vlan))

    st.log("verify that topology is converged fine when ports on initial root switch are unshut")
    if not stp.verify_root_bridge_on_stp_instances(dut_nonroot_list, random_vlan, root_bid):
        res = 0
        st.error("Topology did not converge back fine when all ports are unshut on  {} ".format(root_bridge))
    else:
        st.log("Topology  converged back fine when all ports are unshut on  {} ".format(root_bridge))

    if res:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_rootswitch_shut'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_rootswitch_shut'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of next eliglible switch becomes root when all ports on root switch are shut. -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of next eliglible switch becomes root when members are removed in root switch. -- STARTED")
    #############################################################################################
    res = 1
    st.log("Removing all members {} in vlan {} on root bridge {} ".format(root_bd_ports,random_vlan,root_bridge))
    vlan.config_vlan_members(root_bridge, random_vlan, root_bd_ports, config="del")

    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    st.log(" verify next eligible switch {} becomes root switch".format(next_root_bridge))
    if not stp.poll_for_root_switch(next_root_bridge,random_vlan,iteration=20,delay=1):
        res = 0
        st.error("{} is not root in vlan {} which is not expected".format(next_root_bridge,random_vlan))
    else:
        st.log("{} is root switch in vlan {} as expected".format(next_root_bridge,random_vlan))

    st.log("Adding back all members {} in vlan {} on root bridge {} ".format(root_bd_ports, random_vlan, root_bridge))
    vlan.add_vlan_member(root_bridge,random_vlan,root_bd_ports,tagging_mode=True)

    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    st.log(" verify initial switch {} becomes root switch".format(root_bridge))
    if not stp.poll_for_root_switch(root_bridge, random_vlan, iteration=20, delay=1):
        res = 0
        st.error("{} is not root in vlan {} which is not expected".format(root_bridge, random_vlan))
    else:
        st.log("{} is root switch in vlan {} as expected".format(root_bridge, random_vlan))

    if not stp.verify_root_bridge_on_stp_instances(dut_nonroot_list, random_vlan, root_bid):
        res = 0
        st.error("Topology did not converge back fine when all ports are unshut on  {} ".format(root_bridge))
    else:
        st.log("Topology  converged back fine when all ports are unshut on  {} ".format(root_bridge))

    if res:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_rootswitch_noswitchport'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_rootswitch_noswitchport'.format(stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of next eliglible switch becomes root when members are removed in root switch. -- COMPLETED")
    #############################################################################################

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_timers(vars, stp_ela, stp_protocol):
    pass_cnt = 0
    fail_cnt = 0

    def_fwd_delay = 15
    def_max_age = 6
    new_fwd_delay = 20
    new_max_age = 25
    convergence_time= 2*new_fwd_delay + new_max_age

    dut_list = stp_wrap.get_dut_list(vars)
    for d in dut_list:
        slog.clear_logging(d)

    st.log("Clearing stats before sending traffic ...")
    tg = stp_wrap.tg_info['tg_info']['tg']
    tg_ph_1 = stp_wrap.tg_info['tg_info']["tg_ph_1"]
    tg_ph_2 = stp_wrap.tg_info['tg_info']["tg_ph_2"]
    tg_ph_3 = stp_wrap.tg_info['tg_info']["tg_ph_3"]
    rate_pps = 10000
    random_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(random_vlan))
    tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=10000, transmit_mode="continuous",mac_src="00:60:00:00:00:01", mac_src_mode="increment", mac_src_count=1,mac_src_step="00:00:00:00:00:01", mac_dst="00:00:60:80:00:01",mac_dst_mode="increment", mac_dst_count=1, mac_dst_step="00:00:00:00:00:01",vlan_id=random_vlan, vlan_id_count=1, vlan_id_mode='increment',vlan_id_step=1, l2_encap='ethernet_ii')
    stream_id_1 = tg_1['stream_id']
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_unicast'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg2_unicast'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_unknown'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_multicast'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_broadcast'])
    tg.tg_traffic_config(mode='disable', stream_id=stp_wrap.tg_info['tg1_vlan_inc_mac_fix_unknown'])
    tg.tg_traffic_config(mode='enable', stream_id=stream_id_1)

    root_bridge = stp_ela['states'][random_vlan]['root']
    st.log("Topology root bridge:  {}".format(root_bridge))

    blocking_bridge_info = stp_ela['states'][random_vlan]['non_root']['highest_mac']
    st.log("blocking_bridge_info: {}".format(blocking_bridge_info))

    if not 'name' in blocking_bridge_info:
        fail_cnt+=2
        st.error("Did not get the name of {} switch.".format(stp_dict[stp_protocol]["non_fwd_state"]))
    else:
        blocking_bridge = blocking_bridge_info['name']
        st.log("{} bridge : {}".format(stp_dict[stp_protocol]["non_fwd_state"],blocking_bridge))

        st.log("Get neighbors to root switch")
        neighbor_list = stp_wrap.get_dut_neighbors(root_bridge)
        non_blocked_neighbor_list = list()
        st.log("neighbor list {} for root bridge {} ".format(neighbor_list, root_bridge))

        for key,value in neighbor_list.items():
            for dut in value:
                if dut != blocking_bridge:
                    st.log("Getting non {} neighbor...".format(stp_dict[stp_protocol]["non_fwd_state"]))
                    non_blocked_neighbor_list.append(dut)
        st.log("List of DUT neighbors to root switch excluding {} bridge {}".format(stp_dict[stp_protocol]["non_fwd_state"],non_blocked_neighbor_list))

        nonroot_switch =non_blocked_neighbor_list[0]
        st.log("switch where ports will be shut for the test is {}".format(nonroot_switch))

        #############################################################################################
        utils.banner_log("Verification of STP timers. -- STARTED")
        #############################################################################################
        res1 = 1
        st.log("configuring non default fwd delay and max age timers on root switch {}".format(root_bridge))
        stp.config_stp_vlan_parameters(root_bridge, random_vlan, forward_delay=new_fwd_delay)
        stp.config_stp_vlan_parameters(root_bridge, random_vlan, max_age=new_max_age)
        st.wait(5)
        st.log("verify that fwd delay and max age configured on root switch are reflected fine in {} switch for vlan {}".format(stp_dict[stp_protocol]["non_fwd_state"],random_vlan))
        if not int(stp.get_stp_bridge_param(blocking_bridge,random_vlan,'rt_fwddly'))==new_fwd_delay:
            res1 = 0
            st.error("Forward delay is not propogated from root switch in vlan {} on switch {}".format(random_vlan,blocking_bridge))
        else:
            st.log("Forward delay is configured fine in vlan {} in switch {}".format(random_vlan,blocking_bridge))

        if not int(stp.get_stp_bridge_param(blocking_bridge,random_vlan,'rt_maxage'))==new_max_age:
            res1 = 0
            st.error("Max age is not conigured fine on vlan {} in switch {}".format(random_vlan,blocking_bridge))
        else:
            st.log("Max age is configured fine on vlan {} in switch {}".format(random_vlan,blocking_bridge))

        st.log("Get links between root switch {} and non root switch {}".format(root_bridge, nonroot_switch))
        root_nonroot_ports = stp_wrap.get_dut_partner_interfaces(root_bridge, nonroot_switch)

        ports_to_shut = list()
        for key, value in root_nonroot_ports.items():
            if key != root_bridge:
                ports_to_shut = value
        st.log("Ports to be shut are: {}".format(ports_to_shut))
        if vars.config.ifname_type == "alias":
            ports_to_shut1 = intf.get_native_interface_name(nonroot_switch, ports_to_shut)
        else:
            ports_to_shut1 = ports_to_shut
        st.log("Ports to be shut are: {}".format(ports_to_shut1))

        st.log("Sending continuous traffic for vlan {} for which forwarding delay {} and max age {} are non default values".format(random_vlan, new_fwd_delay, new_max_age))
        tgapi.traffic_action_control(stp_wrap.tg_info['tg_info'], actions=['clear_stats'])
        st.wait(5)
        tg.tg_traffic_control(action='run', stream_handle = stream_id_1)
        st.wait(10)

        #############################################################################################
        utils.banner_log("Verification of STP debug messages. -- STARTED")
        #############################################################################################
        res2 = 1
        debug_log_count_1 = slog.get_logging_count(nonroot_switch, filter_list=['stp'])
        st.log("debug_log_count_1= {}".format(debug_log_count_1))

        stp.debug_stp(nonroot_switch)
        port.shutdown(nonroot_switch,ports_to_shut1,cli_type="click")

        st.log("Wait for 2*fwd delay plus max age time")
        st.wait(convergence_time)

        tg.tg_traffic_control(action='stop', stream_handle = stream_id_1)
        st.wait(10)
        tg.tg_traffic_config(mode='disable', stream_id=stream_id_1)

        stp.debug_stp(nonroot_switch, 'reset')
        debug_log_count_2 = slog.get_logging_count(nonroot_switch, filter_list=['stp'])

        st.log("debug_log_count_2= {}".format(debug_log_count_2))
        if debug_log_count_2 <= debug_log_count_1:
            res2 = 0
            st.error("Debug logs are not seen even after enabling debug spanning tree")
        else:
            st.log("Debug logs are seen after enabling debug spanning tree")

        if res2:
            pass_cnt+=1
            st.report_tc_pass('ft_{}_debug_commands'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.report_tc_fail('ft_{}_debug_commands'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verification of STP debug messages. -- COMPLETED")
        #############################################################################################

        stat1 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_1)
        stat2 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_2)
        stat3 = tgapi.get_traffic_stats(tg, port_handle=tg_ph_3)
        mac.get_mac_all_dut(dut_list)

        st.log("stat1 tx pkts: {}  stat2 rx pkts: {} stat3 rx pkts {}".format(stat1.tx.total_packets,stat2.rx.total_packets,stat3.rx.total_packets))
        stat2_convergence = abs(round((int(stat1.tx.total_packets) - int(stat2.rx.total_packets)) / (int(rate_pps) * 1.0),1))
        stat3_convergence = abs(round((int(stat1.tx.total_packets) - int(stat3.rx.total_packets)) / (int(rate_pps) * 1.0),1))
        st.log("Convergence time on TG2 port is {} and covergence time on TG3 port is {}".format(stat2_convergence,stat3_convergence))
        if stat2_convergence > convergence_time or stat3_convergence > convergence_time:
            res1 = 0
            st.error("Convergence times are not within acceptable limit when non default fwd delay and max age are configured")
        else:
            st.log("convergence time is within acceptable limit when non default fwd delay and max age are configured")

        if res1:
            pass_cnt+=1
            st.report_tc_pass('ft_{}_timers'.format(stp_protocol),'test_case_passed')
        else:
            fail_cnt+=1
            st.report_tc_fail('ft_{}_timers'.format(stp_protocol),'test_case_failed')
        #############################################################################################
        utils.banner_log("Verification of STP timers. -- COMPLETED")
        #############################################################################################

        st.log("configuring back the fwd delay and max age to defaults....")
        stp.config_stp_vlan_parameters(root_bridge, random_vlan, forward_delay=def_fwd_delay)
        stp.config_stp_vlan_parameters(root_bridge, random_vlan, max_age=def_max_age)

        st.log("unshut the previously shut ports")
        port.noshutdown(nonroot_switch, ports_to_shut)
        st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))
    if fail_cnt:
        return(0)
    else:
        return(1)

def lib_stp_stress_stp_disable_enable(vars, stp_ela, stp_protocol):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify the STP convergence by disabling and re-enabling spanning tree globally on the dut for multiple times.
    #
    ############### Test bed details ################
    result = 1

    utils.banner_log("Checking {} convergence and traffic before protocol enable/disable test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    count = 0
    while (count < 5):
        st.log("Disabling {} on all the duts".format(stp_protocol))
        stp.config_stp_in_parallel(stp_wrap.get_dut_list(vars), feature=stp_protocol, mode="disable")
        st.wait(5)
        st.log("Enabling {} on all the duts".format(stp_protocol))
        stp.config_stp_in_parallel(stp_wrap.get_dut_list(vars), feature=stp_protocol, mode="enable")
        st.wait(5)
        count = count + 1

    stp.config_stp_vlan_parameters_parallel(stp_wrap.get_dut_list(vars), vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"], priority=[0]*len(stp_wrap.get_dut_list(vars)))

    if stp_protocol == "rpvst":
        dut_list = stp_wrap.get_dut_list(vars)
        for dut in dut_list:
            for vlan_id in stp_wrap.complete_data["vlan_data"]["vlan_list"]:
                stp.config_stp_vlan_parameters(dut, vlan_id, max_age=stp_dict["rpvst"]["stp_max_age"])
            for interf in stp_ela[dut]['tg_links']:
                stp.config_port_type(dut, interf[0], stp_type='rpvst', port_type='edge', no_form=False)

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    utils.banner_log("Checking {} convergence and traffic after protocol enable/disable test".format(stp_protocol))
    for (dut_test, vlan_test) in zip(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"]):
        if stp.poll_for_root_switch(dut_test, vlan_test, iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut_test, vlan_test))
        else:
            st.error("{} is not root switch for vlan {}".format(dut_test, vlan_test))
            result=0

    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    return(result)

def lib_stp_stress_bridge_priority(vars, stp_ela, stp_protocol):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify the STP convergence by changing the bridge priorities and check for stable state.
    #
    ############### Test bed details ################
    result = 1
    used_vlan_list = stp_wrap.complete_data["vlan_data"]["vlan_list"]
    utils.banner_log("Checking {} convergence and traffic before the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    utils.banner_log("Configuring DUT bridge priority to default in all the duts.")
    stp.config_stp_vlan_parameters_parallel(stp_wrap.get_dut_list(vars), vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"], priority=[32768]*len(stp_wrap.get_dut_list(vars)))

    utils.banner_log("Making single DUT as root bridge in all the instances and checking root status")
    dut_test = random.choice(stp_wrap.get_dut_list(vars))
    for vlan_test in stp_wrap.complete_data["vlan_data"]["vlan_list"]:
        stp.config_stp_vlan_parameters_parallel([dut_test], vlan=[vlan_test], priority=[0])

        if stp.poll_for_root_switch(dut_test, vlan_test, iteration=15, delay=2):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut_test, vlan_test))
        else:
            st.error("{} is not root switch for vlan {}".format(dut_test, vlan_test))
            result=0

        stp.config_stp_vlan_parameters_parallel([dut_test], vlan=[vlan_test], priority=[32768])

    stp.config_stp_vlan_parameters_parallel(stp_wrap.get_dut_list(vars), vlan=stp_wrap.complete_data["vlan_data"]["vlan_list"], priority=[0]*len(stp_wrap.get_dut_list(vars)))

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    utils.banner_log("Checking {} convergence and traffic after protocol enable/disable test".format(stp_protocol))
    for (dut_test, vlan_test) in zip(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"]):
        if stp.poll_for_root_switch(dut_test, vlan_test, iteration=10, delay=4):
            st.log("SUCCESSFULL : {} is root switch for vlan {}".format(dut_test, vlan_test))
        else:
            st.error("{} is not root switch for vlan {}".format(dut_test, vlan_test))
            result=0

    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])
    if stp_protocol == 'pvst':
        st.log("Verifying ports are converged fine in all vlan instances")
        for vlan_id in used_vlan_list:
            if not stp_wrap.poll_stp_convergence(vars, vlan_id, iteration=20, delay=1):
                st.error("ports did not converged fine in vlan {}".format(vlan_id))
                result = 0
            else:
                st.log("ports converged fine in vlan {}".format(vlan_id))
    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    return(result)

def lib_stp_stress_lag_shut_noshut(vars, stp_ela, stp_protocol):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify the STP convergence by shut/no shut of lag interfaces for multiple times and checking for convergence.
    #
    ############### Test bed details ################
    result = 1

    utils.banner_log("Checking {} convergence and traffic before the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    dut_test = random.choice(stp_wrap.get_dut_list(vars))
    port_channel_list = list()
    for lag_intf in portchannel.get_portchannel_list(dut_test):
        if stp_cli_type != "click":
            port_channel_list.append(lag_intf["name"])
        else:
            port_channel_list.append(lag_intf["teamdev"])

    utils.banner_log("Shutting down/Starting up all the port channel interfaces {} on the DUT {}".format(port_channel_list,dut_test))
    count = 0
    while (count < 5):
        if count == 0:
            intf.interface_operation(dut_test, port_channel_list , "shutdown")
            st.wait(5)

            # STP convergence check after trigger.
            st.log("Waiting for {} to converge".format(stp_protocol))
            st.wait(stp_dict[stp_protocol]["stp_wait_time"])
            utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
            stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

            if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
                st.log("Unicast traffic test PASSED")
            else:
                st.error("learned unicast test FAILED !!")
                result = 0

            intf.interface_operation(dut_test, port_channel_list , "startup")
        else:
            intf.interface_operation(dut_test, port_channel_list , "shutdown")
            st.wait(5)
            intf.interface_operation(dut_test, port_channel_list , "startup")
        count = count + 1

    utils.banner_log("Verifying the port channel link states after multiple iterations of shut and no shut operation.")
    for lag_intf in port_channel_list:
        if not portchannel.poll_for_portchannel_status(dut_test, lag_intf, state="up", iteration=90, delay=1):
            st.error("Failed to startup port channels {} on the DUT {}".format(lag_intf,dut_test))
            result=0

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])
    utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    return(result)

def lib_stp_stress_shut_noshut(vars, stp_ela, stp_protocol):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify the STP convergence by shut/no shut of physical interfaces for multiple times and checking for convergence.
    #
    ############### Test bed details ################
    result = 1

    utils.banner_log("Checking {} convergence and traffic before the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    dut_test = random.choice(stp_wrap.get_dut_list(vars))
    st.banner(dut_test)
    port_channel_list = list()
    for lag_intf in portchannel.get_portchannel_list(dut_test):
        if stp_cli_type != "click":
            port_channel_list.append(lag_intf["name"])
        else:
            port_channel_list.append(lag_intf["teamdev"])
    vlan_test = stp_wrap.complete_data["dut_vlan_data"][dut_test]
    physical_interfaces_list1 = stp.get_stp_port_list(dut_test, vlan_test, exclude_port=port_channel_list)
    dut_tg_links = list()
    for interf in stp_ela[dut_test]['tg_links']:
        dut_tg_links.append(interf[0])
    physical_interfaces_list2 = stp.get_stp_port_list(dut_test, vlan_test, exclude_port=dut_tg_links)
    physical_interfaces_list = list(set(physical_interfaces_list1).intersection(physical_interfaces_list2))

    utils.banner_log("Shutting down/Starting up all the physical interfaces {} on the DUT {}".format(physical_interfaces_list, dut_test))
    count = 0
    while (count < 5):
        if count == 0:
            intf.interface_operation(dut_test, physical_interfaces_list , "shutdown")
            st.wait(5)

            # STP convergence check after trigger.
            st.log("Waiting for {} to converge".format(stp_protocol))
            st.wait(stp_dict[stp_protocol]["stp_wait_time"])
            utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
            stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

            if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
                st.log("Unicast traffic test PASSED")
            else:
                st.error("learned unicast test FAILED !!")
                result = 0

            intf.interface_operation(dut_test, physical_interfaces_list , "startup")
        else:
            intf.interface_operation(dut_test, physical_interfaces_list , "shutdown")
            st.wait(5)
            intf.interface_operation(dut_test, physical_interfaces_list , "startup")
        count = count + 1

    utils.banner_log("Verifying the physical interfaces states after multiple iterations of shut and no shut operation.")
    for each_intf in physical_interfaces_list:
        if not intf.poll_for_interface_status(dut_test, [each_intf], "oper", "up", iteration=5, delay=1):
            st.error("Failed to startup interface {} on the DUT {}".format(each_intf,dut_test))
            result=0

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])
    utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    return(result)

def lib_stp_save_reload(vars, stp_ela, stp_protocol):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify the STP convergence by reloading the DUT and checking for convergence.
    # Objective - Verify that switch is elected back as the root in the event of root switch failure by rebooting the root switch in STP topology.
    #
    ############### Test bed details ################
    result = 1

    utils.banner_log("Checking {} convergence and traffic before the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    utils.banner_log("Finding out a root bride in one of the vlan.")
    random_vlan = stp_wrap.tg_info['vlan_id']
    dut_test = stp_ela['states'][random_vlan]['root']
    st.log("Root bridge for vlan {} is {}".format(random_vlan, dut_test))

    utils.banner_log("Issuing config save and rebooting the DUT {}".format(dut_test))
    reboot.config_save(dut_test)
    st.reboot(dut_test)

    utils.banner_log("Polling for system status of DUT {}".format(dut_test))
    if not basic.poll_for_system_status(dut_test):
        st.error("SYSTEM is not ready !!")
        result = 0

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0
        st.log("Displaying interface counters for failed scenarios")
        intf.show_interface_counters_all(dut_test)

    return(result)

def lib_stp_config_reload(vars, stp_ela, stp_protocol):
    result = 1

    utils.banner_log("Checking {} convergence and traffic before the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    utils.banner_log("Finding out a root bride in one of the vlan.")
    random_vlan = stp_wrap.tg_info['vlan_id']
    dut_test = stp_ela['states'][random_vlan]['root']
    st.log("Root bridge for vlan {} is {}".format(random_vlan, dut_test))

    utils.banner_log("Issuing config save and config reloading the DUT {}".format(dut_test))
    reboot.config_save(dut_test)
    reboot.config_reload(dut_test)

    utils.banner_log("Polling for system status of DUT {}".format(dut_test))
    if not basic.poll_for_system_status(dut_test):
        st.error("SYSTEM is not ready !!")
        result = 0

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0
        st.log("Displaying interface counters for failed scenarios")
        intf.show_interface_counters_all(dut_test)

    return(result)

def lib_stp_fast_reboot(vars, stp_ela, stp_protocol):
    result = 1

    utils.banner_log("Checking {} convergence and traffic before the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    utils.banner_log("Finding out a root bride in one of the vlan.")
    random_vlan = stp_wrap.tg_info['vlan_id']
    dut_test = stp_ela['states'][random_vlan]['root']
    st.log("Root bridge for vlan {} is {}".format(random_vlan, dut_test))

    utils.banner_log("Issuing config save and fast rebooting the DUT {}".format(dut_test))
    reboot.config_save(dut_test)
    st.reboot(dut_test, "fast")

    utils.banner_log("Polling for system status of DUT {}".format(dut_test))
    if not basic.poll_for_system_status(dut_test):
        st.error("SYSTEM is not ready !!")
        result = 0

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        st.log("Displaying interface counters for failed scenarios")
        intf.show_interface_counters_all(dut_test)
        result = 0

    return(result)

def lib_stp_max_vlan_instances(vars, stp_ela, stp_protocol, max_stp_instances):
    ################# Author Details ################
    # Name: Rakesh Kumar Vooturi
    # Email:  rakesh-kumar.vooturi@broadcom.com
    #################################################
    #
    # Objective - Verify STP convergence with MAX instances.
    # Objective - Verify running max STP VLAN instances are not disrupted when max+1 vlan is created and ports are added to this vlan.
    #
    ############### Test bed details ################
    result = 1
    global unused_vlan_list
    global unused_vlan_list_range
    max_instances = list()
    for device in stp_wrap.get_dut_list(vars):
        version_data = basic.show_version(device)
        hw_constants_DUT = st.get_datastore(device, "constants")
        if version_data['hwsku'].lower() in hw_constants_DUT['TH3_PLATFORMS']:
            max_stp_instances = 62
            st.banner("platform used : {} max stp instances value : {}".format(device, max_stp_instances))
        else:
            max_stp_instances = max_stp_instances
            st.banner("platform used : {} max stp instances value : {}".format(device, max_stp_instances))
        max_instances.append(max_stp_instances)
    
    max_stp_instances = min(max_instances)
    st.banner("Taking the min value from max instances : {}".format(max_stp_instances))
    
    utils.banner_log("Checking {} convergence and traffic before the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"], stp_wrap.complete_data["dut_vlan_data"])
    st.log("Waiting for {} converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])
    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    used_vlan_list = stp_wrap.complete_data["vlan_data"]["vlan_list"]
    utils.banner_log("Used vlans: {}".format(used_vlan_list))

    unused_vlan_list = utils.get_random_vlans_in_sequence(count=max_stp_instances-len(used_vlan_list)+1, start=3100, end=4093)
    unused_vlan_list_range = "{} {}".format(unused_vlan_list[0],unused_vlan_list[-2])
    unused_vlan_list_range_plus_one = unused_vlan_list[-1]
    utils.banner_log("Unused vlans count: {}, Unused vlans range: {}, Unused vlans list: {}".format(len(unused_vlan_list),unused_vlan_list_range,unused_vlan_list))

    utils.banner_log("Configuring max vlans and particiapting all the DUTS in all the max vlans.")
    for device in stp_wrap.get_dut_list(vars):
        vlan.config_vlan_range(device, unused_vlan_list_range, config="add")
        vlan_test = stp_wrap.complete_data["dut_vlan_data"][device]
        intf_list = stp.get_stp_port_list(device, vlan_test, exclude_port="")
        vlan.config_vlan_range_members(device, unused_vlan_list_range, intf_list, config="add")

    dut_test = random.choice(stp_wrap.get_dut_list(vars))
    vlan_test = stp_wrap.complete_data["dut_vlan_data"][dut_test]
    interfaces_list = stp.get_stp_port_list(dut_test, vlan_test, exclude_port="")

    utils.banner_log("Shutting down/Starting up all the interfaces {} on the DUT {}".format(interfaces_list,dut_test))
    intf.interface_operation(dut_test, interfaces_list , "shutdown")
    st.wait(5)
    intf.interface_operation(dut_test, interfaces_list , "startup")
    st.wait(5)

    port_channel_list = list()
    for lag_intf in portchannel.get_portchannel_list(dut_test):
        if stp_cli_type != "click":
            port_channel_list.append(lag_intf["name"])
        else:
            port_channel_list.append(lag_intf["teamdev"])

    st.log("PORT CHANNEL LIST : {}".format(port_channel_list))
    utils.banner_log("Verifying the interfaces states after shut and no shut operation.")
    for interface in interfaces_list:
        if interface not in port_channel_list:
            if not intf.poll_for_interface_status(dut_test, [interface], "oper", "up", iteration=10, delay=1):
                st.error("Failed to startup interface {} on the DUT {}".format(interface,dut_test))
                result=0
        else:
            if not portchannel.poll_for_portchannel_status(dut_test, interface, "up", iteration=10, delay=1):
                st.error("Failed to startup port channel interface {} on the DUT {}".format(interface,dut_test))
                result=0

    st.log("Waiting for {} to converge".format(stp_protocol))
    st.wait(stp_dict[stp_protocol]["stp_wait_time"])

    utils.banner_log("Checking {} convergence and traffic after the test".format(stp_protocol))
    stp.check_for_single_root_bridge_per_vlan(stp_wrap.get_dut_list(vars), stp_wrap.complete_data["vlan_data"]["vlan_list"],stp_wrap.complete_data["dut_vlan_data"])

    st.log("Verifying ports are converged fine in all vlan instances")
    for vlan_id in used_vlan_list:
        if not stp_wrap.poll_stp_convergence(vars, vlan_id,iteration=30,delay=1):
            st.error("ports did not converged fine in vlan {}".format(vlan_id))
            result=0
        else:
            st.log("ports converged fine in vlan {}".format(vlan_id))

    if stp_wrap.verify_traffic('unicast', stp_wrap.tg_info):
        st.log("Unicast traffic test PASSED")
    else:
        st.error("learned unicast test FAILED !!")
        result = 0

    unused_vlan_list_range_cleanup = "{} {}".format(unused_vlan_list[0],unused_vlan_list[-2])
    utils.banner_log("Unconfiguring max+1 vlans and removing participation of all the interfaces in all the max vlans.")
    for device in stp_wrap.get_dut_list(vars):
        vlan_test = stp_wrap.complete_data["dut_vlan_data"][device]
        intf_list = stp.get_stp_port_list(device, vlan_test, exclude_port="")
        vlan.config_vlan_range_members(device, unused_vlan_list_range_cleanup, intf_list, config="del")
        vlan.config_vlan_range(device, unused_vlan_list_range_cleanup, config="del")
        st.wait(20)
    return(result)

def lib_stp_bpdu_filter(vars, stp_ela, stp_protocol):
    ################# Author Details ################
    # Name: Praveen Kumar Kota
    # Email: praveenkumar.kota@broadcom.com
    #################################################
    #
    # Objective - Verify that BPDU filter is working fine when DUT is working on spanning tree PVST mode.
    #
    #################################################
    #############################################################################################
    utils.banner_log("Verification of BPDU filter functinality -- STARTED")
    #############################################################################################

    result = 1
    pass_cnt = 0
    fail_cnt = 0
    bpdu_filter_wait = 30
    bpdu_filter_int_wait = 15
    bpdu_filter_bpdu_cnt = 12
    random_vlan = stp_wrap.tg_info['vlan_id']
    st.log("Random VLAN {}".format(random_vlan))

    root_bridge = stp_ela['states'][random_vlan]['root']
    st.log("Topology root bridge:  {}".format(root_bridge))

    root_ph_port = stp_wrap.get_physical_link_with_partner(root_bridge)[root_bridge][0]['local']
    st.log("Root port:  {}".format(root_ph_port))

    st.log("Displaying the spanning tree out on {} in vlan : {}".format(root_bridge, random_vlan))
    stp.show_stp_vlan(root_bridge, random_vlan)

    dut_partner_details = stp_wrap.get_dut_partner_details_by_dut_interface(root_bridge, root_ph_port)
    st.log("partner_details: {}".format(dut_partner_details))

    if root_ph_port in dut_partner_details[root_bridge]:
        local_interface_index = dut_partner_details[root_bridge].index(root_ph_port)
    else:
        local_interface_index = None
    st.log("Local Interface Index: {}".format(local_interface_index))

    st.log("Getting details of a DUT with TG connected port")
    dut_tg_info = stp_wrap.get_random_dut_tg_interface(no_of_duts=3, no_of_links=1)
    st.log("dut_tg: {} ".format(dut_tg_info))

    st.log("Device with Tg")
    dut_tg = dut_tg_info['dut']
    st.log("DUT with TG is : {}".format(dut_tg))

    st.log("Getting Tg link info")
    dut_tglink = dut_tg_info['physical_link']
    st.log("Physical link connected to tg is : {} ".format(dut_tglink))


    if stp_protocol=='rpvst':
        st.log("############## Configuring edge port on interface in rpvst ##########")
        stp.config_port_type(dut_tg,dut_tglink,stp_type='rpvst',port_type='edge',no_form=True)
        stp.config_port_type(dut_tg,dut_tglink,stp_type='rpvst',port_type='edge',no_form=False)
        intf.interface_shutdown(dut_tg, dut_tglink)
        if not stp.poll_for_stp_status(dut_tg, random_vlan, dut_tglink, 'DISABLED', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            result = 0
            st.error("Interface {} did not move to DISABLED state".format(dut_tglink))
            intf.interface_noshutdown(dut_tg, dut_tglink)
        else:
            st.log("Interface {} moved to DISABLED state as expected".format(dut_tglink))
        intf.interface_noshutdown(dut_tg, dut_tglink)

        if not stp.poll_for_stp_status(dut_tg, random_vlan, dut_tglink, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
            result = 0
            st.error("Interface {} is not moving to Forwarding state immediately when configured as Edge port".format(dut_tglink))
        else:
            st.log("Interface {} is moving to Forwarding state immediately as expected when configured as edge port".format(dut_tglink))
        if result:
            pass_cnt += 1
            st.report_tc_pass('ft_{}_edgeport'.format(stp_protocol), 'test_case_passed')
        else:
            fail_cnt += 1
            st.report_tc_fail('ft_{}_edgeport'.format(stp_protocol), 'test_case_failed')
    elif stp_protocol == "pvst":
        utils.banner_log("Enabling port fast config on TG link")
        stp.config_stp_interface_params(dut_tg, dut_tglink, portfast="enable")
        st.wait(2)
        if stp.get_stp_port_param(dut_tg, random_vlan, dut_tglink, "port_portfast") == "Y":
            st.log("Port fast is enabled on TG link.")
        else:
            result = 0
            st.error("Port fast is no enabled on TG link.")

    stp.config_bpdu_filter(dut_tg)

    intf.interface_shutdown(dut_tg, dut_tglink)

    if not stp.poll_for_stp_status(dut_tg, random_vlan, dut_tglink, 'DISABLED', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
        result = 0
        st.error("Interface {} did not move to DISABLED state".format(dut_tglink))
        intf.interface_noshutdown(dut_tg, dut_tglink)
    else:
        st.log("Interface {} moved to DISABLED state as expected".format(dut_tglink))

    stp.stp_clear_stats(dut_tg, vlan=random_vlan)

    intf.interface_noshutdown(dut_tg, dut_tglink)

    if not stp.poll_for_stp_status(dut_tg, random_vlan, dut_tglink, 'FORWARDING', iteration=stp_dict[stp_protocol]["stp_wait_time"], delay=1):
        result = 0
        st.error("Interface {} is not moving to Forwarding state immediately".format(dut_tglink))
    else:
        st.log("Interface {} is moving to Forwarding state immediately".format(dut_tglink))

    st.wait(bpdu_filter_wait)

    bpdu_tx_cnt = stp.get_stp_stats(dut_tg, random_vlan, dut_tglink, "st_bpdutx")

    if bpdu_tx_cnt > bpdu_filter_bpdu_cnt :
        result = 0
        st.error("operation_failed_msg - BPDU counters are not incremented when bpdu filter is configured globally")
    else:
        st.log("BPDU counters incremented successfuly when BPDU filter is configured globally")

    st.log("Disabling bpdu_filter at interface level on TG port {}".format(dut_tg))
    stp.config_bpdu_filter(dut_tg, interface=dut_tglink, action="disable")
    stp.show_stp_stats_vlan(dut_tg, random_vlan)
    stp.stp_clear_stats(dut_tg, vlan=random_vlan)
    st.wait(bpdu_filter_int_wait)
    bpdu_tx_cnt = stp.get_stp_stats(dut_tg, random_vlan, dut_tglink, "st_bpdutx")
    if bpdu_tx_cnt == 0 :
        result = 0
        st.error("operation_failed_msg - BPDU counters are not incremented on {} when bpdu filter is configured globally and disabled on interface".format(dut_tglink))
    else:
        st.log("BPDU counters incremented successfuly on {} when BPDU filter is configured globally and disabled on interface level".format(dut_tglink))
    if result:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_bpdu_filter_edgeport'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_bpdu_filter_edgeport'.format(stp_protocol),'test_case_failed')

    st.log("Doing no form of bpdu_filter at interface level on TG port {}".format(dut_tg))
    stp.config_bpdu_filter(dut_tg, interface=dut_tglink, no_form=True)
    stp.show_stp_stats_vlan(dut_tg, random_vlan)
    stp.stp_clear_stats(dut_tg, vlan=random_vlan)
    st.wait(bpdu_filter_int_wait)
    bpdu_tx_cnt = stp.get_stp_stats(dut_tg, random_vlan, dut_tglink, "st_bpdutx")
    if bpdu_tx_cnt != 0:
        result = 0
        st.error(
            "operation_failed_msg - BPDU counters are incremented on {} when bpdu filter is configured globally and no form of bpdu filter on interface".format(
                dut_tglink))
    else:
        st.log(
            "BPDU counters are not incremented successfuly on {} when BPDU filter is configured globally and no form of bpdu filter on interface level".format(
                dut_tglink))

    if result:
        pass_cnt += 1
        st.report_tc_pass('ft_{}_bpdu_filter_int_no_form'.format(stp_protocol), 'test_case_passed')
    else:
        fail_cnt += 1
        st.report_tc_fail('ft_{}_bpdu_filter_int_no_form'.format(stp_protocol), 'test_case_failed')

    #############################################################################################
    utils.banner_log("Verification of BPDU filter is enabled globally and on interface -- STARTED")
    #############################################################################################
    result=1
    partner_dut = ''
    for key, value in dut_partner_details.items():
        if key != root_bridge:
            partner_dut = key
    if partner_dut and local_interface_index!=None:
        remote_interface = dut_partner_details[partner_dut][local_interface_index]
        st.log("Enabling bpdu_filter at interface level on {}".format(partner_dut))
        stp.config_bpdu_filter(partner_dut,interface=remote_interface,action="enable")
        stp.show_stp_stats_vlan(partner_dut, random_vlan)
        stp.stp_clear_stats(partner_dut, vlan=random_vlan)
        st.wait(bpdu_filter_int_wait)
        bpdu_tx_cnt = stp.get_stp_stats(partner_dut, random_vlan, remote_interface, "st_bpdutx")
        bpdu_rx_cnt = stp.get_stp_stats(partner_dut, random_vlan, remote_interface, "st_bpdurx")

        if bpdu_tx_cnt > 0 or bpdu_rx_cnt > 0:
            result = 0
            st.error(
                "operation_failed_msg - BPDU counters are  incremented on interface {} which has  bpdu filter configured".format(
                    remote_interface))
        else:
            st.log("BPDU counters are not incremented on interface {} when BPDU filter is configured at interface level".format(
                remote_interface))
    if result:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_bpdu_filter_{}_mode'.format(stp_protocol,stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_bpdu_filter_{}_mode'.format(stp_protocol,stp_protocol),'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of BPDU filter is enabled globally and on interface -- COMPLETED")
    #############################################################################################

    #############################################################################################
    utils.banner_log("Verification of BPDU filter is enabled globally and disabled on interface -- STARTED")
    #############################################################################################
    result=1
    st.log("Disabling bpdu_filter at interface level on {}".format(partner_dut))
    stp.config_bpdu_filter(partner_dut,interface=remote_interface,action="disable")
    stp.show_stp_stats_vlan(partner_dut, random_vlan)
    stp.stp_clear_stats(partner_dut, vlan=random_vlan)
    st.wait(bpdu_filter_int_wait)
    bpdu_tx_cnt = stp.get_stp_stats(partner_dut, random_vlan, remote_interface, "st_bpdutx")
    bpdu_rx_cnt = stp.get_stp_stats(partner_dut, random_vlan, remote_interface, "st_bpdurx")

    if bpdu_tx_cnt == 0 and bpdu_rx_cnt == 0:
        result = 0
        st.error(
            "operation_failed_msg - BPDU counters are  not incremented on interface {} which has  bpdu filter disabled".format(
                remote_interface))
    else:
        st.log("BPDU counters are  incremented on interface {} when BPDU filter is disabled at interface level".format(
            remote_interface))
    if result:
        pass_cnt+=1
        st.report_tc_pass('ft_{}_bpdu_filter_Global_mode_enable'.format(stp_protocol),'test_case_passed')
    else:
        fail_cnt+=1
        st.report_tc_fail('ft_{}_bpdu_filter_Global_mode_enable'.format(stp_protocol),'test_case_failed')
    #######################################################################################################
    utils.banner_log("Verification of BPDU filter is globally disabled and enabled on interface -- STARTED")
    #######################################################################################################
    result = 1
    st.log("Disabling BPDU filter globally")
    stp.config_bpdu_filter(dut_tg, no_form=True)
    st.log("Enabling bpdu_filter at interface level on {}".format(partner_dut))
    stp.config_bpdu_filter(partner_dut, interface=remote_interface, action="enable")
    stp.show_stp_stats_vlan(partner_dut, random_vlan)
    stp.stp_clear_stats(partner_dut, vlan=random_vlan)
    st.wait(bpdu_filter_int_wait)
    bpdu_tx_cnt = stp.get_stp_stats(partner_dut, random_vlan, remote_interface, "st_bpdutx")
    bpdu_rx_cnt = stp.get_stp_stats(partner_dut, random_vlan, remote_interface, "st_bpdurx")

    if bpdu_tx_cnt != 0 and bpdu_rx_cnt != 0:
        result = 0
        st.error(
            "operation_failed_msg - BPDU counters are  incremented on interface {} which has bpdu filter enabled and globally disabled".format(
                remote_interface))
    else:
        st.log(
            "BPDU counters are not incremented on interface {} when BPDU filter is disabled at interface level and globally disabled".format(
                remote_interface))
    ########################################################################################################
    utils.banner_log("Verification of BPDU filter is globally disabled and enabled on interface -- completed")
    ########################################################################################################
    if result:
        pass_cnt += 1
        st.report_tc_pass('ft_{}_bpdu_filter_intf_mode_enable'.format(stp_protocol), 'test_case_passed')
    else:
        fail_cnt += 1
        st.report_tc_pass('ft_{}_bpdu_filter_intf_mode_enable'.format(stp_protocol), 'test_case_failed')
    #############################################################################################
    utils.banner_log("Verification of BPDU filter is enabled on portchannel interface -- STARTED")
    #############################################################################################
    result = 1
    st.log("Get local and remote DUTs for port channel; and get port channel name")
    portchannel_data = stp_wrap.get_portchannel_details()
    for key, value in portchannel_data.items():
        port_channel_name = key
        local_dut_for_po = value["partners"][0]
    stp.config_bpdu_filter(local_dut_for_po)
    st.log("Enabling bpdu_filter at interface level on {}".format(local_dut_for_po))
    stp.config_bpdu_filter(local_dut_for_po, interface=port_channel_name, action="enable")
    stp.show_stp_stats_vlan(local_dut_for_po, random_vlan)
    stp.stp_clear_stats(local_dut_for_po, vlan=random_vlan)
    st.wait(bpdu_filter_int_wait)
    bpdu_tx_cnt = stp.get_stp_stats(local_dut_for_po, random_vlan, port_channel_name, "st_bpdutx")
    bpdu_rx_cnt = stp.get_stp_stats(local_dut_for_po, random_vlan, port_channel_name, "st_bpdurx")

    if bpdu_tx_cnt != 0 and bpdu_rx_cnt != 0:
        result = 0
        st.error(
            "operation_failed_msg - BPDU counters are  incremented on interface {} which has bpdu filter enabled on portchannel interface".format(
                port_channel_name))
    else:
        st.log(
            "BPDU counters are not incremented on interface {} when BPDU filter is enabled at portchannel interface level".format(
                port_channel_name))

    if result:
        pass_cnt += 1
        st.report_tc_pass('ft_{}_bpdu_filter_lag_port'.format(stp_protocol), 'test_case_passed')
    else:
        fail_cnt += 1
        st.report_tc_pass('ft_{}_bpdu_filter_lag_port'.format(stp_protocol), 'test_case_failed')
    ############################################################################################################
    utils.banner_log("Verification of BPDU filter is globally disabled and enabled on portchannel  -- Completed")
    #############################################################################################################
    st.log("Disabling BPDU filter globally and on interfaces")
    stp.config_bpdu_filter(local_dut_for_po, no_form=True)
    stp.config_bpdu_filter(partner_dut, interface=remote_interface, action="disable")
    stp.config_bpdu_filter(local_dut_for_po, interface=port_channel_name, action="disable")
    utils.banner_log("Total Test cases PASSED are {} | Total Test cases FAILED are {}".format(pass_cnt, fail_cnt))

    if fail_cnt:
        return(result)
    else:
        return(result)

def verify_stp_config(data, protocol, vlan_id):
    """
    To verify configurations using gnmi/rest response
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param data:
    :param protocol:
    :param vlan_id:
    :return:
    """
    stp_get = "openconfig-spanning-tree:stp"
    if not data:
        st.log("Get response not found")
        return False
    if protocol == "pvst":
        stp_type = "openconfig-spanning-tree-ext:PVST"
        stp_status = "spanning-tree-enable"
        stp_get_type = "openconfig-spanning-tree-ext:pvst"
    elif protocol == "rpvst":
        stp_type = "openconfig-spanning-tree-types:RAPID_PVST"
        stp_status = "openconfig-spanning-tree-ext:spanning-tree-enable"
        stp_get_type = "rapid-pvst"
    else:
        st.log("Invalid protocol")
        return False
    if not data[stp_get]["global"]["config"]["enabled-protocol"][0] == stp_type:
        st.log("pvst is not enabled")
        return False
    output = data[stp_get][stp_get_type]["vlan"]
    vlan_data = common_obj.filter_and_select(output=output, match={"vlan-id": vlan_id})
    if not vlan_data[0]["state"][stp_status]:
        st.log("{} is not enabled on configured vlan".format(protocol))
        return False
    return True

def gnmi_rest_unconfig(vars, vlan_id, intf_name):
    vlan.delete_vlan_member(dut=vars.D1, vlan=vlan_id, port_list= intf_name)
    vlan.delete_vlan(dut=vars.D1, vlan_list=vlan_id)

def lib_stp_rest(vars, protocol):
    """
    To verify STP rest calls
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param vars:
    :param protocol:
    :return:
    """
    rest_url = "/restconf/data/openconfig-spanning-tree:stp"
    vlan_list = vlan.get_vlan_list(dut=vars.D1)
    vlan_id = common_obj.random_vlan_list(exclude=vlan_list)[0]
    intf_name = st.get_free_ports(vars.D1)[0]
    vlan.create_vlan(dut=vars.D1, vlan_list=vlan_id)
    vlan.add_vlan_member(dut=vars.D1, vlan=vlan_id, port_list=intf_name)
    delete_resp = st.rest_delete(vars.D1, path=rest_url)
    if not rest_obj.rest_status(delete_resp['status']):
        st.error("Delete request failed")
        gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
        return False
    intf = st.get_other_names(vars.D1, [intf_name])[0] if vars.config.ifname_type == 'alias' else intf_name
    if protocol == "pvst":
        stp_pvst = "openconfig-spanning-tree-ext:pvst"
        data = json.loads("""
        {
          "openconfig-spanning-tree:global": {
            "config": {
              "enabled-protocol": [
                "openconfig-spanning-tree-ext:PVST"
              ],
              "bpdu-filter": false,
              "openconfig-spanning-tree-ext:rootguard-timeout": 30,
              "openconfig-spanning-tree-ext:hello-time": 2,
              "openconfig-spanning-tree-ext:max-age": 20,
              "openconfig-spanning-tree-ext:forwarding-delay": 15,
              "openconfig-spanning-tree-ext:bridge-priority": 32768
            }
          },
          "openconfig-spanning-tree-ext:pvst": {
            "vlan": [
              {
                "vlan-id": 0,
                "config": {
                  "vlan-id": 0,
                  "hello-time": 2,
                  "max-age": 20,
                  "forwarding-delay": 15,
                  "bridge-priority": 32768
                },
                "interfaces": {
                  "interface": [
                    {
                      "name": "string",
                      "config": {
                        "name": "string",
                        "cost": 200,
                        "port-priority": 128
                      }
                    }
                  ]
                }
              }
            ]
          }
        }
            """)
        data[stp_pvst]["vlan"][0]["vlan-id"] = vlan_id
        data[stp_pvst]["vlan"][0]["config"]["vlan-id"] = vlan_id
        data[stp_pvst]["vlan"][0]["interfaces"]["interface"][0]["name"] = intf
        data[stp_pvst]["vlan"][0]["interfaces"]["interface"][0]["config"]["name"] = intf
        post_resp = st.rest_create(vars.D1, path=rest_url, data=data)
        if not rest_obj.rest_status(post_resp['status']):
            st.log("POST request failed")
            stp.config_spanning_tree(vars.D1, feature="pvst", mode="enable")
            gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
            return False
        get_resp = st.rest_read(vars.D1, rest_url)
        if not rest_obj.rest_status(get_resp['status']):
            st.log("GET request failed")
            gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
            return False
        if not verify_stp_config(data=get_resp["output"], protocol=protocol, vlan_id=vlan_id):
            gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
            return False
    else:
        stp_rpvst = "openconfig-spanning-tree:stp"
        data = json.loads("""
        {
         "openconfig-spanning-tree:stp": {
           "global": {
             "config": {
               "enabled-protocol": [
                 "openconfig-spanning-tree-types:RAPID_PVST"
               ],
               "bpdu-filter": false,
               "openconfig-spanning-tree-ext:rootguard-timeout": 30,
               "openconfig-spanning-tree-ext:hello-time": 2,
               "openconfig-spanning-tree-ext:max-age": 20,
               "openconfig-spanning-tree-ext:forwarding-delay": 15,
               "openconfig-spanning-tree-ext:bridge-priority": 32768
             }
           },
           "rapid-pvst": {
             "vlan": [
               {
                 "vlan-id": 0,
                 "config": {
                   "vlan-id": 0,
                   "hello-time": 2,
                   "max-age": 20,
                   "forwarding-delay": 15,
                   "bridge-priority": 32768
                 },
                 "interfaces": {
                   "interface": [
                     {
                       "name": "string",
                       "config": {
                         "name": "string",
                         "cost": 2000,
                         "port-priority": 128
                       }
                     }
                   ]
                 }
               }
             ]
           },
           "interfaces": {
             "interface": [
               {
                 "name": "string",
                 "config": {
                   "name": "string",
                   "link-type": "P2P",
                   "guard": "ROOT",
                   "bpdu-guard": false,
                   "bpdu-filter": false,
                   "openconfig-spanning-tree-ext:portfast": true,
                   "openconfig-spanning-tree-ext:uplink-fast": true,
                   "openconfig-spanning-tree-ext:bpdu-guard-port-shutdown": true
                 }
               }
             ]
           }
         }
        }
          """)
        data[stp_rpvst]["rapid-pvst"]["vlan"][0]["vlan-id"] = vlan_id
        data[stp_rpvst]["rapid-pvst"]["vlan"][0]["config"]["vlan-id"] = vlan_id
        data[stp_rpvst]["rapid-pvst"]["vlan"][0]["interfaces"]["interface"][0]["name"] = intf
        data[stp_rpvst]["rapid-pvst"]["vlan"][0]["interfaces"]["interface"][0]["config"]["name"] = intf
        data[stp_rpvst]["interfaces"]["interface"][0]["name"] = intf
        data[stp_rpvst]["interfaces"]["interface"][0]["config"]["name"] = intf
        put_resp = st.rest_update(vars.D1, path=rest_url, data=data)
        if not rest_obj.rest_status(put_resp['status']):
            st.error("PUT request failed")
            stp.config_spanning_tree(vars.D1, feature="rpvst", mode="enable")
            gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
            return False
        get_resp = st.rest_read(vars.D1, rest_url)
        if not rest_obj.rest_status(get_resp['status']):
            st.error("GET response failed")
            gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
            return False
        if not verify_stp_config(data=get_resp["output"], protocol=protocol, vlan_id=vlan_id):
            gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
            return False
    gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
    return True

def lib_stp_gnmi(vars, protocol, stp_ela=''):
    """
    To perform and verify STP gnmi calls
    Author: Pradeep Bathula (pradeep.b@broadcom.com)
    :param vars:
    :param protocol:
    :return:
    """
    # if protocol=='pvst':
        # verify_klish_commands(stp_ela,protocol)
    # if protocol=='rpvst':
        # verify_klish_commands(stp_ela,protocol)

    gnmi_url = "/openconfig-spanning-tree:stp/"
    stp_set = "openconfig-spanning-tree:stp"
    vlan_list = vlan.get_vlan_list(dut=vars.D1)
    vlan_id = common_obj.random_vlan_list(exclude=vlan_list)[0]
    intf_name = st.get_free_ports(vars.D1)[1]
    vlan.create_vlan(dut=vars.D1, vlan_list=vlan_id)
    vlan.add_vlan_member(dut=vars.D1, vlan=vlan_id, port_list=intf_name)
    stp.config_spanning_tree(vars.D1, feature=protocol, mode="disable")
    intf = st.get_other_names(vars.D1, [intf_name])[0] if vars.config.ifname_type == 'alias' else intf_name

    if protocol == "rpvst":
        data = json.loads("""
        {"openconfig-spanning-tree:stp":{
        "global": {
        "config": {
        "enabled-protocol": [
        "openconfig-spanning-tree-types:RAPID_PVST"
        ],
        "bpdu-filter": true,
        "openconfig-spanning-tree-ext:rootguard-timeout": 30,
        "openconfig-spanning-tree-ext:hello-time": 2,
        "openconfig-spanning-tree-ext:max-age": 20,
        "openconfig-spanning-tree-ext:forwarding-delay": 15,
        "openconfig-spanning-tree-ext:bridge-priority": 32768
        }
        },
        "rapid-pvst": {
        "vlan": [{
        "vlan-id": 0,
        "config": {
        "vlan-id": 0,
        "hello-time": 2,
        "max-age": 20,
        "forwarding-delay": 15,
        "bridge-priority": 32768
        },
        "interfaces": {
        "interface": [{
        "name": "string",
        "config": {
        "name": "string",
        "cost": 2000,
        "port-priority": 128
        }
        }]
        }
        }]
        },
        "interfaces": {
        "interface": [{
        "name": "string",
        "config": {
        "name": "string",
        "edge-port": "openconfig-spanning-tree-types:EDGE_DISABLE",
        "link-type": "P2P",
        "guard": "ROOT",
        "bpdu-guard": true,
        "bpdu-filter": true,
        "openconfig-spanning-tree-ext:portfast": false,
        "openconfig-spanning-tree-ext:uplink-fast": false,
        "openconfig-spanning-tree-ext:bpdu-guard-port-shutdown": false
        }
        }]
        }
        }
        }
        """)
        protocol_type = "rapid-pvst"
        stp_get = "openconfig-spanning-tree-types:RAPID_PVST"
        stp_intf = "interfaces"
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0]["vlan-id"] = vlan_id
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0]["config"]["vlan-id"] = vlan_id
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0][stp_intf]["interface"][0]["name"] = intf
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0][stp_intf]["interface"][0]["config"]["name"] = intf
        data["openconfig-spanning-tree:stp"][stp_intf]["interface"][0]["name"] = intf
        data["openconfig-spanning-tree:stp"][stp_intf]["interface"][0]["config"]["name"] = intf
    else:
        data = json.loads("""
        {"openconfig-spanning-tree:stp":{
        "global": {
        "config": {
        "enabled-protocol": [
        "openconfig-spanning-tree-ext:PVST"
        ],
        "bpdu-filter": false,
        "openconfig-spanning-tree-ext:rootguard-timeout": 30,
        "openconfig-spanning-tree-ext:hello-time": 2,
        "openconfig-spanning-tree-ext:max-age": 20,
        "openconfig-spanning-tree-ext:forwarding-delay": 15,
        "openconfig-spanning-tree-ext:bridge-priority": 32768
        }
        },
        "openconfig-spanning-tree-ext:pvst": {
        "vlan": [{
        "vlan-id": 0,
        "config": {
        "vlan-id": 0,
        "hello-time": 2,
        "max-age": 20,
        "forwarding-delay": 15,
        "bridge-priority": 32768
        },
        "interfaces": {
        "interface": [{
        "name": "string",
        "config": {
        "name": "string",
        "cost": 200,
        "port-priority": 128
        }
        }]
        }
        }]
        },
        "interfaces": {
        "interface":[{
        "name": "string",
        "config": {
        "name": "string",
        "bpdu-guard": false,
        "guard": "NONE",
        "openconfig-spanning-tree-ext:bpdu-guard-port-shutdown": false,
        "openconfig-spanning-tree-ext:portfast": true,
        "openconfig-spanning-tree-ext:spanning-tree-enable": true,
        "openconfig-spanning-tree-ext:uplink-fast": false
        }
        }]
        }
        }
        }
        """)
        protocol_type = "openconfig-spanning-tree-ext:pvst"
        stp_get = "openconfig-spanning-tree-ext:PVST"
        stp_intf = "interfaces"
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0]["vlan-id"] = vlan_id
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0]["config"]["vlan-id"] = vlan_id
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0][stp_intf]["interface"][0]["name"] = intf
        data["openconfig-spanning-tree:stp"][protocol_type]["vlan"][0][stp_intf]["interface"][0]["config"]["name"] = intf
        data["openconfig-spanning-tree:stp"]["interfaces"]["interface"][0]["name"] = intf
        data["openconfig-spanning-tree:stp"]["interfaces"]["interface"][0]["config"]["name"] = intf
    if not gnmi_obj.gnmi_set(dut=vars.D1, xpath=gnmi_url, json_content=data):
        if protocol == "rpvst":
            stp.config_spanning_tree(vars.D1, feature="rpvst", mode="enable")
        else:
            stp.config_spanning_tree(vars.D1, feature="pvst", mode="enable")
        gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
        return False
    get_resp = gnmi_obj.gnmi_get(dut=vars.D1, xpath=gnmi_url)
    if not get_resp:
        st.log("gnmi_get response not found")
        gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
        return False
    if not get_resp[stp_set]["global"]["config"]["enabled-protocol"][0] == stp_get:
        st.log("STP is not enabled")
        gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
        return False
    if not verify_stp_config(data=get_resp, protocol=protocol, vlan_id=vlan_id):
        gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)
        return False
    gnmi_rest_unconfig(vars, vlan_id=vlan_id, intf_name=intf_name)

    # if protocol=='pvst':
        # verify_klish_commands(stp_ela,protocol)
    # if protocol=='rpvst':
        # verify_klish_commands(stp_ela,protocol)
    return True

def klish_cmd_validator(commands, stp_ela):
    random_vlan = stp_wrap.tg_info['vlan_id']
    root_bridge = stp_ela['states'][random_vlan]['root']
    cmd_validator(root_bridge, commands, cli_type='klish')

def verify_klish_commands(stp_ela, stp_protocol):
    """

    :param vars:
    :param stp_ela:
    :param stp_protocol:
    :return:
    """
    random_vlan = stp_wrap.tg_info['vlan_id']
    root_bridge = stp_ela['states'][random_vlan]['root']
    root_ph_port = stp_wrap.get_physical_link_with_partner(root_bridge)[root_bridge][0]['local']
    root_ph_port_num = utils.get_interface_number_from_name(root_ph_port)

    st.banner("config start")
    commands = """
    interface Ethernet {}
    spanning-tree uplinkfast
    no spanning-tree enable
    exit
    spanning-tree vlan {} priority 4096
    spanning-tree vlan {} hello-time 4
    spanning-tree hello-time 6
    spanning-tree guard root timeout 40
    no spanning-tree vlan {}
    no spanning-tree mode
    """.format(root_ph_port_num["number"],random_vlan,random_vlan,random_vlan)
    klish_cmd_validator(commands, stp_ela)
    st.wait(10)

    st.banner("Unconfig start")
    commands = """
    spanning-tree mode {}
    spanning-tree vlan {}
    no spanning-tree vlan {} priority
    no spanning-tree vlan {} hello-time
    no spanning-tree hello-time
    no spanning-tree guard root timeout
    interface Ethernet {}
    no spanning-tree uplinkfast
    spanning-tree enable
    exit
    """.format(stp_protocol, random_vlan, random_vlan, random_vlan,root_ph_port_num["number"])
    klish_cmd_validator(commands, stp_ela)
