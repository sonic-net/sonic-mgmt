import pytest
from tabulate import tabulate

from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.reboot as reboot_api
from evpn_convergence import *
from utilities import parallel

scale = SpyTestDict()
trigger_list = ['link_down_active','link_up_active','link_down_stdby','link_up_stdby',
                'link_down_uplink','link_up_uplink','reboot_active_node','reboot_stdby_node','reboot_spine']

data.iteration_count = 3
data.threshold = 1.0


@pytest.fixture(scope="module", autouse=True)
def evpn_underlay_hooks(request):
    global vars
    create_glob_vars()
    vars = st.get_testbed_vars()
    if st.get_ui_type() == 'click':
        st.report_unsupported("test_execution_skipped", "Not supported for ui_type - click")
    api_list = [[create_evpn_5549_config]]
    parallel.exec_all(True, api_list, True)
    create_stream()

    st.log("verify MC LAG status in LVTEP nodes")
    mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                        session_status='OK',local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0],
                        peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1],mclag_intfs=1,
                        peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role='Active')
    mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                        session_status='OK',local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0],
                        peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1],mclag_intfs=1,
                        peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role='Standby')
    st.log("verify MC LAG interface status in LVTEP nodes")
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][0],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up",
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')
    mclag.verify_interfaces(evpn_dict["leaf_node_list"][1],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                            mclag_intf=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
                            mclag_intf_local_state="Up", mclag_intf_peer_state="Up",
                            mclag_intf_l3_status='No',isolate_peer_link='Yes',
                            traffic_disable='No')

    st.log("verify BGP EVPN neighborship for all nodes ")
    result = st.exec_all([[spine1_verify_evpn],[spine2_verify_evpn],[leaf1_verify_evpn],
                          [leaf2_verify_evpn],[leaf3_verify_evpn]])

    if result[0].count(False) > 0:
        st.error("########## BGP EVPN neighborship is NOT UP on all spine and leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")

    st.log("verify vxlan tunnel status on leaf nodes")
    result=st.exec_all([[leaf1_verify_vxlan],[leaf2_verify_vxlan],[leaf3_verify_vxlan]])
    if result[0].count(False) > 0:
        st.error("########## VxLAN tunnel status is NOT up on all leaf nodes; Abort the suite ##########")
        st.report_fail("base_config_verification_failed")
    get_mlag_active_stdby('Active')

    st.exec_all([[reboot_api.config_save,data['active']],[reboot_api.config_save,data['stdby']],[reboot_api.config_save,evpn_dict['spine_node_list'][0]]])
    st.exec_all([[reboot_api.config_save, data['active'],'vtysh'], [reboot_api.config_save, data['stdby'],'vtysh'],
                 [reboot_api.config_save, evpn_dict['spine_node_list'][0],'vtysh']])

    data.config_tgen_bgp = False
    yield


def test_convergence_l2_unknown(evpn_underlay_hooks):
    func_result=True;err_list=[]
    data['table'] = list()
    data.tc_list = ['l2_unknown']
    for tc in data.tc_list:
        tc_result = True
        ############################################
        st.banner('Testcase - {}'.format(tc))
        ############################################
        data['table_{}'.format(tc)] = list()
        for trigger in trigger_list:
            tech_support = True;
            ##########################################################
            st.banner('Testcase -{} : Trigger - {}'.format(tc,trigger))
            ###########################################################
            data[trigger] = {}
            data['table_{}'.format(trigger)] = [tc, trigger]
            if 'uplink' in trigger:
                st.log("\n\n>>> Keep only one uplink port between Leaf and Spine nodes <<<<\n\n")
                st.exec_all([[port_api.shutdown,evpn_dict['leaf_node_list'][0],[evpn_dict["leaf1"]["intf_list_spine"][0],
                                                                                evpn_dict["leaf1"]["intf_list_spine"][3],
                  evpn_dict["leaf1"]["intf_list_spine"][4],evpn_dict["leaf1"]["intf_list_spine"][7]]],
                             [port_api.shutdown, evpn_dict['leaf_node_list'][1],
                              [evpn_dict["leaf2"]["intf_list_spine"][0], evpn_dict["leaf2"]["intf_list_spine"][3],
                               evpn_dict["leaf2"]["intf_list_spine"][4], evpn_dict["leaf2"]["intf_list_spine"][7]]]])
            for iter in range(data.iteration_count):
                ##################################################
                st.banner('Testcase -{} : Trigger - {},Iteration -{}'.format(tc,trigger,(iter+1)))
                ###################################################
                convergence_time = convergence_measure(tc,trigger=trigger,streams=stream_dict[tc],iteration=(iter+1))
                if type(convergence_time) is bool and convergence_time is False:
                    data[trigger]['convergence_{}'.format(iter)] = None
                else:
                    data[trigger]['convergence_{}'.format(iter)] = float(convergence_time)
                if data[trigger]['convergence_{}'.format(iter)] > data.threshold or data[trigger]['convergence_{}'.format(iter)] is None:
                    err = "Average Traffic convergence after {} : {} sec".format(trigger,data[trigger]['convergence_{}'.format(iter)])
                    st.error(err)
                    st.report_tc_fail(tc, 'test_case_failure_message', err)
                    if tech_support: st.generate_tech_support(dut=None, name='{}_{}_{}'.format(tc,trigger,iter))
                    tech_support = False;tc_result=False;err_list.append(err);func_result=False
                revert_trigger_change(trigger,iteration=(iter+1))
                table_append = data[trigger]['convergence_{}'.format(iter)]
                data['table_{}'.format(trigger)].append(table_append)
            get_average_convergence(data[trigger],trigger)

            if 'uplink' in trigger:
                st.log(">>> \n\nBring back all uplink ports between Leaf and SPine nodes <<<<\n\n")
                st.exec_all([[port_api.noshutdown,evpn_dict['leaf_node_list'][0],[evpn_dict["leaf1"]["intf_list_spine"][0],
                                                                                evpn_dict["leaf1"]["intf_list_spine"][3],
                  evpn_dict["leaf1"]["intf_list_spine"][4],evpn_dict["leaf1"]["intf_list_spine"][7]]],
                             [port_api.noshutdown, evpn_dict['leaf_node_list'][1],
                              [evpn_dict["leaf2"]["intf_list_spine"][0], evpn_dict["leaf2"]["intf_list_spine"][3],
                               evpn_dict["leaf2"]["intf_list_spine"][4], evpn_dict["leaf2"]["intf_list_spine"][7]]]])
                if 'link_down_uplink' not in trigger :
                    st.log("verify BGP EVPN neighborship for all nodes ")
                    st.exec_all([[leaf1_verify_evpn],[leaf2_verify_evpn]])
            if tc_result:
                st.report_tc_pass(tc,'test_case_passed')
            data['table_{}'.format(tc)].append(data['table_{}'.format(trigger)])
        #Append each testcase along with all trigger result to data.table
        data['table'].append(data['table_{}'.format(tc)])
    #Tabulate results
    tabulate_results(data['table'])
    if not func_result:
        st.report_fail('test_case_failure_message',err_list[0])
    st.report_pass('test_case_passed')




def test_convergence_l3_scale(evpn_underlay_hooks):
    func_result=True;err_list=[]
    data['table'] = list()
    tgen_emulate_bgp()
    data.config_tgen_bgp = True
    data.tc_list = ['scale']
    for tc in data.tc_list:
        tc_result = True
        ############################################
        st.banner('Testcase - {}'.format(tc))
        ############################################
        data['table_{}'.format(tc)] = list()
        for trigger in trigger_list:
            tech_support = True;
            ##########################################################
            st.banner('Testcase -{} : Trigger - {}'.format(tc,trigger))
            ###########################################################
            data[trigger] = {}
            data['table_{}'.format(trigger)] = [tc, trigger]
            if 'uplink' in trigger:
                st.log("\n\n>>> Keep only one uplink port between Leaf and Spine nodes <<<<\n\n")
                st.exec_all([[port_api.shutdown,evpn_dict['leaf_node_list'][0],[evpn_dict["leaf1"]["intf_list_spine"][0],
                                                                                evpn_dict["leaf1"]["intf_list_spine"][3],
                  evpn_dict["leaf1"]["intf_list_spine"][4],evpn_dict["leaf1"]["intf_list_spine"][7]]],
                             [port_api.shutdown, evpn_dict['leaf_node_list'][1],
                              [evpn_dict["leaf2"]["intf_list_spine"][0], evpn_dict["leaf2"]["intf_list_spine"][3],
                               evpn_dict["leaf2"]["intf_list_spine"][4], evpn_dict["leaf2"]["intf_list_spine"][7]]]])
            for iter in range(data.iteration_count):
                ##################################################
                st.banner('Testcase -{} : Trigger - {},Iteration -{}'.format(tc,trigger,(iter+1)))
                ###################################################
                convergence_time = convergence_measure(tc,trigger=trigger,streams=stream_dict[tc],iteration=(iter+1))
                if type(convergence_time) is bool and convergence_time is False:
                    data[trigger]['convergence_{}'.format(iter)] = None
                else:
                    data[trigger]['convergence_{}'.format(iter)] = float(convergence_time)
                if data[trigger]['convergence_{}'.format(iter)] > data.threshold or data[trigger]['convergence_{}'.format(iter)] is None:
                    err = "Average Traffic convergence after {} : {} sec".format(trigger,data[trigger]['convergence_{}'.format(iter)])
                    st.error(err)
                    st.report_tc_fail(tc, 'test_case_failure_message', err)
                    if tech_support: st.generate_tech_support(dut=None, name='{}_{}_{}'.format(tc,trigger,iter))
                    tech_support = False;tc_result=False;err_list.append(err);func_result=False
                revert_trigger_change(trigger,iteration=(iter+1))
                table_append = data[trigger]['convergence_{}'.format(iter)]
                data['table_{}'.format(trigger)].append(table_append)
            get_average_convergence(data[trigger],trigger)

            if 'uplink' in trigger:
                st.log(">>> \n\nBring back all uplink ports between Leaf and SPine nodes <<<<\n\n")
                st.exec_all([[port_api.noshutdown,evpn_dict['leaf_node_list'][0],[evpn_dict["leaf1"]["intf_list_spine"][0],
                                                                                evpn_dict["leaf1"]["intf_list_spine"][3],
                  evpn_dict["leaf1"]["intf_list_spine"][4],evpn_dict["leaf1"]["intf_list_spine"][7]]],
                             [port_api.noshutdown, evpn_dict['leaf_node_list'][1],
                              [evpn_dict["leaf2"]["intf_list_spine"][0], evpn_dict["leaf2"]["intf_list_spine"][3],
                               evpn_dict["leaf2"]["intf_list_spine"][4], evpn_dict["leaf2"]["intf_list_spine"][7]]]])
                if 'link_down_uplink' not in trigger :
                    st.log("verify BGP EVPN neighborship for all nodes ")
                    st.exec_all([[leaf1_verify_evpn],[leaf2_verify_evpn]])
            if tc_result:
                st.report_tc_pass(tc,'test_case_passed')
            data['table_{}'.format(tc)].append(data['table_{}'.format(trigger)])
        #Append each testcase along with all trigger result to data.table
        data['table'].append(data['table_{}'.format(tc)])
    #Tabulate results
    tabulate_results(data['table'])
    if not func_result:
        st.report_fail('test_case_failure_message',err_list[0])
    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def ecmp_fixture(evpn_underlay_hooks):
    st.banner("ECMP Pre-Config")
    st.log(">>>> Bring down all paths from Leaf3 to Spine-1 <<<<<\n\n")
    if data.config_tgen_bgp is False:
        tgen_emulate_bgp()
        data.config_tgen_bgp = True
    port_api.shutdown(evpn_dict['leaf_node_list'][2],evpn_dict["leaf3"]["intf_list_spine"][0:4])
    yield
    st.banner("ECMP Post-Config")
    start_traffic(action='stop',stream_han_list=stream_dict['scale'])
    st.log(">>>> Bring back all paths from Leaf3 to Spine-1 <<<<<\n\n")
    port_api.noshutdown(evpn_dict['leaf_node_list'][2], evpn_dict["leaf3"]["intf_list_spine"][0:4])

def test_convergence_ecmp(ecmp_fixture):
    func_result=True
    table = {}
    ecmp_intf_list = [evpn_dict["leaf3"]["pch_intf_list"][1] ,evpn_dict["leaf3"]["intf_list_spine"][4],
                                                            evpn_dict["leaf3"]["intf_list_spine"][7]]
    port_flap_list = evpn_dict["spine2"]["intf_list_leaf"][8:]
    port_flap_list_2 = evpn_dict["leaf3"]["intf_list_spine"][4:]
    header1 = ['link_{}_shut'.format(i+1) for i in range(len(port_flap_list[:-1]))]
    header2 = ['link_{}_noshut'.format(i + 1) for i in range(len(port_flap_list[::-1][1:]))]
    header1[1] = 'link_2_shut(Po member port)'
    header2[1] = 'link_2_noshut(Po member port)'
    data['table_header'] = ['ECMP']+header1+header2

    ################################################
    st.banner("Verify Traffic is getting hashed along all ECMP paths between Leaf3-SPine2")
    ################################################

    start_traffic(stream_han_list=stream_dict['scale'])
    st.wait(10,'Wait for 10 sec before checking ECMP hashing')
    if not retry_api(verify_ecmp_hashing,evpn_dict['leaf_node_list'][2],ecmp_intf_list):
        err = 'Traffic hashing did not happen across ecmp paths from Leaf3 to SPine2'
        st.report_fail('test_case_failure_message',err)

    start_traffic(action='stop', stream_han_list=stream_dict['scale'])
    for dut,port_list in zip([evpn_dict['spine_node_list'][1],evpn_dict['leaf_node_list'][2]],[port_flap_list,port_flap_list_2]):
        st.banner(">>> ECMP test with port flap on DUT {} <<<<".format(dut))
        data['table_data'] = []
        for iter in range(int(data.iteration_count)):
            st.banner("\n\n >>>>> Iteration : {} <<<<<\n\n".format(iter+1))
            result = convergence_ecmp(dut,port_list,streams=stream_dict['scale'],iteration=(iter+1))
            data['table_data'].append(data['table_data_{}'.format(iter+1)])
            if not result: func_result=False

        table[dut] = tabulate(data['table_data'], headers=data['table_header'], tablefmt="grid")

    for dut in [evpn_dict['spine_node_list'][1],evpn_dict['leaf_node_list'][2]]:
        st.log("\n\n>>>> ECMP Convergence Table with port flap done on {} <<<<<\n\n".format(dut))
        st.log("\n\n" + table[dut])

    if not func_result:
        st.report_fail('test_case_failure_message','ECMP convergence test failed')
    st.report_pass('test_case_passed')



def no_test_convergence_orphan_traffic(evpn_underlay_hooks):
    #st.log("create static ARP in DUT4 for DUT3's orphan traffic")
    #Arp.add_static_arp(evpn_dict["mlag_node_list"][1], evpn_dict["leaf3"]["v4_prefix"][0], evpn_dict["orphan_mac"],
    #                             interface=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0])
    if data.config_tgen_bgp is False:
        tgen_emulate_bgp()
        data.config_tgen_bgp = True
    tech_support = True;func_result=True;err_list=[]
    data['table'] = list()
    trigger_list = ['shut_all_uplinks_active']
    data.tc_list = ['orphan_traffic']
    for tc in data.tc_list:
        tc_result = True
        ############################################
        st.banner('Testcase - {}'.format(tc))
        ############################################
        data['table_{}'.format(tc)] = list()
        for trigger in trigger_list:
            ##########################################################
            st.banner('Testcase -{} : Trigger - {}'.format(tc,trigger))
            ###########################################################
            data[trigger] = {}
            data['table_{}'.format(trigger)] = [tc, trigger]

            for iter in range(data.iteration_count):
                ##################################################
                st.banner('Testcase -{} : Trigger - {},Iteration -{}'.format(tc,trigger,(iter+1)))
                ###################################################
                convergence_time = convergence_measure(tc,trigger=trigger,streams=stream_dict[tc],iteration=(iter+1))
                if type(convergence_time) is bool and convergence_time is False:
                    data[trigger]['convergence_{}'.format(iter)] = None
                else:
                    data[trigger]['convergence_{}'.format(iter)] = float(convergence_time)
                if data[trigger]['convergence_{}'.format(iter)] > data.threshold or data[trigger]['convergence_{}'.format(iter)] is None:
                    err = "Average Traffic convergence after {} : {} sec".format(trigger,data[trigger]['convergence_{}'.format(iter)])
                    st.error(err)
                    st.report_tc_fail(tc, 'test_case_failure_message', err)
                    if tech_support: st.generate_tech_support(dut=None, name='test_convergence_on_fail')
                    tech_support = False;tc_result=False;err_list.append(err);func_result=False

                table_append = data[trigger]['convergence_{}'.format(iter)]
                data['table_{}'.format(trigger)].append(table_append)
            get_average_convergence(data[trigger],trigger)

            if tc_result:
                st.report_tc_pass(tc,'test_case_passed')
            data['table_{}'.format(tc)].append(data['table_{}'.format(trigger)])
        #Append each testcase along with all trigger result to data.table
        data['table'].append(data['table_{}'.format(tc)])
    #Tabulate results
    tabulate_results(data['table'])
    if not func_result:
        st.report_fail('test_case_failure_message',err_list[0])
    st.report_pass('test_case_passed')
