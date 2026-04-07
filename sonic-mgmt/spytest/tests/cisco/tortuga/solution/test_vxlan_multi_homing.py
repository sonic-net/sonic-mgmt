import os
import re
import yaml
import pytest
import random
from spytest import st, tgapi
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.switching.portchannel as pc_obj
from spytest.tgen import tg
import vxlan_helper as vxlan_obj
import profile
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj
import apis.system.basic as basic
from spytest.utils import poll_wait
from copy import deepcopy
import json
from utilities.utils import get_intf_short_name


@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    global vars, nodes, pf, tgen_handles, test_cfg, CONFIGS_FILE

    CONFIGS_FILE = 'vxlan_multi_homing_input.yaml'

    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        test_cfg = yaml.load(f, Loader=yaml.FullLoader)

    test_cfg['nodes'] = {'leaf': [], 'spine': [], 'all': [], 'l2l3vni': []}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            test_cfg['nodes']['leaf'].append(dut)
        else:
            test_cfg['nodes']['spine'].append(dut)
        test_cfg['nodes']['all'].append(dut)

        if test_cfg.get(dut) and \
           'l2vni' in test_cfg[dut].keys() and \
           'l3vni' in test_cfg[dut].keys():
            test_cfg['nodes']['l2l3vni'].append(dut)

    if not test_cfg.get('testcases'): 
        test_cfg['testcases'] = dict()
        test_cfg['global'] = dict()

    # setting platform specific variables
    if not st.getenv('platform'):
        if basic.get_hwsku('leaf0') == "Cisco-HF6100-64ED":
            platform = 'g200'
        else:
            platform = 'q200'
    else:
        platform = st.getenv('platform')

    if platform == 'g200':
        test_cfg['global']['ndf_exp_tx_pkts'] = 300
        test_cfg['global']['bum_triggers_retries'] = 4
        test_cfg['global']['del_add_bgp_retries'] = 10
        test_cfg['global']['proc_restart_retries'] = 7
        test_cfg['global']['config_reload'] = 7
        test_cfg['global']['plus_bringup_time'] = 12
        test_cfg['global']['traffic_stop_protocol_sleep'] = 15
        test_cfg['global']['traffic_start_protocol_sleep'] = 15
        test_cfg['global']['restart_tgen_per_class'] = False
        # TODO test_cfg['global']['dpb_types'] = ['1x800G', '2x400G', '4x200G', '8x100G']
        test_cfg['global']['dpb_types'] = ['2x400G']
    else:
        test_cfg['global']['ndf_exp_tx_pkts'] = 150
        test_cfg['global']['bum_triggers_retries'] = 2
        test_cfg['global']['del_add_bgp_retries'] = 5
        test_cfg['global']['proc_restart_retries'] = 5
        test_cfg['global']['config_reload'] = 5
        test_cfg['global']['plus_bringup_time'] = 0
        test_cfg['global']['traffic_stop_protocol_sleep'] = 15
        test_cfg['global']['traffic_start_protocol_sleep'] = 15
        test_cfg['global']['restart_tgen_per_class'] = False
        test_cfg['global']['dpb_types'] = ['1x50', '1x25G', '1x10G']

    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()
    pf = profile.VxlanMultiHomingProfile(input_file=CONFIGS_FILE, vars=vars, 
                                          leaf_nodes=test_cfg['nodes']['leaf'], spine_nodes=test_cfg['nodes']['spine'],
                                          l2l3vni_nodes=test_cfg['nodes']['l2l3vni'], test_cfg=test_cfg)

@pytest.fixture(scope="module", autouse=True)
def copy_default_config_db():
    cmd = "sudo cp /etc/sonic/config_db.json config_db.json.orig"
    for dut in st.get_dut_names():
        st.config(dut, cmd, skip_error_check=True)

@pytest.fixture(scope="module", autouse=True)
def copy_spytest_helper():
    for dut in st.get_dut_names():
        st.config(dut, "cp /etc/spytest/remote/spytest-helper.py /etc/sonic/spytest-helper.py ")
        st.config(dut, " ls -lrt  /etc/spytest/remote/")
        st.config(dut, " ls -lrt /etc/sonic/")
    yield
    for dut in st.get_dut_names():
        st.config(dut,"rm /etc/sonic/spytest-helper.py")

def restore_helper_file(dut):
    st.config(dut, "mkdir -p /etc/spytest/remote")
    st.config(dut, "cp /etc/sonic/spytest-helper.py /etc/spytest/remote/spytest-helper.py")
    st.config(dut, "ls -lrt /etc | grep spytest")

@pytest.fixture(scope="module", autouse=True)
def vxlan_multi_homing_config():
    global tgen_handles
    
    if st.getenv('skip_cfg', 'false') == 'false':
        pf.configure_sonic()
        # configure_tgen is called in fixture of all classes . add back if fixture changes
        #tgen_handles = pf.configure_tgen()

        for node in test_cfg['nodes']['l2l3vni']:
            vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")
            vxlan_obj.config_dut(node, "bgp", "do write")

    yield
    if st.getenv('skip_uncfg', 'false') == 'false':
        pf.configure_sonic(config=False)
   
        for node in test_cfg['nodes']['all']:
            vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")


@pytest.fixture(scope = "function", autouse=True)
def pretest(request):
    result = True
    
    for dut in test_cfg['nodes']['l2l3vni']:
        st.log("Pretest : Check vteps on leaf_nodes node: {}".format(dut))
        try:
            exp_data = vxlan_obj.get_expected_vxlan_remotevtep(dut)
            vxlan_obj.verify_vxlan_remotevtep(dut, exp_data)
            st.log('Verify Vxlan-VNI map on {}: Pass'.format(dut))
        except Exception as err:
            st.log('Verify EVPN ES-EVI on {}: Fail\n{}'.format(dut, err))
            result = False

    if result:
        st.log("Pretest : Pass")
    else:
        st.log("Pretest : Fail")
        vxlan_obj.get_cli_out(test_cfg['nodes']['l2l3vni'])
        vxlan_obj.collect_diags()
        st.banner("Pretest : Fail. Skipping testcase.")
    return result

@pytest.fixture(scope="function", autouse=True)       
def fail_on_core(request):
    cores = vxlan_obj.check_core()
    cores = None

    if cores:
        st.banner("core present in dut before the start of the test, core copied and failing test")
        st.report_fail("test_case_failed")
    yield
    cores = vxlan_obj.check_core()
    if cores:
        st.banner("core generated during the test, core copied and failing test")
        st.report_fail("test_case_failed")

@pytest.fixture(scope="function", autouse=False)
def pause_run(request):
    pause_before = st.getenv('pause_before', None)
    if pause_before == request.node.name or \
        pause_before == 'all':
        value = raw_input("Press return to continue...")

    yield

    pause_after = st.getenv('pause_after', None)
    if pause_after == request.node.name or \
        pause_after == 'all':
        value = raw_input("Press return to continue...")

def reset_preconf_tgen(kill=True):

    global test_cfg, tgen_handles, vars
    if kill:
        for tgen in vars['tgen_list']:
            tgobj =  tgapi.get_tgen_obj_dict()[tgen]
            #tgobj.clean_all()
            tgobj.tg_disconnect()
        st.wait(120)
        tg.connect_tgen()
    tgen_handles = pf.configure_tgen()

    return True

@pytest.fixture(scope = 'function', autouse=True)
def tgen_health_check(request):
    test_cfg['tgen_tc_status'] = {'last_tc': request.node.name, request.node.name: True}
    yield
    st.log('Last failure {} : {} : {}'.format(request.node.name, st.get_result(), st.getwa().last_error))
    if st.getwa().last_error and st.getwa().last_error.startswith('TG'):
        st.banner('TGen Failure detected ({}), reseting tgen'.format(st.getwa().last_error))
        reset_preconf_tgen()
        test_cfg['tgen_tc_status'][request.node.name] = False


@pytest.fixture(scope = 'class', autouse=True)
def tgen_health_check_class(request):
    if test_cfg['global'].get('restart_tgen_force', 'first') == 'first':
        st.banner('Configuring IXIA')
        reset_preconf_tgen(kill=False)
        test_cfg['global']['restart_tgen_force'] = False
    elif test_cfg['global']['restart_tgen_force'] == True:
        st.banner('Restarting and Reconfiguring IXIA')
        reset_preconf_tgen()
        test_cfg['global']['restart_tgen_force'] = False
    elif test_cfg['global']['restart_tgen_per_class']:
        if test_cfg['tgen_tc_status'][test_cfg['tgen_tc_status']['last_tc']] == True:
            #if the prev testcase tgen failed and did reset then dont reset
            st.banner('Restarting and Reconfiguring IXIA as restart tgen per class flag is set')
            reset_preconf_tgen()
    yield
    st.log('Last failure {} : {} : {}'.format(request.node.name, st.get_result(), st.getwa().last_error))
    if st.getwa().last_error and st.getwa().last_error.startswith('TG'):

        # module result is set to TGenFail if the fixture 
        # for the class fails due to tgen failure
        # this will result in skipping all remaining tests in the module.
        # Reset the module result to pass after tgen recovery
        test_cfg['global']['restart_tgen_force'] = True
        from spytest import framework
        res, desc = framework.get_current_result('module')
        st.log('Current Module Result: {} Desc: {}'.format(res, desc))
        framework.set_current_result(res=None, scope='module')
        res, desc = framework.get_current_result('module')
        st.log('New Module Result set: {} Desc: {}'.format(res, desc))
        st.log(st.getwa().abort_module_msg)
        st.log(st.getwa().abort_module_res)
        st.getwa().abort_module_msg = None
        st.getwa().abort_module_res = None

@pytest.fixture(scope = 'class', autouse=True)
def config_random_dpb_underlay(request):
    if st.getenv('config_dpb', 'true') == 'true':
        try:
            dpb_type = random.choice(test_cfg['global']['dpb_types'])
            st.log("Configuring new DPB setting on underlay links: {})".format(dpb_type))
            pf.change_underlay_dpb(dpb_type=dpb_type)
        except Exception as err:
            if not "already configured" in str(err):
                raise err

@pytest.mark.usefixtures('tgen_health_check_class')
class TestVxlanMultiHomingBase():
    
    def test_base_mh_l2l3vni_bringup(self, pause_run):
        """
        Testcase: Bring up L2VNI and L3VNI with multi-homed host.(Control plane only)
        Description:
            1)Bring up the Multihoming profile . Refer to MH base profile .
            2)Bring up ebgp between spine and leaf. Bring up V6 underlay and V6 overlay .
            3)Configure portchannel for the links part of multi-homed host .
            4)Verify type 4 route is exchanged to discover other ESI members connected to same host.
            5)Verify Type 1 route is also exchanged between the leaf's for the remote leaf to load balance
            traffic to multi-homed host .  Based on Auto-discover routes received by all remote vteps ,
            it should build a forwarding table to load-balance the traffic to each leafs with dual-homed host.Verify
            Route-Type-1 per ES and per EVI
            6)Verify if DF is Elected
            7)Verify BFD session is up .
            8)Verify No core/crashes
        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify , DF / NDF election .
        """
        tc_id = "test_base_mh_l2l3vni_bringup"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        st.banner('Testcase MH:125: Bring up L2VNI and L3VNI with multi-homed host ({})'.format(tc_id))
        leaf_nodes = test_cfg['nodes']['l2l3vni']
        result = True
        summ = ''

        for dut in leaf_nodes:
            st.banner('Verify L2VNI and L3VNI with multi-homed on leaf node: {}'.format(dut))
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vlanvnimap(dut)
                vxlan_obj.verify_vxlan_vlanvnimap(dut, exp_data)
                st.log('Verify Vxlan-VlanVni map on {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Verify Vxlan-VlanVni map on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False
            try:
                exp_data = vxlan_obj.get_expected_vxlan_vrfvnimap(dut)
                vxlan_obj.verify_vxlan_vrfvnimap(dut, exp_data)
                st.log('Verify Vxlan-VrfVni map on {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Verify Vxlan-VrfVni map on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False

        vxlan_obj.report_result(result, tc_id, summ)

    def test_base_mh_frr_es(self, pause_run):
        """
        Testcase: Verify FRR ES SHOW commands:
        Description:
            - show evpn es detail
            - show evpn es XX:XX:XX:XX:XX:XX:XX:XX:XX:XX
            - show evpn es-evi detail
            - show evpn es-evi (1-16777215)"
        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify FRR ES show commands
        """
        tc_id = "test_base_mh_frr_es"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        st.banner('Testcase MH:126: Verify FRR ES SHOW commands ({})'.format(tc_id))
        leaf_nodes = test_cfg['nodes']['l2l3vni']
        result = True
        summ = ''

        for dut in leaf_nodes:
            st.banner('Verify EVPN ES on leaf node: {}'.format(dut))
            try:
                exp_data = vxlan_obj.get_expected_evpn_es(dut)
                vxlan_obj.verify_evpn_es(dut, exp_data)
                st.log('Verify EVPN ES on {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Verify EVPN ES on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False

            try:
                exp_data = vxlan_obj.get_expected_evpn_es_evi(dut)
                vxlan_obj.verify_evpn_es_evi(dut, exp_data)
                st.log('Verify EVPN ES-EVI on {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Verify EVPN ES-EVI on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False

        vxlan_obj.report_result(result, tc_id, summ)

    def test_base_mh_evpn(self, pause_run):
        """
        Testcase: Verify FRR ES SHOW commands:
        Description:

        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify EVPN ES show commands
        """
        tc_id = "test_base_mh_evpn"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        st.banner('Testcase MH:127: Verify EVPN SHOW commands ({})'.format(tc_id))
        leaf_nodes = test_cfg['nodes']['l2l3vni']
        result = True
        summ = ''

        for dut in leaf_nodes:
            st.banner('Verify EVPN ES on leaf node: {}'.format(dut))
            try:
                exp_data = vxlan_obj.get_expected_vxlan_remotevtep(dut)
                vxlan_obj.verify_vxlan_remotevtep(dut, exp_data)
                st.log('Verify Vxlan remote vtep on {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Verify Vxlan remote vtep on on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False

        vxlan_obj.report_result(result, tc_id, summ)

    def test_base_mh_nexthop_group(self, pause_run):
        """
        Testcase: check L2 Next-hop group
        Description:
            1) show vxlan l2-nexthop-group
            For each ES-ID, a unique L2 Next-hop group (NHG) is formed that contains the participating VTEPs.
        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify vxlan neighbour groups
        """
        tc_id = "test_base_mh_nexthop_group"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        st.banner('Testcase MH:281: check L2 Next-hop group ({})'.format(tc_id))
        leaf_nodes = test_cfg['nodes']['l2l3vni']
        result = True
        summ = ''

        for dut in leaf_nodes:
            st.banner('Verify vxlan neighbor group on leaf node: {}'.format(dut))

            try:
                pf.verify_vxlan_neigh_groups(dut)
                st.log('Verify Vxlan neighbor group on {}: Pass'.format(dut))
            except Exception as err:
                msg = 'Verify Vxlan neighbor group on {}: Fail\n{}\n'.format(dut, err)
                st.log(msg)
                summ += msg
                result = False

        vxlan_obj.report_result(result, tc_id, summ)

    def test_base_mh_L2L3VNI_v4_traffic(self, pause_run):
        """
        Testcase: Verify L2VNI and L3VNI IPv4 traffic between the hosts .
        Hosts will be multi-homed and single homed as well . IPv4 traffic over V6Vtep
        Description:
            Pre-requisite : MH:1 test to pass .
            1)Send L2VNI traffic (IPv4 host) based on the traffic flows mentioned in MH base profile .
                Verify no traffic drops.
            2)Send L3VNI traffic(IPv4 host)based on traffic flows mentioned in MH base profile .
                Verify no traffic drops.

            Add pure l2 unicast traffic
        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify L2VNI / L3VNI IPv4 Traffic
        """
        tc_id = "test_base_mh_L2L3VNI_v4_traffic"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        st.banner('Testcase MH:129: Verify L2VNI and L3VNI IPv4 traffic between the hosts ({})'.format(tc_id))
        result = True
        summ = ''

        if pf.verify_traffic(tgen_handles,regenerate = True, traffic_types=['l2_v4', 'l3_v4']):
            st.log('L2VNI and L3VNI IPv4 traffic Check: Pass')
        else:
            summ = 'L2VNI and L3VNI IPv4 traffic Check: Fail'
            st.log(summ)
            result = False

        vxlan_obj.report_result(result, tc_id, summ)

    def test_base_mh_L2L3VNI_v6_traffic(self, pause_run):
        """
        Testcase: Verify L2VNI and L3VNI IPv6 traffic between the hosts .
        Hosts will be multi-homed and single homed as well . IPv6 traffic over V6Vtep
        Description:
            Pre-requisite : MH:1 test to pass .
            1)Send L2VNI traffic (IPv6 host) based on the traffic flows mentioned in MH base profile .
                Verify no traffic drops.
            2)Send L3VNI traffic(IPv6 host)based on traffic flows mentioned in MH base profile .
                Verify no traffic drops.

            Add pure l2 unicast traffic
        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify L2VNI / L3VNI IPv6 Traffic
        """
        tc_id = "test_base_mh_L2L3VNI_v6_traffic"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        st.banner('Testcase MH:130: Verify L2VNI and L3VNI IPv6 traffic between the hosts ({})'.format(tc_id))
        result = True
        summ = ''

        if pf.verify_traffic(tgen_handles,regenerate = True, traffic_types=['l2_v6', 'l3_v6']):
            st.log('L2VNI and L3VNI IPv6 traffic Check: Pass')
        else:
            summ = 'L2VNI and L3VNI IPv6 traffic Check: Fail'
            st.log(summ)
            result = False

        vxlan_obj.report_result(result, tc_id, summ)

    def test_base_mh_dual_home_BUM_traffic(self, pause_run):
        """
        Testcase: V6vtep : BUM traffic validation from dual-homed host to orphan host
        Hosts will be multi-homed and single homed as well . IPv6 traffic over V6Vtep
        Description:
            1)Bring up the Multihoming profile .
            2)Verify Broadcast, Unknown unicast and Multicast traffic with multi-homed host.
            3)Verify only 1 leaf is a DF(designated forwarder) and other leaf's are Backup designated
                forwarder (BDF) for BUM traffic to avoid receiving/sending duplicate frames .
            4)Verify that only DF sends BUM traffic to Dualhomed host and not the NDF
            5)Send Traffic from Dual homed host with L1 being DF for Vlan6 . Same BUM traffic for
                VLAN6 should not be received back to the Dual homed host from L0 .
            6)Verify Ingress Replication for BUM
            H5 to H11 . Send with both vlan2 and vlan3
        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify BUM traffic originating from dual homed hosts
        """
        tc_id = "test_base_mh_dual_home_BUM_traffic"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        st.banner('Testcase MH:140: BUM Traffic verification from dual-homed host ({})'.format(tc_id))
        result = True
        summ = ''

        if pf.verify_traffic(tgen_handles,regenerate = True, bum=True, traffic_types=['bum_MH']):
            st.log('Single-Homed BUM traffic Check: Pass')
        else:
            summ = 'Single-Homed BUM traffic Check: Fail'
            st.log(summ)
            result = False
        vxlan_obj.report_result(result, tc_id, summ)

    def test_base_mh_single_home_BUM_traffic(self, pause_run):
        """
        Testcase: V6vtep : BUM Traffic verification with dual-homed host .(Split horizon)
        Description:
            1)Bring up the Multihoming profile .
            2)Verify Broadcast, Unknown unicast and Multicast traffic with multi-homed host.
            3)Verify only 1 leaf is a DF(designated forwarder) and other leaf's are Backup designated
                forwarder (BDF) for BUM traffic to avoid receiving/sending duplicate frames .
            4)Verify that only DF sends BUM traffic to Dualhomed host and not the NDF
            5)Send Traffic from Dual homed host with L1 being DF for Vlan6 . Same BUM traffic for
                VLAN6 should not be received back to the Dual homed host from L0 .
            6)Verify Ingress Replication for BUM
            H5 to H11 . Send with both vlan2 and vlan3
        Steps:
            1. Multihoming profile is brought up by module level fixtures
            2. Verify BUM traffic originating from dual homed hosts
        """
        tc_id = "test_base_mh_single_home_BUM_traffic"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params('test_mh_bum_triggers')
        tc_cfg['uncfg_cli'] = dict()
        df_dut = tc_cfg['df_dut']
        df_dut_id = vxlan_obj.get_device_id(df_dut,vars)
        ndf_dut = tc_cfg['ndf_dut']
        ndf_dut_id = vxlan_obj.get_device_id(ndf_dut,vars)
        es_if = 'PortChannel{}'.format(tc_cfg['port_channel_num'])
        traffic_type = 'bum_SH'
        result = True
        summ = ''

        st.banner('Testcase MH:140: BUM Traffic verification to dual-homed host ({})'.format(tc_id))

        st.log('Verify EVPN ES peering state on {}'.format(df_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(df_dut)
            vxlan_obj.verify_evpn_es(df_dut, exp_data)
            st.log('EVPN ES peering state verifcation : Pass')
        except vxlan_obj.CompareFailed as err:
            msg = 'EVPN ES peering state verifcation on {}: Fail\n{}\n'.format(df_dut, err)
            st.log(msg)
            summ += msg
            result = False

        st.log('Verify EVPN ES peering state on {}'.format(ndf_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(ndf_dut)
            vxlan_obj.verify_evpn_es(ndf_dut, exp_data)
            st.log('EVPN ES peering state verifcation : Pass')
        except vxlan_obj.CompareFailed as err:
            msg = 'EVPN ES peering state verifcation on {}: Fail\n{}\n'.format(df_dut, err)
            st.log(msg)
            summ += msg
            result = False

        df_int_id = df_dut_id + test_cfg[df_dut]['port_channels'][0]['member_ids'][0]
        ndf_int_id = ndf_dut_id + test_cfg[ndf_dut]['port_channels'][0]['member_ids'][0]

        # calculating expected packet expected
        df_exp_tx_pkts = 0
        ndf_exp_tx_pkts = test_cfg['global']['ndf_exp_tx_pkts']
        for stream_cntr, stream_info in tgen_handles[traffic_type].items():
            for dst_port, handle in stream_info['dst_ports']:
                if es_if in dst_port:
                    df_exp_tx_pkts += test_cfg['global']['bum']['pkts_per_burst']

        st.log('Clearing Interface counters on duts')
        st.show(df_dut, "sonic-clear counters",  skip_tmpl=True)
        st.show(ndf_dut, "sonic-clear counters",  skip_tmpl=True)

        st.log('Verify traffic to multi-homed host')
        if pf.verify_traffic(tgen_handles, bum=True, traffic_types=[traffic_type]):
            st.banner('BUM Traffic Check Passed')
        else:
            st.banner('BUM Traffic Check Failed')
            msg = 'BUM Traffic Check Failed'
            st.log(msg)
            summ += msg
            result = False

        # getting multi-homed member link on dut
        df_dut_int_cntrs = intf_obj.show_interfaces_counters(dut=df_dut, 
                                                            interface=[vars[df_int_id]])
        ndf_dut_int_cntrs = intf_obj.show_interfaces_counters(dut=ndf_dut, 
                                                            interface=[vars[ndf_int_id]])
            
        st.log('Tx counter on DF dut {} interface {} : {}'.format(df_dut, vars[df_int_id],
                                                        df_dut_int_cntrs[0]['tx_ok']))
        df_tx = int(df_dut_int_cntrs[0]['tx_ok'].replace(',', ''))
        if df_tx > df_exp_tx_pkts:
            st.log('Tx counter {} > {} on DF node: Pass'.format(df_tx, df_exp_tx_pkts))
        else:
            msg = 'Tx counter {} < {} on DF node: Fail'.format(df_tx, df_exp_tx_pkts)
            st.log(msg)
            summ += msg
            result = False

        st.log('Tx counter on NDF dut {} interface {} : {}'.format(ndf_dut, vars[ndf_int_id],
                                                        ndf_dut_int_cntrs[0]['tx_ok']))
        ndf_tx = int(ndf_dut_int_cntrs[0]['tx_ok'].replace(',', ''))
        if ndf_tx < ndf_exp_tx_pkts:
            st.log('Tx counter {} < {} on NDF node: Pass'.format(ndf_tx, ndf_exp_tx_pkts))
        else:
            msg = 'Tx counter {} > {} on NDF node: Fail'.format(ndf_tx, ndf_exp_tx_pkts)
            st.log(msg)
            summ += msg
            result = False

        vxlan_obj.report_result(result, tc_id, summ)

###TRIGGERS####
@pytest.mark.usefixtures("tgen_health_check_class")
class TestVxlanBumTriggers():

    def test_mh_local_int_down(self, cleanup_mh_int_down, pause_run):
        """
        Testcase: Solution_test:MH:269 :  BUM Traffic Verification with local DF interface shut(host side)
        Description:
            "1)Bring up the Multi-homing profile
            2)Shut the local interface to the DF leaf0 .
            3)Verify that  other leaf1 of dual homed host becomes DF and traffic flows through that.
            4)Unshut the interface to Older leaf0 and verify that if the leaf0 becomes DF or leaf1 stays as DF
            5)Verify no core/crash"
        Steps:
            Check DF and NDF states of leaf0 and leaf1
            Shut Tgen vport to df
            Check DF and NDF states of leaf0 and leaf1
            clear interface counters
            check bum_sh traffic works
            verify new df counters increments
            unshut tgen vport
            Check DF and NDF states of leaf0 and leaf1
        """
        tc_id = "test_bum_local_int_shut"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params('test_mh_bum_triggers')
        tc_cfg['uncfg'] = None
        df_dut = tc_cfg['df_dut']
        ndf_dut = tc_cfg['ndf_dut']
        es_if = 'PortChannel{}'.format(tc_cfg['port_channel_num'])
        result = True

        st.banner('Testcase : BUM Traffic Verification with local DF interface shut(host side) ({})'.format(tc_id))
        # calling common api to verify testcase
        result = self._verify_mh_int_down(tc_id=tc_id, tc_cfg=tc_cfg, df_dut=df_dut, ndf_dut=ndf_dut,
                                 interface = es_if, shut_oper = 'local')

        vxlan_obj.report_result(result, tc_id)

    def test_mh_remote_int_down(self, cleanup_mh_int_down, pause_run):
        """
        Testcase: Solution_test:MH:269 :  BUM Traffic Verification with remove DF interface shut(router side)
        Description:
            "1)Bring up the Multi-homing profile
            2)Shut the remote interface to the DF leaf0 .
            3)Verify that  other leaf1 of dual homed host becomes DF and traffic flows through that.
            4)Unshut the interface to Older leaf0 and verify that if the leaf0 becomes DF or leaf1 stays as DF
            5)Verify no core/crash"
        Steps:
            Check DF and NDF states of leaf0 and leaf1
            Shut DF router portchannel interface 
            Check DF and NDF states of leaf0 and leaf1
            clear interface counters
            check bum_sh traffic works
            verify new df counters increments
            UnShut DF router portchannel interface 
            Check DF and NDF states of leaf0 and leaf1
        """
        tc_id = "test_bum_remote_int_shut"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params('test_mh_bum_triggers')
        tc_cfg['uncfg'] = None
        df_dut = tc_cfg['df_dut']
        ndf_dut = tc_cfg['ndf_dut']
        es_if = 'PortChannel{}'.format(tc_cfg['port_channel_num'])
        result = True

        st.banner('Testcase : BUM Traffic Verification with remove DF interface shut(router side) ({})'.format(tc_id))
        # calling common api to verify testcase
        result = self._verify_mh_int_down(tc_id=tc_id, tc_cfg=tc_cfg, df_dut=df_dut, ndf_dut=ndf_dut,
                                 interface = es_if, shut_oper = 'remote')

        vxlan_obj.report_result(result, tc_id)

    def test_mh_local_bias(self, pause_run, cleanup_local_bias):
        """
        Testcase: Solution_test:MH:152 :  Verify DF election with Node Failures of original Non-DF
        Description:
            1)Bring up Multihoming profile
            2)L1 being the DF for the dualhomed host between L0 and L1 .
            3)Send BUM traffic from orphan host behind L0.
            4)Eventhough L1 is DF , due to local bias feature , L0 should forward BUM traffic to dual homed host .
        Steps:
            1)Change DF preference on DF leaf 0 .
            2)Check Leaf 1 is new DF
            3)Send and Verify Bum traffic from Leaf 0 orphen port
            4)Check interface counters to verify local bias
            5)remove DF preference on DF leaf 0 .
        """
        tc_id = 'test_mh_local_bias'
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params('test_mh_bum_triggers')
        df_dut = tc_cfg['df_dut']
        ndf_dut = tc_cfg['ndf_dut']
        tc_cfg['interface'] = 'PortChannel{}'.format(tc_cfg['port_channel_num'])
        tc_cfg['df_pref'] = 100
        tc_cfg['ndf_pref'] = 10
        summ = ''
        tc_cfg['uncfg'] = False
        traffic_type = 'bum_SH'
        result = True
        df_dut_id = vxlan_obj.get_device_id(df_dut,vars)                         
        ndf_dut_id = vxlan_obj.get_device_id(ndf_dut,vars)
        df_int_id = df_dut_id + test_cfg[df_dut]['port_channels'][0]['member_ids'][0]
        ndf_int_id = ndf_dut_id + test_cfg[ndf_dut]['port_channels'][0]['member_ids'][0]

        st.banner('Testcase : Verify DF election with DF switchover ({})'.format(tc_id))
        st.log('Changing DF prority on DF node : {}'.format(df_dut))
        st.config(df_dut, 'interface {} \nevpn mh es-df-pref {}\n\
                  end\nexit\n'.format(tc_cfg['interface'], tc_cfg['ndf_pref']), type='vtysh')

        st.log('Changing DF prority on NDF node : {}'.format(ndf_dut))
        st.config(ndf_dut, 'interface {} \nevpn mh es-df-pref {}\n\
                  end\nexit\n'.format(tc_cfg['interface'], tc_cfg['df_pref']), type='vtysh')
        tc_cfg['uncfg'] = True

        st.log('Verify DF state on {}'.format(df_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(df_dut)
            for es_data in exp_data:
                if es_data['es_if'] == tc_cfg['interface']:
                    es_data['type'] = 'LRN'
                    break
            vxlan_obj.verify_evpn_es(df_dut, exp_data)
            st.log('DF state verification on {} : Pass'.format(df_dut))
        except vxlan_obj.CompareFailed as err:
            log = 'DF state verification on {} : Fail'.format(df_dut)
            st.log(log)
            summ += '{}\n'.format(log)
            result = False

        df_exp_tx_pkts = 0
        ndf_exp_tx_pkts = test_cfg['global']['ndf_exp_tx_pkts']
        traffic_name = ':T1{}'.format(df_dut_id)
        for stream_cntr, stream_info in tgen_handles[traffic_type].items():
            if traffic_name in stream_info['stream_id']:
                for dst_port, handle in stream_info['dst_ports']:
                    if tc_cfg['interface'] in dst_port:
                        df_exp_tx_pkts += test_cfg['global']['bum']['pkts_per_burst']

        st.log('Clearing Interface counters on duts')
        st.show(df_dut, "sonic-clear counters",  skip_tmpl=True)
        st.show(ndf_dut, "sonic-clear counters",  skip_tmpl=True)

        st.log('Verify BUM traffic takes local bias to reach multi-homed host')

        if pf.verify_traffic(tgen_handles, bum=True, traffic_types=[traffic_type], traffic_names=[traffic_name],):
            st.banner('BUM Traffic Check Passed')
        else:
            log = 'BUM Traffic Check Failed'
            st.log(log)
            summ += '{}\n'.format(log)
            result = False

        # getting multi-homed member link on dut
        df_dut_int_cntrs = intf_obj.show_interfaces_counters(dut=df_dut, 
                                                            interface=[vars[df_int_id]])
        ndf_dut_int_cntrs = intf_obj.show_interfaces_counters(dut=ndf_dut, 
                                                            interface=[vars[ndf_int_id]])
            
        st.log('Tx counter on DF dut {} interface {} : {}'.format(df_dut, vars[df_int_id],
                                                        df_dut_int_cntrs[0]['tx_ok']))
        df_tx = int(df_dut_int_cntrs[0]['tx_ok'].replace(',', ''))
        if df_tx > df_exp_tx_pkts:
            st.log('Tx counter {} > {} on local bias node {}: Pass'.format(df_tx, df_exp_tx_pkts, df_dut))
        else:
            msg = 'Tx counter {} < {} on local bias node {}: Fail\n'.format(df_tx, df_exp_tx_pkts, df_dut)
            st.log(msg)
            summ += msg
            result = False

        st.log('Tx counter on NDF dut {} interface {} : {}'.format(ndf_dut, vars[ndf_int_id],
                                                        ndf_dut_int_cntrs[0]['tx_ok']))
        ndf_tx = int(ndf_dut_int_cntrs[0]['tx_ok'].replace(',', ''))
        if ndf_tx < ndf_exp_tx_pkts:
            st.log('Tx counter {} < {} on non local bias node {} : Pass'.format(ndf_tx, ndf_exp_tx_pkts, ndf_dut))
        else:
            msg = 'Tx counter {} > {} on non local bias node {} : Fail\n'.format(ndf_tx, ndf_exp_tx_pkts, ndf_dut)
            st.log(msg)
            summ += msg
            result = False

        vxlan_obj.report_result(result, tc_id, summ)


    def _verify_mh_int_down(self, tc_id, tc_cfg, df_dut, ndf_dut, interface , shut_oper):

        result = True
        traffic_type = 'bum_SH'
        df_dut_id = vxlan_obj.get_device_id(df_dut,vars)
        ndf_dut_id = vxlan_obj.get_device_id(ndf_dut,vars)

        st.log('Verify EVPN ES peering state on {}'.format(df_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(df_dut)
            for es_data in exp_data:
                if es_data['es_if'] == interface:
                    es_data['type'] = 'LR'
                    break
            vxlan_obj.verify_evpn_es(df_dut, exp_data)
            st.log('EVPN ES peering state verifcation : Pass')
        except vxlan_obj.CompareFailed as err:
            st.log('EVPN ES peering state verifcation : Fail')
            return False

        st.log('Verify EVPN ES peering state on {}'.format(ndf_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(ndf_dut)
            for es_data in exp_data:
                if es_data['es_if'] == interface:
                    es_data['type'] = 'LRN'
                    break
            vxlan_obj.verify_evpn_es(ndf_dut, exp_data)
            st.log('EVPN ES peering state verifcation : Pass')
        except vxlan_obj.CompareFailed as err:
            st.log('EVPN ES peering state verifcation : Fail')
            return False
        
        df_int_id = df_dut_id + test_cfg[df_dut]['port_channels'][0]['member_ids'][0]
        ndf_int_id = ndf_dut_id + test_cfg[ndf_dut]['port_channels'][0]['member_ids'][0]
        tc_cfg['uncfg'] = shut_oper
        if shut_oper == 'local':
            # shutting vport on tgen-df 
            for int_id, handles in tgen_handles['topo_handles'][df_dut].items():
                if interface in int_id:
                    for vport,port_id in zip(handles['vport_handles'], handles['vport_port_ids']):
                        if df_dut_id in port_id:
                            tc_cfg['port_handle'] = tgapi.get_handle_byname(port_id)[1]
                            tc_cfg['tg_handle'] = handles['tg_handle']
                            tc_cfg['tg_handle'].tg_interface_config(mode='modify', 
                                                                    port_handle=tc_cfg['port_handle'], 
                                                                    op_mode='sim_disconnect')
                            break
        elif shut_oper == 'remote':
            st.log('Sutting down member link {} on DF dut {}'.format(vars[df_int_id], df_dut))
            intf_obj.interface_shutdown(dut=df_dut, interfaces=vars[df_int_id])
            tc_cfg['dut'] = df_dut
            tc_cfg['interface'] = vars[df_int_id]

        st.log('Verify that {} is the new DF'.format(ndf_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(ndf_dut)
            for es_data in exp_data:
                if es_data['es_if'] == interface:
                    es_data['type'] = 'L'
                    es_data['vteps'] = ''
                    break
            vxlan_obj.verify_evpn_es(ndf_dut, exp_data, vl_retries=2)
            st.log('EVPN ES peering state verifcation : Pass')
        except vxlan_obj.CompareFailed as err:
            st.log('EVPN ES peering state verifcation : Fail')
            return False
        
        st.log('Verify that interface {} on {} is forwarding traffic'.format(vars[ndf_int_id], ndf_dut))
        
        df_exp_tx_pkts = 0
        ndf_exp_tx_pkts = 0
        
        for stream_cntr, stream_info in tgen_handles[traffic_type].items():
            for dst_port, handle in stream_info['dst_ports']:
                if interface in dst_port:
                    df_exp_tx_pkts += test_cfg['global']['bum']['pkts_per_burst']

        st.log('Clearing Interface counters on duts')
        st.show(df_dut, "sonic-clear counters",  skip_tmpl=True)
        st.show(ndf_dut, "sonic-clear counters",  skip_tmpl=True)

        st.log('Verify traffic to multi-homed host')
        if pf.verify_traffic(tgen_handles, bum=True, traffic_types=[traffic_type]):
            st.banner('BUM Traffic Check Passed')
        else:
            st.banner('BUM Traffic Check Failed')
            result = False

        # getting multi-homed member link on dut
        df_dut_int_cntrs = intf_obj.show_interfaces_counters(dut=df_dut, 
                                                            interface=[vars[df_int_id]])
        ndf_dut_int_cntrs = intf_obj.show_interfaces_counters(dut=ndf_dut, 
                                                            interface=[vars[ndf_int_id]])
            
        st.log('Tx counter on DF dut {} interface {} : {}'.format(df_dut, vars[df_int_id],
                                                        df_dut_int_cntrs[0]['tx_ok']))
        df_tx = int(df_dut_int_cntrs[0]['tx_ok'].replace(',', ''))
        if df_tx <= ndf_exp_tx_pkts:
            st.log('Tx counter {} <= {} on DF node: Pass'.format(df_tx, ndf_exp_tx_pkts))
        else:
            st.log('Tx counter {} > {} on DF node: Fail'.format(df_tx, ndf_exp_tx_pkts))
            result = False

        st.log('Tx counter on NDF dut {} interface {} : {}'.format(ndf_dut, vars[ndf_int_id],
                                                        ndf_dut_int_cntrs[0]['tx_ok']))
        ndf_tx = int(ndf_dut_int_cntrs[0]['tx_ok'].replace(',', ''))
        if ndf_tx > df_exp_tx_pkts:
            st.log('Tx counter {} > {} on NDF node: Pass'.format(ndf_tx, df_exp_tx_pkts))
        else:
            st.log('Tx counter {} < {} on NDF node: Fail'.format(ndf_tx, df_exp_tx_pkts))
            result = False

        if shut_oper == 'local':
            # unshutting vport on tgen-df 
            tc_cfg['tg_handle'].tg_interface_config(mode='modify', 
                                                    port_handle=tc_cfg['port_handle'], 
                                                    op_mode='normal')
        elif shut_oper == 'remote':
            st.log('Un-Sutting down member link {} on DF dut {}'.format(vars[df_int_id], df_dut))
            intf_obj.interface_noshutdown(dut=df_dut, interfaces=vars[df_int_id])

        tc_cfg['uncfg'] = None
        st.log('Verify EVPN ES peering state on {} after unshut of interface'.format(df_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(df_dut)
            vxlan_obj.verify_evpn_es(df_dut, exp_data, vl_retries=test_cfg['global']['bum_triggers_retries'])
            st.log('EVPN ES peering state verifcation : Pass')
        except vxlan_obj.CompareFailed as err:
            st.log('EVPN ES peering state verifcation : Fail')
            result = False

        st.log('Verify EVPN ES peering state on {} after unshut of interface'.format(ndf_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(ndf_dut)
            vxlan_obj.verify_evpn_es(ndf_dut, exp_data, vl_retries=test_cfg['global']['bum_triggers_retries'])
            st.log('EVPN ES peering state verifcation : Pass')
        except vxlan_obj.CompareFailed as err:
            st.log('EVPN ES peering state verifcation : Fail')
            result = False        

        return result

    @pytest.fixture
    def cleanup_mh_int_down(self):
        """
        DUT and Tgen clean up for testcase 'test_vtep_add_new_ES'
        """

        yield
        tc_cfg = vxlan_obj.get_tc_params('test_mh_bum_triggers')
        if tc_cfg['uncfg'] == 'local':
            tc_cfg['tg_handle'].tg_interface_config(mode='modify', 
                                                    port_handle=tc_cfg['port_handle'], 
                                                    op_mode='normal')        
        elif tc_cfg['uncfg'] == 'remote':
            st.log('Un-Sutting down member link {} on DF dut'.format(tc_cfg['interface'], tc_cfg['dut']))
            intf_obj.interface_noshutdown(dut=tc_cfg['dut'], interfaces=tc_cfg['interface'])

    @pytest.fixture
    def cleanup_local_bias(self):
        """
        DUT DF preference unconfig
        """

        yield

        tc_id = test_cfg['tc_id']
        tc_cfg = vxlan_obj.get_tc_params('test_mh_bum_triggers')
        if tc_cfg['uncfg']:
            df_dut = tc_cfg['df_dut']
            ndf_dut = tc_cfg['ndf_dut']
            st.log('Removing DF prority on DF node : {}'.format(df_dut))
            st.config(df_dut, 'interface {} \nno evpn mh es-df-pref {}\n\
                    end\nexit\n'.format(tc_cfg['interface'], tc_cfg['ndf_pref']), type='vtysh')

            st.log('Removing DF prority on NDF node : {}'.format(ndf_dut))
            st.config(ndf_dut, 'interface {} \nno evpn mh es-df-pref {}\n\
                    end\nexit\n'.format(tc_cfg['interface'], tc_cfg['df_pref']), type='vtysh')

@pytest.mark.usefixtures("tgen_health_check_class")
class TestVxlanBasicTriggers():
    
    def test_clear_fdb(self):
        st.banner("TEST Trigger Clear FDB: Verify L2/L3 Traffic after clear fdb on all leafs") 
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        for node in leaf_nodes:
            st.banner("Clearing fdb in {}".format(node))
            #check for remote mac count on all leafs
            action = mac_obj.clear_mac(node)
            if action:
                st.log("fdb clear successful")
            else:
                st.log("fdb clear failed, skipping traffic test")
                vxlan_obj.report_result(result = False)
        st.wait(10)
        #check for remote mac count on all leafs
        traffic_result = pf.verify_traffic(tgen_handles, bum=True)
        vxlan_obj.get_cli_out(leaf_nodes)
        vxlan_obj.report_result(traffic_result)

    def test_del_local_mac(self):
        st.banner("TEST Trigger delete local MAC: Verify on deleting locally learnt MAC on leaf0, MAC entry is deleted in remote VTEP")
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        # ref_mac_list = mac_obj.get_mac_address_list('leaf0',type = 'Static')
        out = st.show('leaf0', "show mac -l", skip_tmpl=False)
        #Select only dynamic entries
        ref_mac_list=[]
        for item in out:
            if item['type'] != 'Static' and item['type'] != '':
                ref_mac_list.append(item['macaddress'])
        st.log(ref_mac_list)
        ##Clear fdb on leaf0
        mac_obj.clear_mac('leaf0')
        out = st.show('leaf0', "show mac -l", skip_tmpl=False)
        st.log(out)
        flag = False
        
        for dut in st.get_dut_names():
            if "leaf" in dut and "leaf0" not in dut:
                cli_output = st.show(dut, "show vxlan remotemac all", skip_tmpl=True)
                parsed_output = st.parse_show(dut, "show vxlan remotemac all",cli_output, "show_vxlan_remotemac_all.tmpl") 
                
                remote_mac_list = []
                st.log("{} : {}".format(dut, remote_mac_list))
                for item in parsed_output:
                    remote_mac_list.append(item['remote_mac'])
                out_list = []
                for mac in ref_mac_list:
                    if mac in remote_mac_list:
                        st.log("Found mac which is not expected",mac)
                        out_list.append(mac)
                st.banner(out_list)
                st.log(out_list)
                if len(out_list) == 0:
                    flag = True
                    st.log('mac successfully removed on {}'.format(dut))
                else:
                    flag = False
                    st.banner('mac not removed on {}'.format(dut))
        if flag:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_remove_add_vrf(self):

        st.banner("TEST Trigger remove add VRF: Verify. Remove and add back VRF ")
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_dict = {}
        #Gather facts
        cli_output = st.show('leaf0', "show vrf", skip_tmpl=True)
        parsed_output = st.parse_show('leaf0', "show vrf",cli_output, "show_vrf.tmpl")
        ref_vrf = parsed_output[0]['vrfname']
        temp_list = []
        for item in parsed_output:
            if item['vrfname'] == ref_vrf:
                for interface in item['interfaces']:
                    if not ref_vrf.split("Vrf")[1] in interface:
                        temp_list.append(interface)
        ref_vlan= int(sorted(temp_list)[0].split("Vlan")[1])
        st.banner("selected vrf is {}".format(ref_vrf))
        
        start_vlan = int(ref_vrf.split("Vrf")[1])
        for node in leaf_nodes:
            cli_output = st.show(node, "show vrf", skip_tmpl=True)
            parsed_output = st.parse_show(node, "show vrf",cli_output, "show_vrf.tmpl")
            for item in parsed_output:
                if item['vrfname'] == ref_vrf:
                    selected_leaf_dict[node]={}
                    selected_leaf_dict[node]['interfaces']=item['interfaces']
        #Del VRF
        flag = True
        for node in selected_leaf_dict:
            out = vxlan_obj.delete_vrf(node, ref_vrf)
            # verify_vrf(dut1,vrfname="Vrf-103")
            if not out:
                flag = False
            ##--> CHeck for core
        if flag:
            st.log("VRF deletion Success")
            st.wait(10)
            #Add back vrf
            #sonic configs
            for node in selected_leaf_dict:
                cfg_dict = {}
                cfg_dict['l2vni'] = ['dummy']
                for key, value in test_cfg.items():
                    if key == node:
                        cfg_dict['l3vni'] = [item for item in value['l3vni'] if item['vrf_id'] == start_vlan]
                        for item in cfg_dict['l3vni']:
                            if item['vrf_id'] == start_vlan:
                                vlan_list = item['vlan_bindings'] 
                cmd_out = vxlan_obj.generate_l3vni_config(cfg_dict)
                vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)     
                #sag_config
                v4_sag_dict = vxlan_obj.generate_svi_ip_sag(test_cfg[node],'ipv4')
                v6_sag_dict = vxlan_obj.generate_svi_ip_sag(test_cfg[node],'ipv6')

                if v4_sag_dict != None:
                    new_dict = {}
                    for vlan ,value in v4_sag_dict.items():
                        if vlan in vlan_list:
                            new_dict[vlan] = value
                    config_out = vxlan_obj.generate_sag_config(new_dict,'ipv4')
                    vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
                if v6_sag_dict != None:
                    new_dict = {}
                    for vlan ,value in v6_sag_dict.items():
                        if vlan in vlan_list:
                            new_dict[vlan] = value
                    config_out = vxlan_obj.generate_sag_config(new_dict,'ipv6')
                    vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
                
            #vtysh configs
            for node in selected_leaf_dict:
                config_out = vxlan_obj.bgp_vrf_config(node, ref_vrf)
                vxlan_obj.config_dut(node, 'bgp', config_out)
        else:
            st.banner("VRF deletion Failed")
            st.report_fail("test_case_failed")
        traffic_result = pf.verify_traffic(tgen_handles, bum=True)
        vxlan_obj.report_result(traffic_result)


    def test_bgp_clear(self):
        st.banner("TEST Trigger clear BGP: Verify L2/L3 Traffic after clear bgp on all leafs")
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        for node in leaf_nodes:
            cmd = "do clear bgp *"
            vxlan_obj.config_dut(node, 'bgp', cmd, add=True)
        # st.wait(5)
        ##--> check MH cli verication
        vxlan_obj.clear_counters(leaf_nodes)
        traffic_result = pf.verify_traffic(tgen_handles, bum=True)
        vxlan_obj.show_counters(leaf_nodes)
        vxlan_obj.report_result(traffic_result)

###DHCP RELAY TESTS###

@pytest.fixture(scope ="class")
def dhcp_relay_preconfig():
    vxlan_obj.dhcp_relay_config(add = True, src_loopback = False, dhcp_helper = False)
    vxlan_obj.dhcp_relay_config(add = True, src_loopback = True, dhcp_helper = True)
    yield 
    vxlan_obj.dhcp_relay_config(add = False, src_loopback = True, dhcp_helper = True)
    vxlan_obj.dhcp_relay_config(add = False, src_loopback = False, dhcp_helper = False)

@pytest.fixture(scope ="class")
def dhcp_tgen_config():
    global handle
    from spytest.tgen.tg import get_ixiangpf as ixia_handle
    handle = ixia_handle()
    topo_handles = tgen_handles["topo_handles"]

    ###Server config###
    my_handles = {}
    my_handles['handle'] = handle
    dhcp_server_handles = {}
    server_info = {}
    server_info['l3'] = {}
    server_info['l2'] = {}
    server_info['l3']["orphan"] = {}
    server_info['l3']["mh"] = {}
    server_info['l3'] ['native'] = {}
    server_info['l3'] ['routed'] = {}
    server_info['l2']["orphan"] = {}
    server_info['l2']["mh"] = {}
    server_info['l2'] ['native'] = {}
    ##L3vni
    
    server_info['l3']["orphan"]["Vrf101"] = {"ipaddress_pool":["80.2.0.200", "80.3.0.200"],"local_mac" : "00:00:00:20:90:10","ip_address":"80.20.0.88","ip_gateway":"80.20.0.1","vlan_id":"20"}
    server_info['l3']["orphan"]["Vrf102"] = {"ipaddress_pool":["80.5.0.200"],"local_mac" : "00:00:00:04:90:10","ip_address":"80.4.0.88","ip_gateway":"80.4.0.1","vlan_id":"4"}
    server_info['l3']["orphan"]["Vrf103"] = {"ipaddress_pool":["80.6.0.200"],"local_mac" : "00:00:00:07:90:10","ip_address":"80.7.0.88","ip_gateway":"80.7.0.1","vlan_id":"7"}
    server_info['l3'] ['native']["Vrf101"]= {"ipaddress_pool":["80.2.0.100", "80.3.0.100"],"local_mac" : "00:00:00:75:91:10","ip_address":"80.75.0.88","ip_gateway":"80.75.0.1"}
    server_info['l3'] ['routed']["Vrf101"]= {"ipaddress_pool":["80.2.0.100", "80.3.0.100"],"local_mac" : "00:00:00:76:91:10","ip_address":"80.75.0.88","ip_gateway":"80.75.0.1"}
    server_info['l3']["mh"]["Vrf101"] = {"ipaddress_pool":["80.2.0.150", "80.3.0.150"],"local_mac" : "00:00:00:30:90:11","ip_address":"80.30.0.89","ip_gateway":"80.30.0.1","vlan_id":"30"}
    server_info['l3']["mh"]["Vrf102"] = {"ipaddress_pool":["80.5.0.150"],"local_mac" : "00:00:00:04:90:11","ip_address":"80.4.0.89","ip_gateway":"80.4.0.1","vlan_id":"4"}
    server_info['l3']["mh"]["Vrf103"] = {"ipaddress_pool":["80.6.0.150"],"local_mac" : "00:00:00:07:90:11","ip_address":"80.7.0.89","ip_gateway":"80.7.0.1","vlan_id":"7"}
    ##L2vni
    server_info['l2']["orphan"]["Vrf101"] = {"ipaddress_pool":["80.2.0.200"],"local_mac" : "00:00:00:20:91:10","ip_address":"80.2.0.88","ip_gateway":"80.2.0.1","vlan_id":"2"}
    server_info['l2']["orphan"]["Vrf102"] = {"ipaddress_pool":["80.4.0.200"],"local_mac" : "00:00:00:04:91:10","ip_address":"80.4.0.88","ip_gateway":"80.4.0.1","vlan_id":"4"}
    server_info['l2']["orphan"]["Vrf103"] = {"ipaddress_pool":["80.7.0.200"],"local_mac" : "00:00:00:07:91:10","ip_address":"80.7.0.88","ip_gateway":"80.7.0.1","vlan_id":"7"}
    server_info['l2'] ['native']["Vrf101"]= {"ipaddress_pool":["80.75.0.100"],"local_mac" : "00:00:00:75:92:10","ip_address":"80.75.0.88","ip_gateway":"80.75.0.1"}
    server_info['l2']["mh"]["Vrf101"] = {"ipaddress_pool":["80.2.0.150"],"local_mac" : "00:00:00:02:91:11","ip_address":"80.2.0.89","ip_gateway":"80.2.0.1","vlan_id":"2"}
    server_info['l2']["mh"]["Vrf102"] = {"ipaddress_pool":["80.4.0.150"],"local_mac" : "00:00:00:04:91:11","ip_address":"80.4.0.89","ip_gateway":"80.4.0.1","vlan_id":"4"}
    server_info['l2']["mh"]["Vrf103"] = {"ipaddress_pool":["80.7.0.150",],"local_mac" : "00:00:00:07:91:11","ip_address":"80.7.0.89","ip_gateway":"80.7.0.1","vlan_id":"7"}

    my_handles['server_info'] = server_info
    for key, value in topo_handles['leaf0'].items():
        if "P1" in key:
            orphan_port_handle = value['topology_handle']
        if "P3" in key:
            routed_port_handle = value['topology_handle']
        if 'PortChannel' in key:
            mh_port_handle = value['topology_handle']
    for vni_type in server_info:
        dhcp_server_handles[vni_type] = {}
        for key, value in server_info[vni_type].items():
            if key in ["orphan","native"]:
                topo_handle = orphan_port_handle
            elif key == 'routed':
                topo_handle = routed_port_handle
            else:
                topo_handle = mh_port_handle
            dhcp_server_handles[vni_type][key] = {}
            for vrf, values in value.items():
                if vrf == "Vrf101":
                    count = 2
                else:
                    count = 1
                dhcp_server_handles[vni_type][key][vrf] = {}
                if server_info[vni_type][key][vrf].get('vlan_id'):
                    dhcp_server_orp = handle.emulation_dhcp_server_config(mode='create', 
                                                                        ipaddress_count='50',
                                                                        ipaddress_pool=server_info[vni_type][key][vrf]['ipaddress_pool'],  
                                                                        handle=topo_handle, 
                                                                        count='1', 
                                                                        local_mac=server_info[vni_type][key][vrf]['local_mac'], 
                                                                        ip_address=server_info[vni_type][key][vrf]['ip_address'],
                                                                        ip_gateway=server_info[vni_type][key][vrf]['ip_gateway'], 
                                                                        pool_count=count,
                                                                        subnet_addr_assign=1, 
                                                                        subnet='link_selection', 
                                                                        ip_version='4', 
                                                                        vlan_id =server_info[vni_type][key][vrf]['vlan_id'],
                                                                        protocol_name = "servervlan_{}_{}".format(server_info[vni_type][key][vrf]['vlan_id'],vni_type) )
                    
                else:
                    dhcp_server_orp = handle.emulation_dhcp_server_config(mode='create', 
                                                                        ipaddress_count='50',
                                                                        ipaddress_pool=server_info[vni_type][key][vrf]['ipaddress_pool'],  
                                                                        handle=topo_handle, 
                                                                        count='1', 
                                                                        local_mac=server_info[vni_type][key][vrf]['local_mac'], 
                                                                        ip_address=server_info[vni_type][key][vrf]['ip_address'],
                                                                        ip_gateway=server_info[vni_type][key][vrf]['ip_gateway'], 
                                                                        pool_count=count,
                                                                        subnet_addr_assign=1, 
                                                                        subnet='link_selection', 
                                                                        ip_version='4',
                                                                        protocol_name = "servervlan_native") 
                st.wait(1)
                    
                dhcp_server_handles[vni_type][key][vrf]['server_handle'] = dhcp_server_orp['dhcpv4server_handle']

    my_handles['server'] = dhcp_server_handles
    
    ###Client config
    dhcp_client_handles = {}
    dhcp_client_handles['l3'] = {}
    dhcp_client_handles['l2'] = {}

    dhcp_client_handles['l3']["L1_orphan"] = {}
    dhcp_client_handles['l3']["L2_orphan"] = {}
    dhcp_client_handles['l3']["mh2"] = {}
    dhcp_client_handles['l3']["L3_orphan"] = {}

    dhcp_client_handles['l2']["L1_orphan"] = {}
    dhcp_client_handles['l2']["L2_orphan"] = {}
    dhcp_client_handles['l2']["mh2"] = {}
    # dhcp_client_handles['l2']["mh1"] = {}
    dhcp_client_handles['l2']["L3_orphan"] = {}
    #client port handles
    # for key, value in topo_handles['leaf0'].items():
    #     if 'PortChannel' in key:
    #         dhcp_client_handles['l2']["mh1"]['port_handle'] = value['port_handle']
    #         dhcp_client_handles['l2']["mh1"]['topology_handle'] = value['topology_handle']
    for key, value in topo_handles['leaf1'].items():
        if "P1" in key:
            dhcp_client_handles['l3']["L1_orphan"]['port_handle'] = dhcp_client_handles['l2']["L1_orphan"]['port_handle'] = value['port_handle']
            dhcp_client_handles['l3']["L1_orphan"]['topology_handle'] = dhcp_client_handles['l2']["L1_orphan"]['topology_handle'] = value['topology_handle']
    for key, value in topo_handles['leaf2'].items():
        if "P1" in key:
            dhcp_client_handles['l3']["L2_orphan"]['port_handle'] = dhcp_client_handles['l2']["L2_orphan"]['port_handle'] = value['port_handle']
            dhcp_client_handles['l3']["L2_orphan"]['topology_handle'] = dhcp_client_handles['l2']["L2_orphan"]['topology_handle'] = value['topology_handle']
        if 'PortChannel' in key:
            dhcp_client_handles['l3']["mh2"]['port_handle'] = dhcp_client_handles['l2']["mh2"]['port_handle'] = value['port_handle']
            dhcp_client_handles['l3']["mh2"]['topology_handle'] = dhcp_client_handles['l2']["mh2"]['topology_handle'] = value['topology_handle']
    for key, value in topo_handles['leaf3'].items():
        if "P1" in key:
            dhcp_client_handles['l3']["L3_orphan"]['port_handle'] = dhcp_client_handles['l2']["L3_orphan"]['port_handle'] = value['port_handle']
            dhcp_client_handles['l3']["L3_orphan"]['topology_handle'] = dhcp_client_handles['l2']["L3_orphan"]['topology_handle'] = value['topology_handle']

    input_dict = {"l3" : {"Vrf101": [2,3], "Vrf102": [5], "Vrf103": [6]},"l2" : {"Vrf101": [2], "Vrf102": [4], "Vrf103": [7]} }

    out = vxlan_obj.get_vlan_info(test_cfg)
    vlan_dict = {}
    vlan_dict['L1_orphan'] = out['leaf1']['orphan_vlan_list']
    # vlan_dict['mh1'] = out['leaf0']['po_vlan_list']
    vlan_dict['L2_orphan'] = out['leaf2']['orphan_vlan_list']
    vlan_dict['mh2'] = out['leaf2']['po_vlan_list']
    vlan_dict['L3_orphan'] = out['leaf3']['orphan_vlan_list']

    mac_addr = "00:00:00:99:99:01"
    for vni_type in dhcp_client_handles:
    
        for port, values in dhcp_client_handles[vni_type].items():
            for key, value in input_dict[vni_type].items():
                for vlan in value:
                    if vlan in vlan_dict[port]:
                        dhcp_client_handles[vni_type][port][vlan] = {}
                        new_mac = vxlan_obj.increment_mac_address(mac_addr,increment_value = 5)
                        client_config = handle.emulation_dhcp_group_config(handle=values['topology_handle'],
                                                                            mac_addr = mac_addr, 
                                                                            mac_addr_step = "00:00:00:00:00:01", 
                                                                            num_sessions = "5", vlan_id =vlan, 
                                                                            vlan_id_count = "1", 
                                                                            dhcp_range_ip_type ='ipv4',
                                                                            dhcp_range_renew_timer ="10",
                                                                            protocol_name = port+"_dhcpv4client_"+str(vlan)+"_"+vni_type, 
                                                                            mode="create", mac_mtu ="1500", 
                                                                            vlan_id_step = "0", 
                                                                            encap = "ethernet_ii_vlan")
                                
                        dhcp_client_handles[vni_type][port][vlan]['client_handle'] = client_config['dhcpv4client_handle']
                        mac_addr = vxlan_obj.increment_mac_address(mac_addr,increment_value = 5)
            mac_addr = vxlan_obj.increment_mac_address(mac_addr,increment_value = 5)
        mac_addr = "00:00:00:98:99:01"
    my_handles['client'] = dhcp_client_handles
    handle.test_control(action="apply_on_the_fly_changes")
    yield my_handles 

@pytest.mark.usefixtures('tgen_health_check_class', "dhcp_relay_preconfig","dhcp_tgen_config")
class TestVxlanDhcpRelay():

    @pytest.fixture(autouse=True)
    def init_fixtures(self, request):
        self.dhcp_handles = request.getfixturevalue('dhcp_tgen_config')

    def verify_dhcp_stats(self, stats = "", vlan = "2", port_type = [], vni_type = 'l3'):
        if stats == "":
            st.banner("No stats found")
            return
        result = True
        out = False
        address_pool = {}
        for port, value in self.dhcp_handles['server_info'][vni_type].items():
            address_pool[port] = {}
            for vrf, values in value.items():
                address_pool[port][vrf] = []
                for item in values['ipaddress_pool']:
                    address_pool[port][vrf].extend(vxlan_obj.generate_ip_list(item, num_ips = 20))

        ip_list, result_flag = vxlan_obj.get_client_ip_list(stats)

        if vlan in [2,3]:
            vrf = "Vrf101"
        elif vlan in [4,5]:
             vrf = "Vrf102"
        elif vlan in [6,7]:
             vrf = "Vrf103"
        if result_flag:
            if len(port_type) == 1:
                if port_type[0] == "orphan":
                    out = set(ip_list).issubset(address_pool['orphan'][vrf])
                elif port_type[0] == "mh":
                    out = set(ip_list).issubset(address_pool['mh'][vrf])
                elif port_type[0] == "native":
                    out = set(ip_list).issubset(address_pool['native'][vrf]) 
                elif port_type[0] == "routed":
                    out = set(ip_list).issubset(address_pool['routed'][vrf])     
            else:
                master_list = address_pool['orphan'][vrf] + address_pool['mh'][vrf]
                out = set(ip_list).issubset(master_list)
        else:
            result = False

        if not out:
            result = False

        #Add this debug log right before returning
        st.log("DHCP stats check: vlan={} port_type={} vrf={} expected_pool={} got_ip_list={}".format(
            vlan, port_type, vrf, address_pool.get(port_type[0], {}).get(vrf, []), ip_list))
        return result
    
    def verify_dhcp_bindings(self, server_port = [], vni_type = "l3", retries=3):
        attempt = 0
        while attempt < retries:
            attempt += 1
            server_handle = self.dhcp_handles['server'][vni_type]
            client_handle = self.dhcp_handles['client'][vni_type]
            # Start server 
            for port_type in server_port:
                for vrf , values in server_handle[port_type].items():
                    self.dhcp_handles['handle'].emulation_dhcp_server_control( action='collect', dhcp_handle=values['server_handle'])
            # Start all clients
            result_dict = {}
            dhcp_stats = ""
            for port, values in client_handle.items():
                result_dict[port] = {}
                for vlan , clients in values.items():
                    if server_port == ["native"] and vni_type == "l3":
                        if vlan in [4,5,6,7]:
                            continue
                    if server_port == ["routed"]:
                        if vlan in [4,5,6,7]:
                            continue
                    if vlan not in ['port_handle','topology_handle']:
                        result_dict[port][vlan] = {}
                        self.dhcp_handles['handle'].emulation_dhcp_control(action="bind", handle=clients['client_handle'])
                        st.wait(10)
                        dhcp_stats = self.dhcp_handles['handle'].emulation_dhcp_stats(handle=clients['client_handle'], mode='session')
                        st.log("Starting clients on vlan {} behind port {}".format(vlan,port))
                        result_dict[port][vlan] = self.verify_dhcp_stats(dhcp_stats,vlan, port_type = server_port, vni_type = vni_type)
                        self.dhcp_handles['handle'].emulation_dhcp_control(action="release", handle=clients['client_handle'])

            # Stop server 
            for port_type in server_port:
                for vrf , values in server_handle[port_type].items():
                        self.dhcp_handles['handle'].emulation_dhcp_server_control(action='reset', dhcp_handle=values['server_handle'])

            result_flag = True
            for port, vlans in result_dict.items():
                for vlan, res in vlans.items():
                    if res:
                        st.banner("dhcp bind passed for clients behind {} and vlan {}".format(port, vlan))
                    else:
                        st.banner("dhcp bind Failed for clients behind {} and vlan {}".format(port, vlan))
                        result_flag = False

            if result_flag:
                return True
            else:
                st.log("Attempt {} failed, retrying in 10 secs...".format(attempt))
                st.wait(10)
                if attempt < retries:
                    st.wait(5)
        return False

    
    ###Triggers###
    
    def test_server_intf_flap(self):
        tc_id = "dhcp server interface flap"
        st.banner(tc_id)
        before_trigger = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        st.log("Before interface shutdown, DHCP bindings verified: {}".format(before_trigger))
        selected_dut = "leaf0"
        dut_interfaces = vxlan_obj.get_dut_interfaces(vars)
        uplink_interfaces = dut_interfaces[selected_dut]['underlay_dict']
        selected_port = list(uplink_interfaces.values())[0]
        st.log("Before intf shutdown")
        intf_obj.interface_shutdown(selected_dut, selected_port)
        st.wait(2)
        intf_obj.interface_noshutdown(selected_dut, selected_port)
        st.wait(4)
        st.log("After intf shutdown")
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    def test_rem_add_src_loopback(self):
        tc_id = "rem add dhcp src loopback"
        vxlan_obj.dhcp_relay_config(add = False, src_loopback = True, dhcp_helper = False)
        st.wait(5)
        vxlan_obj.dhcp_relay_config(add = True, src_loopback = True, dhcp_helper = False)
        st.wait(5)
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    def test_rem_add_helper_address(self):
        tc_id = "rem add dhcp helper address"
        vxlan_obj.dhcp_relay_config(add = False, src_loopback = False, dhcp_helper = True)
        st.wait(5)
        vxlan_obj.dhcp_relay_config(add = True, src_loopback = False, dhcp_helper = True)
        st.wait(30)
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)
    
    def test_restart_dhcp(self):
        """
        Restarts a system service (dhcp) on all duts and verifies docker recovery after trigger.
        Then performs sanity checks and traffic validation
        """
        tc_id = "test_restart_dhcp"
        dut_count_arr = {}
        for dut in test_cfg['nodes']['l2l3vni']:
            dut_count_arr[dut] = basic_obj.get_and_match_docker_count(dut)
            restart_complete = basic_obj.systemctl_restart_service(dut, "dhcp_relay")
                
        for dut in test_cfg['nodes']['l2l3vni']:
            # Check Docker Status
            result = True
            if not poll_wait(basic_obj.verify_docker_status, 180, dut, 'Exited'):
                st.error("Post 'systemctl restart dhcp on {}', dockers are not auto recovered.".format(dut))
                result = False
                vxlan_obj.report_result(result, tc_id, "Docker Status Failed")
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, dut, dut_count_arr[dut]):
                st.error("Post 'systemctl restart dhcp on {}', ALL dockers are not UP.".format(dut))
                result = False
                vxlan_obj.report_result(result, tc_id, "Docker Status Failed")
        # PreSanity
        result_presanity = pf.verify_base_setup(retry=3)
        if not result_presanity :
            vxlan_obj.report_result(result_presanity, tc_id, "Presanity Check Failed")
        #Check Traffic
        traffic_result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        #check for remote mac count on all leafs
        vxlan_obj.report_result(traffic_result, tc_id, "Traffic Failed")

    @pytest.mark.skip
    def test_reboot(self):
        ###restore spytest helper <<-- todo 
        tc_id = "Server behind both orphan and MH after reboot"
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut_list = ['leaf0', 'leaf2']
        for selected_dut in selected_dut_list:
            vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
            reboot_obj.dut_reboot(selected_dut)
            restore_helper_file(selected_dut)
        st.wait(360)
        
        #     #change hostname to sonic
        #     vxlan_obj.config_dut(selected_dut,"sonic", "sudo hostname sonic")
        #     #check docker status
        #     result = True
        #     if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
        #         st.error("Post 'config reload', dockers are not auto recovered.")
        #         result = False
        #     if result:
        #         if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
        #             st.error("Post 'config reload', ALL dockers are not UP.")
        #             st.report_fail("test_case_failed")
        
            #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail("test_case_failed")
        vxlan_obj.get_cli_out(leaf_nodes)
        
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    def test_config_reload(self):
        tc_id = "Server behind both orphan and MH after reload"
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut_list = ['leaf0', 'leaf2']
        #config save sonic and frr
        for selected_dut in selected_dut_list:
            reboot_obj.config_save(selected_dut)
            vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
            count = basic_obj.get_and_match_docker_count(selected_dut)
            status = reboot_obj.config_reload(selected_dut)
            if status:
                st.banner("config reload cmd success!")
            else:
                st.banner("config reload cmd failed!")
                st.report_fail("test_case_failed")
            #change hostname to sonic
            vxlan_obj.config_dut(selected_dut,"sonic", "sudo hostname sonic") 

            #check docker status
            result = True
            if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
                st.error("Post 'config reload', dockers are not auto recovered.")
                result = False
            if result:
                if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
                    st.error("Post 'config reload', ALL dockers are not UP.")
                    st.report_fail("test_case_failed")
        st.wait(180)
        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail("test_case_failed")

        vxlan_obj.get_cli_out(leaf_nodes)
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)  

    
    ###Server and client on diff vlans###
    def test_server_behind_orphan(self):
        tc_id = "Server behind orphan"
        result = self.verify_dhcp_bindings(server_port = ["orphan"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    def test_server_behind_mh(self):
        tc_id = "Server behind MH"
        result = self.verify_dhcp_bindings(server_port = ["mh"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    def test_server_behind_both(self):
        tc_id = "Server behind both orphan and MH"
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    ### Server behind routed interface###
    @pytest.fixture
    def add_routed_interface(self):
        ref_int = vars[vars.dut_ids['leaf0']+"T1P3"]
        vrf_id = "Vrf101"
        vrf_obj.bind_vrf_interface(dut = 'leaf0', vrf_name = vrf_id, intf_name =ref_int)
        ip_obj.config_ip_addr_interface('leaf0', interface_name=ref_int, ip_address="80.75.0.1", subnet='24', family="ipv4", config='add', skip_error=True)
        yield
        vrf_obj.bind_vrf_interface(dut = 'leaf0', vrf_name = vrf_id, intf_name =ref_int,config = 'no')

    def test_server_behind_routed_int(self, add_routed_interface):
        tc_id = "Server behind routed int"
        result = self.verify_dhcp_bindings(server_port = ["routed"], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    ### Server behind native vlan interface (vlan untagged)###
    @pytest.fixture
    def add_untag_interface(self):
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        ref_int = vars[vars.dut_ids['leaf0']+"T1P1"]
        cmd = "sudo config vxlan map add VXLAN 75 5075\n"
        cmd += "sudo config interface vrf bind Vlan75 Vrf101\n"
        cmd += "config interface ip add Vlan75 80.75.0.1/24\n"
        cmd += "sudo config vlan static-anycast-gateway enable 75\n"
        vlan_list = ['75']
        for node in leaf_nodes:
            if node == "leaf0":
                vlan_obj.create_vlan(node, vlan_list = '75')
                vlan_obj.add_vlan_member(node, "75", [ref_int], tagging_mode=False)
                st.config(node, cmd, skip_error_check=True)
        yield

        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        ref_int = vars[vars.dut_ids['leaf0']+"T1P1"]
        cmd = "sudo config vlan static-anycast-gateway disable 75\n"
        cmd += "sudo config interface vrf unbind Vlan75\n"
        cmd += "sudo config vxlan map del VXLAN 75 5075\n"
        
        for node in leaf_nodes:
            if node == "leaf0":
                st.config(node, cmd, skip_error_check=True)
                vlan_obj.delete_vlan_member(node, "75", [ref_int], tagging_mode=False)
                vlan_obj.delete_vlan(node, vlan_list = '75')
                
    def test_server_behind_native_vlan(self,add_untag_interface):
        tc_id = "Server behind native vlan"
        result = self.verify_dhcp_bindings(server_port = ['native'], vni_type = "l3")
        vxlan_obj.report_result(result, tc_id)

    ###server and client on same vlan###
    @pytest.fixture
    def setup_l2_test(self):
        
        vxlan_obj.dhcp_relay_config(add = False, src_loopback = True, dhcp_helper = True)
        vxlan_obj.dhcp_relay_config(add = False, src_loopback = False, dhcp_helper = False)
        st.wait(5)
        for dut in st.get_dut_names():
            if "leaf" in dut:
                st.config(dut,"sudo config feature autorestart dhcp_relay disabled\nsudo config feature state dhcp_relay disabled\n")
        yield
        for dut in st.get_dut_names():
            if "leaf" in dut:
                st.config(dut,"sudo config feature state dhcp_relay enabled\nconfig feature autorestart dhcp_relay enabled\n")
        st.wait(5)
        vxlan_obj.dhcp_relay_config(add = True, src_loopback = False, dhcp_helper = False)
        vxlan_obj.dhcp_relay_config(add = True, src_loopback = True, dhcp_helper = True)

    def test_server_behind_orphan_samevlan(self,setup_l2_test):
        tc_id = "Server behind orphan"
        result = self.verify_dhcp_bindings(server_port = ["orphan"], vni_type = "l2")
        vxlan_obj.report_result(result, tc_id)

    def test_server_behind_mh_samevlan(self,setup_l2_test):
        tc_id = "Server behind MH"
        result = self.verify_dhcp_bindings(server_port = ["mh"], vni_type = "l2")
        vxlan_obj.report_result(result, tc_id)

    def test_server_behind_both_samevlan(self,setup_l2_test):
        tc_id = "Server behind both orphan and MH"
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "l2")
        vxlan_obj.report_result(result, tc_id)

    @pytest.fixture
    def setup_config_for_static(self):
        ext_dut_id = vars.dut_ids['external_router']
        leaf3_dut_id = vars.dut_ids['leaf3']
        for node,dut_id in vars.dut_ids.items():
            if dut_id == ext_dut_id or dut_id == leaf3_dut_id :
                for key,value in vars.items():
                    if ext_dut_id+leaf3_dut_id in key:
                        ext_dut_int = value
                    if leaf3_dut_id+ext_dut_id in key:
                        leaf3_int = value
                    if ext_dut_id+"T1P1" in key:
                        ext_tgen_int = value
        ref_vrf = "Vrf101"
        vrf_obj.bind_vrf_interface(dut = 'leaf3', vrf_name = ref_vrf, intf_name =leaf3_int)
        ip_obj.config_ip_addr_interface('leaf3', interface_name=leaf3_int, ip_address="21.21.21.1", subnet='24', family="ipv4", config='add', skip_error=True)
        vrf_obj.config_vrf(dut = 'external_router', vrf_name = ref_vrf, config = 'yes')
        vrf_obj.bind_vrf_interface(dut = 'external_router', vrf_name = ref_vrf, intf_name =ext_dut_int)
        ip_obj.config_ip_addr_interface('external_router', interface_name=ext_dut_int, ip_address="21.21.21.2", subnet='24', family="ipv4", config='add', skip_error=True)
        vrf_obj.bind_vrf_interface(dut = 'external_router', vrf_name = ref_vrf, intf_name =ext_tgen_int)
        ip_obj.config_ip_addr_interface('external_router', interface_name=ext_tgen_int, ip_address="99.99.99.1", subnet='24', family="ipv4", config='add', skip_error=True)
        #add dhcp relay
        for node in st.get_dut_names():
            if 'leaf' in node:
                cmd = "config vlan dhcp_relay add 2 99.99.99.99\n"
                cmd += "sudo config route add prefix vrf Vrf101 99.99.99.99/32 nexthop 21.21.21.2\n"
                st.config(node, cmd, skip_error_check=True)

            if "external" in node:
                cmd = "vrf Vrf101\nip route 112.111.111.101/32 21.21.21.1\n"
                cmd += "ip route 111.111.111.101/32 21.21.21.1\nend\nexit\n"
                vxlan_obj.config_dut(node, 'bgp', cmd)
        yield
        #unconfig
        for node in st.get_dut_names():
            if 'leaf' in node:
                cmd = "config vlan dhcp_relay del 2 99.99.99.99\n"
                cmd += "sudo config route del prefix vrf Vrf101 99.99.99.99/32 nexthop 21.21.21.2\n"
                st.config(node, cmd, skip_error_check=True)
                
            if "external" in node:
                cmd = "vrf Vrf101\nno ip route 112.111.111.101/32 21.21.21.1\n"
                cmd += "no ip route 111.111.111.101/32 21.21.21.1\nend\nexit\n"
                vxlan_obj.config_dut(node, 'bgp', cmd)
        vrf_obj.bind_vrf_interface(dut = 'leaf3', vrf_name = ref_vrf, intf_name =leaf3_int, config = 'no')
        vrf_obj.config_vrf(dut = 'external_router', vrf_name = ref_vrf, config = 'no')
        

    def test_server_behind_static_route(self, setup_config_for_static):
        tc_id = "test_server_behind_static_route"
        topo_handles = tgen_handles["topo_handles"]
        for key, value in topo_handles['leaf0'].items():
            if 'PortChannel' in key:
                mh_port_handle = value['topology_handle']
        ext_port_handle = "T1"+vars.dut_ids['external_router']+"P1"
        tg_handle, port_handle = tgapi.get_handle_byname(ext_port_handle)
        device_port = tg_handle.tg_topology_config(
                                            topology_name = """ext tgen int""",
                                            port_handle = port_handle)
        ext_topology_handle = device_port['topology_handle']
        
        #server config
        dhcp_server_ext = handle.emulation_dhcp_server_config(mode='create', 
                                                            ipaddress_count='10',
                                                            ipaddress_pool=["80.2.0.240"],  
                                                            handle=ext_topology_handle, 
                                                            count='1', 
                                                            local_mac="00:00:00:02:99:10", 
                                                            ip_address="99.99.99.99",
                                                            ip_gateway="99.99.99.1", 
                                                            pool_count=1,
                                                            subnet_addr_assign=1, 
                                                            subnet='link_selection', 
                                                            ip_version='4', 
                                                            protocol_name = "server behind static")
        dhcp_server_handle = dhcp_server_ext['dhcpv4server_handle']

        #client config
        client_config = handle.emulation_dhcp_group_config(handle=mh_port_handle,
                                                            mac_addr = "00:00:99:02:99:10", 
                                                            mac_addr_step = "00:00:00:00:00:01", 
                                                            num_sessions = "5", vlan_id ='2', 
                                                            vlan_id_count = "1", 
                                                            dhcp_range_ip_type ='ipv4',
                                                            dhcp_range_renew_timer ="10",
                                                            protocol_name = "client_server_behind_static", 
                                                            mode="create", mac_mtu ="1500", 
                                                            vlan_id_step = "0", 
                                                            encap = "ethernet_ii_vlan")

        dhcp_client_handle = client_config['dhcpv4client_handle']
        handle.test_control(action="apply_on_the_fly_changes")
        #start server
        handle.emulation_dhcp_server_control(action='collect', dhcp_handle=dhcp_server_handle)
        st.wait(2)
        #start client
        handle.emulation_dhcp_control(action="bind", handle=dhcp_client_handle)
        st.wait(5)
        dhcp_stats = handle.emulation_dhcp_stats(handle=dhcp_client_handle, mode='session')
        #stop client
        handle.emulation_dhcp_control(action="release", handle=dhcp_client_handle)
        #stop server
        handle.emulation_dhcp_server_control(action='reset', dhcp_handle=dhcp_server_handle)
        #verify stats
        ip_list, result_flag = vxlan_obj.get_client_ip_list(dhcp_stats)
        address_pool = vxlan_obj.generate_ip_list("80.2.0.240", num_ips = 10)
        result = True
        out = False
        if result_flag:
            out = set(ip_list).issubset(address_pool)
        else:
            result = False
        if not out:
            result = False
        vxlan_obj.report_result(result, tc_id)



@pytest.fixture(scope="class")
def setup_mac_move_vlans():
    '''

    '''
    enable_or_disable_existing_streams(mode='disable')

    ###Add new ES###

    es_duts = ['leaf0','leaf1']
    for node in es_duts:
        # member_port = vars[vars.dut_ids[node]+"T1P3"]
        pc_obj.create_portchannel(node, "PortChannel20")
        pc_obj.add_portchannel_member(node,portchannel="PortChannel20", members=[vars[vars.dut_ids[node]+"T1P3"]] )
        cmd_1 = "sudo config interface sys-mac add PortChannel20 00:44:33:22:99:99\n"
        cmd_1 += "sudo config interface evpn-esi add PortChannel20 auto-system-mac\n"
        vxlan_obj.config_dut(node, 'sonic', cmd_1, add=True)

    ### ADD DUT CONFIGS ###
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    
    int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
    dut_int_data = vxlan_obj.get_dut_interfaces(vars)
    vrf_id = "Vrf101"
    # leaf_data = test_cfg['testcases']['mac_move_test']['leaf0']
    for node in leaf_nodes:
        #add l2vni
        leaf_data = test_cfg['testcases']['mac_move_test'][node]
        config_out = vxlan_obj.generate_l2vni_config(leaf_data,int_config_dict[node]['l2vni_int'],dut_int_data[node])
        vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
        #bindvrf and  add svi
        for vlan, info in leaf_data['host_info'].items():
            ref_int = "Vlan"+str(vlan)
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =ref_int)
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=info['v4_svi'], subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=info['v6_svi'], subnet='64', family="ipv6", config='add', skip_error=True)
            cmd = "sudo config vlan static-anycast-gateway enable {}\n".format(vlan)
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
    for node in leaf_nodes:
        st.show(node,"show evpn es", skip_tmpl=True)
        st.show(node,"show vxlan l2nexthopgroup", skip_tmpl=True)
    
    yield
    enable_or_disable_existing_streams(mode='enable')
    ###CLEANUP DUT CONFIGS###

    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
    dut_int_data = vxlan_obj.get_dut_interfaces(vars)
    #unbind vlan from vrf
    for node in leaf_nodes:
        leaf_data = test_cfg['testcases']['mac_move_test'][node]
        for vlan, info in leaf_data['host_info'].items():
            cmd = "sudo config vlan static-anycast-gateway disable {}\n".format(vlan)
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            ref_int = "Vlan"+str(vlan)
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =ref_int,config = 'no')
        ##remove l2vni
        config_out = vxlan_obj.generate_l2vni_config(leaf_data,int_config_dict[node]['l2vni_int'],dut_int_data[node], mode='del')
        vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
    es_duts = ['leaf0','leaf1']
    for node in es_duts:
        cmd_1 = "sudo config interface evpn-esi del PortChannel20\n"
        cmd_1 += "sudo config interface sys-mac remove PortChannel20 00:44:33:22:99:99\n"
        st.config(node, cmd_1, skip_error_check=True)
        pc_obj.delete_portchannel_member(node,portchannel="PortChannel20", members=[vars[vars.dut_ids[node]+"T1P3"]])
        pc_obj.delete_portchannel(node, "PortChannel20")
    

@pytest.fixture(scope="class")
def create_new_es_tgen_cfg():
    enable_or_disable_existing_streams(mode='disable')
    new_es_handles = {}
    topo_handles = tgen_handles["topo_handles"]
    leaf0_es_port = "T1"+vars.dut_ids['leaf0']+"P3"
    leaf1_es_port = "T1"+vars.dut_ids['leaf1']+"P3"
    #destroy existing topo handle
    topo_handles['leaf0'][leaf0_es_port]['tg_handle'].tg_topology_config(mode='destroy',topology_handle=topo_handles['leaf0'][leaf0_es_port]['topology_handle'])
    topo_handles['leaf1'][leaf1_es_port]['tg_handle'].tg_topology_config(mode='destroy',topology_handle=topo_handles['leaf1'][leaf1_es_port]['topology_handle'])
    ##Generate new ES topohandle
    new_es_handles['tg_handle'],  new_es_handles['result'] = vxlan_obj.create_lag_handle(lag_name = "ES2PO20", ports = [leaf0_es_port,leaf1_es_port])
    device_port = new_es_handles['tg_handle'].tg_topology_config(topology_name = "ES2",lag_handle =  new_es_handles['result']['lag_handle'])
    new_es_handles['topology_handle'] = device_port['topology_handle']
    new_es_handles['tg_handle'].tg_test_control(action="apply_on_the_fly_changes")
    vxlan_obj.start_stop_protocols(new_es_handles['tg_handle'],'stop')
    vxlan_obj.start_stop_protocols(new_es_handles['tg_handle'],'start')
    yield new_es_handles

@pytest.mark.usefixtures("tgen_health_check_class", "setup_mac_move_vlans","create_new_es_tgen_cfg")
class TestVxlanMacMoveTriggers():
    
    @pytest.fixture(autouse=True)
    def init_fixtures(self, request):
        self.new_es_handles = request.getfixturevalue('create_new_es_tgen_cfg')

    def verify_mac(self,mac_addr, ip_addr = ""):
        selected_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut or "spine3" in dut:
                selected_nodes.append(dut)
        cmd = "vtysh -c \"show bgp l2vpn evpn route type 2\" | grep  {} -A5".format(mac_addr)
        cmd1 = "show arp | grep {0} ; show nd | grep {0} ; show arp | grep {1} ; show nd | grep {1}".format(mac_addr,ip_addr)
        for dut in selected_nodes:
            output_1 = mac_obj.get_mac_entries_by_mac_address(dut,mac_addr)
            output_2 = st.config(dut, cmd, skip_error_check=True)
            if ip_addr != "":
                output_2 = st.config(dut, cmd1, skip_error_check=True)

    def _chk_stats(self, tg_handle, handles = [], exp_traffic_on = []):
        flag = True
        for item in handles:
            out = vxlan_obj.validate_stats(tg_handle,item)
            if item in exp_traffic_on:
                if not out:
                    flag = False
            else:
                if out:
                    flag = False
        return flag

    def send_traffic(self, tg_handle, traffic_item):
        tg_handle.tg_traffic_control(action='run', stream_handle= traffic_item)
        st.wait(5)
        tg_handle.tg_traffic_control(action='stop', stream_handle= traffic_item)
        st.wait(5)
    
    def cleanup_tgen(self,stream_handles):
        if stream_handles['mm_host'].get('src1'):
            #mac+ip_handles
            for key, value in stream_handles.items():
                if "src" in key:
                    stream_handles['tg_handle'].tg_traffic_config(mode = 'remove', stream_id = value)
            for key, value in stream_handles['mm_host'].items():
                if key in ['src','dest1_handle','dest2_handle']:
                    stream_handles['tg_handle'].tg_topology_config(device_group_handle =value, mode = 'destroy')  
        else:
            #mac_only_handles
            for key, value in stream_handles.items():
                if key not in ['mm_host','tg_handle']:
                    stream_handles['tg_handle'].tg_traffic_config(mode = 'remove', stream_id = value)

    def get_stream_handles(self,move_dir, host_type = "mac_only"):
        topo_handles = tgen_handles["topo_handles"]
        mm_handles = {}
        mm_handles['mh1_2'] = {}
        if move_dir == "mh1_to_mh1_2":
            new_es_handles = self.new_es_handles
            mm_handles['mh1_2']['port_handle'] = new_es_handles['result']['lag_handle']
            mm_handles['mh1_2']['tg_handle'] = new_es_handles['tg_handle']
            mm_handles['mh1_2']['topo_handle'] = new_es_handles['topology_handle']
        
        dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01
        for key, value in topo_handles['leaf2'].items():
            if "P1" in key:
                mm_handles['L2_orp'] = {}
                mm_handles['L2_orp']['port'] = key
                mm_handles['L2_orp']['port_handle'] = value['port_handle']
                mm_handles['L2_orp']['tg_handle'] = value['tg_handle']
                mm_handles['L2_orp']['topo_handle'] = value['topology_handle']

            if 'PortChannel' in key:
                mm_handles['mh2'] = {} 
                mm_handles['mh2']['port'] = key
                mm_handles['mh2']['port_handle'] = value['port_handle']
                mm_handles['mh2']['tg_handle'] = value['tg_handle']
                mm_handles['mh2']['topo_handle'] = value['topology_handle']

        for key, value in topo_handles['leaf0'].items():
            if 'PortChannel' in key:
                mm_handles['mh1'] = {} 
                mm_handles['mh1']['port'] = key
                mm_handles['mh1']['port_handle'] = value['port_handle']
                mm_handles['mh1']['tg_handle'] = value['tg_handle']
                mm_handles['mh1']['topo_handle'] = value['topology_handle']

        for key, value in topo_handles['leaf1'].items():
            if "P1" in key:
                mm_handles['L1_orp'] = {}
                mm_handles['L1_orp']['port'] = key
                mm_handles['L1_orp']['port_handle'] = value['port_handle']
                mm_handles['L1_orp']['tg_handle'] = value['tg_handle']
                mm_handles['L1_orp']['topo_handle'] = value['topology_handle']

        for key, value in topo_handles['leaf3'].items():
            if "P1" in key:
                mm_handles['L3_orp'] = {}
                mm_handles['L3_orp']['port'] = key
                mm_handles['L3_orp']['port_handle'] = value['port_handle']
                mm_handles['L3_orp']['tg_handle'] = value['tg_handle']
                mm_handles['L3_orp']['topo_handle'] = value['topology_handle']

        if test_cfg['spine3'] != None:
            if topo_handles.get('spine3'):
                for key, value in topo_handles['spine3'].items():
                    if "P1" in key:
                        mm_handles['S3_orp'] = {}
                        mm_handles['S3_orp']['port'] = key
                        mm_handles['S3_orp']['port_handle'] = value['port_handle']
                        mm_handles['S3_orp']['tg_handle'] = value['tg_handle']
                        mm_handles['S3_orp']['topo_handle'] = value['topology_handle']
        
        stream_info = {}
        stream_info['dest1'] = {}
        stream_info['src'] = {}
        stream_info['src1'] = {}
        stream_info['src2'] = {}
        stream_info['dest2'] = {}

        #l3 traffic
        stream_info['src3'] = {}
        stream_info['src4'] = {}
        
        if move_dir == "mh1_to_L1orp":
            #host initial behind mh1
            stream_info['dest1']['src_handle'] = mm_handles['mh1']['port_handle']
            stream_info['dest1']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest1']['tg_handle'] = mm_handles['mh1']['tg_handle']
            stream_info['dest1']['topo_handle'] = mm_handles['mh1']['topo_handle']
            #traffic src
            stream_info['src']['src_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['src']['dest_handle1'] = mm_handles['mh1']['port_handle']
            stream_info['src']['dest_handle2'] = mm_handles['L1_orp']['port_handle']
            stream_info['src']['tg_handle'] = mm_handles['L2_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['L2_orp']['topo_handle']
            #host moved to L1 orphan
            stream_info['dest2']['src_handle'] = mm_handles['L1_orp']['port_handle']
            stream_info['dest2']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest2']['tg_handle'] = mm_handles['L1_orp']['tg_handle']
            stream_info['dest2']['topo_handle'] = mm_handles['L1_orp']['topo_handle']
            if host_type == "mac_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:00:90:02"
                stream_info['dest1']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
                #traffic src
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:00:90:02"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:00:90:02"
                stream_info['dest2']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
            elif host_type == "mac+ipv4":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:90:44"
                stream_info['dest1']['ip_src'] = "91.91.91.21"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:90:44"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.21"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.21"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.21"

                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:90:44"
                stream_info['dest2']['ip_src'] = "91.91.91.21"
            elif host_type == "mac+ipv6":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:90:45"
                stream_info['dest1']['ip_src'] = "91:91:91::21"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] =  stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:06:90:45"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::21"

                #L3
                stream_info['src3']['mac_src'] =  stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::21"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::21"

                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:90:45"
                stream_info['dest2']['ip_src'] = "91:91:91::21"
            elif host_type == "ipv4_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:90:46"
                stream_info['dest1']['ip_src'] = "91.91.91.22"
                #traffic src
                #L2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:04:90:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.22"
                stream_info['src2']['mac_dst'] = "00:00:00:04:90:47"
                #L3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.22"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.22"

                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:90:47"
                stream_info['dest2']['ip_src'] = "91.91.91.22"
            elif host_type == "ipv4_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:90:48"
                stream_info['dest1']['ip_src'] = "91.91.91.23"
                #traffic src
                #L2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:90:48"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = "91.91.91.23"
                stream_info['src2']['ip_dst'] = "91.91.91.24"
                #L3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = "91.91.91.23"
                stream_info['src4']['ip_dst'] = "91.91.91.24"
                stream_info['src3']['ip_dst2'] = "91.91.0.23"
                stream_info['src4']['ip_dst2'] = "91.91.0.24"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:90:48"
                stream_info['dest2']['ip_src'] = "91.91.91.24"
            elif host_type == "ipv6_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:90:49"
                stream_info['dest1']['ip_src'] = "91:91:91::24"
                #traffic src
                #L2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:90:49"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = "91:91:91::24"
                stream_info['src2']['ip_dst'] = "91:91:91::25"
                #L3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = "91:91:91::24"
                stream_info['src4']['ip_dst'] = "91:91:91::25"
                stream_info['src3']['ip_dst2'] = "91:91::24"
                stream_info['src4']['ip_dst2'] = "91:91::25"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:90:49"
                stream_info['dest2']['ip_src'] = "91:91:91::25"
            elif host_type == "ipv6_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:90:46"
                stream_info['dest1']['ip_src'] = "91:91:91::26"
                #traffic src
                #L2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:06:90:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::26"
                stream_info['src2']['mac_dst'] = "00:00:00:06:90:47"
                #L3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::26"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::26"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:90:47"
                stream_info['dest2']['ip_src'] = "91:91:91::26"
            
        elif move_dir == "mh1_to_mh2":
            #host initial behind mh1
            stream_info['dest1']['src_handle'] = mm_handles['mh1']['port_handle']
            stream_info['dest1']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest1']['tg_handle'] = mm_handles['mh1']['tg_handle']
            stream_info['dest1']['topo_handle'] = mm_handles['mh1']['topo_handle']
            #traffic src
            stream_info['src']['src_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['src']['dest_handle1'] = mm_handles['mh1']['port_handle']
            stream_info['src']['dest_handle2'] = mm_handles['mh2']['port_handle']
            stream_info['src']['tg_handle'] = mm_handles['L2_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['L2_orp']['topo_handle']
            #host moved mh2
            stream_info['dest2']['src_handle'] = mm_handles['mh2']['port_handle']
            stream_info['dest2']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest2']['tg_handle'] = mm_handles['mh2']['tg_handle']
            stream_info['dest2']['topo_handle'] = mm_handles['mh2']['topo_handle']

            if host_type == "mac_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:00:91:02"
                stream_info['dest1']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
                #traffic src
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:00:91:02"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:00:91:02"
                stream_info['dest2']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
            elif host_type == "mac+ipv4":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:91:44"
                stream_info['dest1']['ip_src'] = "91.91.91.11"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:91:44"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.11"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.11"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.11"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:91:44"
                stream_info['dest2']['ip_src'] = "91.91.91.11"
            elif host_type == "mac+ipv6":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:91:45"
                stream_info['dest1']['ip_src'] = "91:91:91::45"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] =  stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:06:91:45"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::45"
                #l3
                stream_info['src3']['mac_src'] =  stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::45"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::45"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:91:45"
                stream_info['dest2']['ip_src'] = "91:91:91::45"
            elif host_type == "ipv4_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:91:46"
                stream_info['dest1']['ip_src'] = "91.91.91.12"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:04:91:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.12"
                stream_info['src2']['mac_dst'] = "00:00:00:04:91:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] ="00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.12"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.12"

                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:91:47"
                stream_info['dest2']['ip_src'] = "91.91.91.12"
            elif host_type == "ipv4_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:91:48"
                stream_info['dest1']['ip_src'] = "91.91.91.14"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:91:48"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = "91.91.91.14"
                stream_info['src2']['ip_dst'] = "91.91.91.15"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = "91.91.91.14"
                stream_info['src4']['ip_dst'] = "91.91.91.15"
                stream_info['src3']['ip_dst2'] = "91.91.0.14"
                stream_info['src4']['ip_dst2'] = "91.91.0.15"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:91:48"
                stream_info['dest2']['ip_src'] = "91.91.91.15"
            elif host_type == "ipv6_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:91:49"
                stream_info['dest1']['ip_src'] = "91:91:91::14"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:91:49"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = "91:91:91::14"
                stream_info['src2']['ip_dst'] = "91:91:91::15"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = "91:91:91::14"
                stream_info['src4']['ip_dst'] = "91:91:91::15"
                stream_info['src3']['ip_dst2'] = "91:91::14"
                stream_info['src4']['ip_dst2'] = "91:91::15"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:91:49"
                stream_info['dest2']['ip_src'] = "91:91:91::15"
            elif host_type == "ipv6_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:91:46"
                stream_info['dest1']['ip_src'] = "91:91:91::16"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:06:91:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::16"
                stream_info['src2']['mac_dst'] = "00:00:00:06:91:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] ="00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::16"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::16"

                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:91:47"
                stream_info['dest2']['ip_src'] = "91:91:91::16"

        elif move_dir == "mac_freeze":
            #host initial behind mh1
            stream_info['dest1']['src_handle'] = mm_handles['mh1']['port_handle']
            stream_info['dest1']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest1']['tg_handle'] = mm_handles['mh1']['tg_handle']
            stream_info['dest1']['topo_handle'] = mm_handles['mh1']['topo_handle']
            #traffic src
            stream_info['src']['src_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['src']['dest_handle1'] = mm_handles['mh1']['port_handle']
            stream_info['src']['dest_handle2'] = mm_handles['mh2']['port_handle']
            stream_info['src']['tg_handle'] = mm_handles['L2_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['L2_orp']['topo_handle']
            #host moved mh2
            stream_info['dest2']['src_handle'] = mm_handles['mh2']['port_handle']
            stream_info['dest2']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest2']['tg_handle'] = mm_handles['mh2']['tg_handle']
            stream_info['dest2']['topo_handle'] = mm_handles['mh2']['topo_handle']

            if host_type == "mac+ipv4":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:97:44"
                stream_info['dest1']['ip_src'] = "91.91.91.66"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:97:44"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.11"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.11"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:97:44"
                stream_info['dest2']['ip_src'] = "91.91.91.66"

        elif move_dir == "mh1_to_mh1_2":
            #host initial behind mh1
            stream_info['dest1']['src_handle'] = mm_handles['mh1']['port_handle']
            stream_info['dest1']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest1']['tg_handle'] = mm_handles['mh1']['tg_handle']
            stream_info['dest1']['topo_handle'] = mm_handles['mh1']['topo_handle']
            #traffic src
            stream_info['src']['src_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['src']['dest_handle1'] = mm_handles['mh1']['port_handle']
            stream_info['src']['dest_handle2'] = mm_handles['mh1_2']['port_handle']
            stream_info['src']['tg_handle'] = mm_handles['L2_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['L2_orp']['topo_handle']

            #host moved mh1_2
            stream_info['dest2']['src_handle'] = mm_handles['mh1_2']['port_handle']
            stream_info['dest2']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest2']['tg_handle'] = mm_handles['mh1_2']['tg_handle']
            stream_info['dest2']['topo_handle'] = mm_handles['mh1_2']['topo_handle']

            if host_type == "mac_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:00:95:02"
                stream_info['dest1']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
                #traffic src
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:00:95:02"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:00:95:02"
                stream_info['dest2']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
            elif host_type == "mac+ipv4":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:95:44"
                stream_info['dest1']['ip_src'] = "91.91.91.51"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:95:44"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.51"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.51"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.51"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:95:44"
                stream_info['dest2']['ip_src'] = "91.91.91.51"
            elif host_type == "mac+ipv6":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:95:45"
                stream_info['dest1']['ip_src'] = "91:91:91::55"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] =  stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:06:95:45"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::55"
                #l3
                stream_info['src3']['mac_src'] =  stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::55"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::55"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:95:45"
                stream_info['dest2']['ip_src'] = "91:91:91::55"
            elif host_type == "ipv4_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:95:46"
                stream_info['dest1']['ip_src'] = "91.91.91.52"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] =  "00:00:00:04:95:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.52"
                stream_info['src2']['mac_dst'] = "00:00:00:04:95:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] ="00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.52"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.52"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:95:47"
                stream_info['dest2']['ip_src'] = "91.91.91.52"
            elif host_type == "ipv4_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:95:48"
                stream_info['dest1']['ip_src'] = "91.91.91.54"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:95:48"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = "91.91.91.54"
                stream_info['src2']['ip_dst'] = "91.91.91.55"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = "91.91.91.54"
                stream_info['src4']['ip_dst'] = "91.91.91.55"
                stream_info['src3']['ip_dst2'] = "91.91.0.54"
                stream_info['src4']['ip_dst2'] = "91.91.0.55"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:95:48"
                stream_info['dest2']['ip_src'] = "91.91.91.55"
            elif host_type == "ipv6_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:95:49"
                stream_info['dest1']['ip_src'] = "91:91:91::54"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:95:49"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = "91:91:91::54"
                stream_info['src2']['ip_dst'] = "91:91:91::55"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = "91:91:91::54"
                stream_info['src4']['ip_dst'] = "91:91:91::55"
                stream_info['src3']['ip_dst2'] = "91:91::54"
                stream_info['src4']['ip_dst2'] = "91:91::55"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:95:49"
                stream_info['dest2']['ip_src'] = "91:91:91::55"
            elif host_type == "ipv6_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:95:46"
                stream_info['dest1']['ip_src'] = "91:91:91::56"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:06:95:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::56"
                stream_info['src2']['mac_dst'] = "00:00:00:06:95:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::56"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::56"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:95:47"
                stream_info['dest2']['ip_src'] = "91:91:91::56"
            
        elif move_dir == "mh1_to_L3orp":
            #host initial behind mh1
            stream_info['dest1']['src_handle'] = mm_handles['mh1']['port_handle']
            stream_info['dest1']['dest_handle'] = mm_handles['L3_orp']['port_handle']
            stream_info['dest1']['tg_handle'] = mm_handles['mh1']['tg_handle']
            stream_info['dest1']['topo_handle'] = mm_handles['mh1']['topo_handle']
            #traffic src
            stream_info['src']['src_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['src']['dest_handle1'] = mm_handles['mh1']['port_handle']
            stream_info['src']['dest_handle2'] = mm_handles['L3_orp']['port_handle']
            stream_info['src']['tg_handle'] = mm_handles['L2_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['L2_orp']['topo_handle']
            #host moved to L3 orphan
            stream_info['dest2']['src_handle'] = mm_handles['L3_orp']['port_handle']
            stream_info['dest2']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest2']['tg_handle'] = mm_handles['L3_orp']['tg_handle']
            stream_info['dest2']['topo_handle'] = mm_handles['L3_orp']['topo_handle']
            if host_type == "mac_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:00:93:02"
                stream_info['dest1']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
                #traffic src
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:00:93:02"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:00:93:02"
                stream_info['dest2']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
            elif host_type == "mac+ipv4":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:93:44"
                stream_info['dest1']['ip_src'] = "91.91.91.31"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:93:44"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.31"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.31"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.31"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:93:44"
                stream_info['dest2']['ip_src'] = "91.91.91.31"
            elif host_type == "mac+ipv6":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:93:45"
                stream_info['dest1']['ip_src'] = "91:91:91::31"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] =  stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:06:93:45"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::31"
                #l3
                stream_info['src3']['mac_src'] =  stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::31"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::31"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:93:45"
                stream_info['dest2']['ip_src'] = "91:91:91::31"
            elif host_type == "ipv4_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:93:46"
                stream_info['dest1']['ip_src'] = "91.91.91.32"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:04:93:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.32"
                stream_info['src2']['mac_dst'] = "00:00:00:04:93:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.32"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.32"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:93:47"
                stream_info['dest2']['ip_src'] = "91.91.91.32"
            elif host_type == "ipv4_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:93:48"
                stream_info['dest1']['ip_src'] = "91.91.91.33"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:93:48"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = "91.91.91.33"
                stream_info['src2']['ip_dst'] = "91.91.91.34"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = "91.91.91.33"
                stream_info['src4']['ip_dst'] = "91.91.91.34"
                stream_info['src3']['ip_dst2'] = "91.91.0.33"
                stream_info['src4']['ip_dst2'] = "91.91.0.34"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:93:48"
                stream_info['dest2']['ip_src'] = "91.91.91.34"
            elif host_type == "ipv6_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:93:49"
                stream_info['dest1']['ip_src'] = "91:91:91::34"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:93:49"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = "91:91:91::34"
                stream_info['src2']['ip_dst'] = "91:91:91::35"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = "91:91:91::34"
                stream_info['src4']['ip_dst'] = "91:91:91::35"
                stream_info['src3']['ip_dst2'] = "91:91::34"
                stream_info['src4']['ip_dst2'] = "91:91::35"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:93:49"
                stream_info['dest2']['ip_src'] = "91:91:91::35"
            elif host_type == "ipv6_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:93:46"
                stream_info['dest1']['ip_src'] = "91:91:91::32"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:06:93:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::32"
                stream_info['src2']['mac_dst'] = "00:00:00:06:93:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::32"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::32"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:93:47"
                stream_info['dest2']['ip_src'] = "91:91:91::32"
            
        elif move_dir == "L1orp_to_L3orp":
            #host initial behind mh1
            stream_info['dest1']['src_handle'] = mm_handles['L1_orp']['port_handle']
            stream_info['dest1']['dest_handle'] = mm_handles['L3_orp']['port_handle']
            stream_info['dest1']['tg_handle'] = mm_handles['L1_orp']['tg_handle']
            stream_info['dest1']['topo_handle'] = mm_handles['L1_orp']['topo_handle']
            #traffic src
            stream_info['src']['src_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['src']['dest_handle1'] = mm_handles['L1_orp']['port_handle']
            stream_info['src']['dest_handle2'] = mm_handles['L3_orp']['port_handle']
            stream_info['src']['tg_handle'] = mm_handles['L2_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['L2_orp']['topo_handle']
            #host moved to L3 orphan
            stream_info['dest2']['src_handle'] = mm_handles['L3_orp']['port_handle']
            stream_info['dest2']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest2']['tg_handle'] = mm_handles['L3_orp']['tg_handle']
            stream_info['dest2']['topo_handle'] = mm_handles['L3_orp']['topo_handle']
            if host_type == "mac_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:00:94:02"
                stream_info['dest1']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
                #traffic src
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:00:94:02"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:00:94:02"
                stream_info['dest2']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
            elif host_type == "mac+ipv4":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:94:44"
                stream_info['dest1']['ip_src'] = "91.91.91.41"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:94:44"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.41"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.41"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.41"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:94:44"
                stream_info['dest2']['ip_src'] = "91.91.91.41"
            elif host_type == "mac+ipv6":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:94:45"
                stream_info['dest1']['ip_src'] = "91:91:91::41"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] =  stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:06:94:45"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::41"
                #l3
                stream_info['src3']['mac_src'] =  stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::41"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::41"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:94:45"
                stream_info['dest2']['ip_src'] = "91:91:91::41"
            elif host_type == "ipv4_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:94:46"
                stream_info['dest1']['ip_src'] = "91.91.91.42"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:04:94:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.42"
                stream_info['src2']['mac_dst'] = "00:00:00:04:94:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.42"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91.91.0.42"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:94:47"
                stream_info['dest2']['ip_src'] = "91.91.91.42"
            elif host_type == "ipv4_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:94:48"
                stream_info['dest1']['ip_src'] = "91.91.91.43"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:94:48"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = "91.91.91.43"
                stream_info['src2']['ip_dst'] = "91.91.91.44"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = "91.91.91.43"
                stream_info['src4']['ip_dst'] = "91.91.91.44"
                stream_info['src3']['ip_dst2'] = "91.91.0.43"
                stream_info['src4']['ip_dst2'] = "91.91.0.44"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:94:48"
                stream_info['dest2']['ip_src'] = "91.91.91.44"
            elif host_type == "ipv6_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:94:49"
                stream_info['dest1']['ip_src'] = "91:91:91::44"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:94:49"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = "91:91:91::44"
                stream_info['src2']['ip_dst'] = "91:91:91::45"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = "91:91:91::44"
                stream_info['src4']['ip_dst'] = "91:91:91::45"
                stream_info['src3']['ip_dst2'] = "91:91::44"
                stream_info['src4']['ip_dst2'] = "91:91::45"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:94:49"
                stream_info['dest2']['ip_src'] = "91:91:91::45"
            elif host_type == "ipv6_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:94:46"
                stream_info['dest1']['ip_src'] = "91:91:91::42"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:06:94:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::42"
                stream_info['src2']['mac_dst'] = "00:00:00:06:94:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::42"
                stream_info['src3']['ip_dst2'] = stream_info['src4']['ip_dst2'] = "91:91::42"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:94:47"
                stream_info['dest2']['ip_src'] = "91:91:91::42"

        elif move_dir == "L1orp_to_S3orp":
            #host initial behind L1orp
            stream_info['dest1']['src_handle'] = mm_handles['L1_orp']['port_handle']
            stream_info['dest1']['dest_handle'] = mm_handles['S3_orp']['port_handle']
            stream_info['dest1']['tg_handle'] = mm_handles['L1_orp']['tg_handle']
            stream_info['dest1']['topo_handle'] = mm_handles['L1_orp']['topo_handle']
            #traffic src
            stream_info['src']['src_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['src']['dest_handle1'] = mm_handles['L1_orp']['port_handle']
            stream_info['src']['dest_handle2'] = mm_handles['S3_orp']['port_handle']
            stream_info['src']['tg_handle'] = mm_handles['L2_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['L2_orp']['topo_handle']
            #host moved to L3 orphan
            stream_info['dest2']['src_handle'] = mm_handles['S3_orp']['port_handle']
            stream_info['dest2']['dest_handle'] = mm_handles['L2_orp']['port_handle']
            stream_info['dest2']['tg_handle'] = mm_handles['S3_orp']['tg_handle']
            stream_info['src']['topo_handle'] = mm_handles['S3_orp']['topo_handle']
            if host_type == "mac_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:00:96:02"
                stream_info['dest1']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
                #traffic src
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:00:96:02"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:00:96:02"
                stream_info['dest2']['mac_dst'] = "ff:ff:ff:ff:ff:ff"
            elif host_type == "mac+ipv4":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:96:44"
                stream_info['dest1']['ip_src'] = "91.91.91.61"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:96:44"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.61"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.61"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:96:44"
                stream_info['dest2']['ip_src'] = "91.91.91.61"
            elif host_type == "mac+ipv6":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:96:45"
                stream_info['dest1']['ip_src'] = "91:91:91::61"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] =  stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:06:96:45"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] = "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::61"
                #l3
                stream_info['src3']['mac_src'] =  stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] = "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::61"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:96:45"
                stream_info['dest2']['ip_src'] = "91:91:91::61"
            elif host_type == "ipv4_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:96:46"
                stream_info['dest1']['ip_src'] = "91.91.91.62"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:04:96:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91.91.91.62"
                stream_info['src2']['mac_dst'] = "00:00:00:04:96:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91.91.91.62"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:96:47"
                stream_info['dest2']['ip_src'] = "91.91.91.62"
            elif host_type == "ipv4_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:96:48"
                stream_info['dest1']['ip_src'] = "91.91.91.63"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:96:48"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91.91.91.99"
                stream_info['src1']['ip_dst'] = "91.91.91.63"
                stream_info['src2']['ip_dst'] = "91.91.91.64"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92.92.92.99"
                stream_info['src3']['ip_dst'] = "91.91.91.63"
                stream_info['src4']['ip_dst'] = "91.91.91.64"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:96:48"
                stream_info['dest2']['ip_src'] = "91.91.91.64"
            elif host_type == "ipv6_changes":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:04:96:49"
                stream_info['dest1']['ip_src'] = "91:91:91::64"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = stream_info['src2']['mac_dst'] = "00:00:00:04:96:49"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = "91:91:91::64"
                stream_info['src2']['ip_dst'] = "91:91:91::65"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = "91:91:91::64"
                stream_info['src4']['ip_dst'] = "91:91:91::65"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:04:96:49"
                stream_info['dest2']['ip_src'] = "91:91:91::65"
            elif host_type == "ipv6_only":
                #host initial behind mh1
                stream_info['dest1']['mac_src'] = "00:00:00:06:96:46"
                stream_info['dest1']['ip_src'] = "91:91:91::62"
                #traffic src
                #l2
                stream_info['src1']['mac_src'] = stream_info['src2']['mac_src'] = "00:00:00:00:91:99"
                stream_info['src1']['mac_dst'] = "00:00:00:06:96:46"
                stream_info['src1']['ip_src'] = stream_info['src2']['ip_src'] =  "91:91:91::99"
                stream_info['src1']['ip_dst'] = stream_info['src2']['ip_dst'] = "91:91:91::62"
                stream_info['src2']['mac_dst'] = "00:00:00:06:96:47"
                #l3
                stream_info['src3']['mac_src'] = stream_info['src4']['mac_src'] = "00:00:00:00:92:99"
                stream_info['src3']['mac_dst'] = stream_info['src4']['mac_dst'] = "00:11:22:33:44:55"
                stream_info['src3']['ip_src'] = stream_info['src4']['ip_src'] =  "92:92:92::99"
                stream_info['src3']['ip_dst'] = stream_info['src4']['ip_dst'] = "91:91:91::62"
                #host moved mh2
                stream_info['dest2']['mac_src'] = "00:00:00:06:96:47"
                stream_info['dest2']['ip_src'] = "91:91:91::62"

        my_stream_handles = {}

        if host_type == "mac_only":
            my_stream_handles["mm_host"] = {}
            my_stream_handles["mm_host"]['mac'] = stream_info['src1']['mac_dst']  
            my_stream_handles['tg_handle'] = stream_info['src']['tg_handle']
            src_stream_1 = stream_info['src']['tg_handle'].tg_traffic_config(
                                    emulation_src_handle=stream_info['src']['src_handle'], 
                                    emulation_dst_handle=stream_info['src']['dest_handle1'], 
                                    mode='create',
                                    transmit_mode="single_burst", 
                                    pkts_per_burst=pkts_per_burst, 
                                    rate_percent = rate_percent, 
                                    circuit_type='raw', 
                                    frame_size=1000, 
                                    mac_src=stream_info['src1']['mac_src'] , 
                                    mac_dst= stream_info['src1']['mac_dst'],
                                    vlan_id = 910,
                                    src_dest_mesh='one_to_one',
                                    track_by ="endpoint_pair"
                                    )
            st.wait(5)
            my_stream_handles['src1_stream_handle'] = src_stream_1["stream_id"]
            src_stream_2 = stream_info['src']['tg_handle'].tg_traffic_config(
                                    emulation_src_handle=stream_info['src']['src_handle'], 
                                    emulation_dst_handle=stream_info['src']['dest_handle2'], 
                                    mode='create',
                                    transmit_mode="single_burst", 
                                    pkts_per_burst=pkts_per_burst, 
                                    rate_percent = rate_percent, 
                                    circuit_type='raw', 
                                    frame_size=1000, 
                                    mac_src=stream_info['src2']['mac_src'] , 
                                    mac_dst= stream_info['src2']['mac_dst'],
                                    vlan_id = 910,
                                    src_dest_mesh='one_to_one',
                                    track_by ="endpoint_pair"
                                    )
            st.wait(5)
            my_stream_handles['src2_stream_handle'] = src_stream_2["stream_id"]
            dest1_handle = stream_info['dest1']['tg_handle'].tg_traffic_config(
                                emulation_src_handle=stream_info['dest1']['src_handle'], 
                                emulation_dst_handle=stream_info['dest1']['dest_handle'], 
                                mode='create',
                                transmit_mode="single_burst", 
                                pkts_per_burst=pkts_per_burst, 
                                rate_percent = rate_percent, 
                                circuit_type='raw', 
                                frame_size=1000, 
                                mac_src=stream_info['dest1']['mac_src'], 
                                mac_dst= stream_info['dest1']['mac_dst'],
                                vlan_id = 910,
                                src_dest_mesh='one_to_one',
                                track_by ="endpoint_pair"
                                )
            st.wait(5)
            my_stream_handles['dest1_handle'] = dest1_handle["stream_id"]
            dest2_handle = stream_info['dest2']['tg_handle'].tg_traffic_config(
                                emulation_src_handle=stream_info['dest2']['src_handle'], 
                                emulation_dst_handle=stream_info['dest2']['dest_handle'], 
                                mode='create',
                                transmit_mode="single_burst", 
                                pkts_per_burst=pkts_per_burst, 
                                rate_percent = rate_percent, 
                                circuit_type='raw', 
                                frame_size=1000, 
                                mac_src=stream_info['dest2']['mac_src'], 
                                mac_dst= stream_info['dest2']['mac_dst'],
                                vlan_id = 910,
                                src_dest_mesh='one_to_one',
                                track_by ="endpoint_pair"
                                )
            st.wait(5)
            my_stream_handles['dest2_handle'] = dest2_handle["stream_id"]
        
        else:
            #L2
            my_stream_handles["mm_host"] = {'src1': {}, 'src2': {}, 'src3': {}, 'src4': {}}
            my_stream_handles["mm_host"]['src1']['mac'] =  stream_info['src1']['mac_dst'] 
            my_stream_handles["mm_host"]['src1']['ip'] = stream_info['src1']['ip_dst'] 
            my_stream_handles["mm_host"]['src2']['mac'] =  stream_info['src2']['mac_dst'] 
            my_stream_handles["mm_host"]['src2']['ip'] = stream_info['src2']['ip_dst']
            #L3
            my_stream_handles["mm_host"]['src3']['mac'] =  stream_info['src3']['mac_dst'] 
            my_stream_handles["mm_host"]['src3']['ip'] = stream_info['src3']['ip_dst'] 
            my_stream_handles["mm_host"]['src4']['mac'] =  stream_info['src4']['mac_dst'] 
            my_stream_handles["mm_host"]['src4']['ip'] = stream_info['src4']['ip_dst']  

            my_stream_handles['tg_handle'] = stream_info['src']['tg_handle']
            device_group_1 = stream_info['dest1']['tg_handle'].tg_topology_config(
                        topology_handle= stream_info['dest1']['topo_handle'],
                        device_group_name= """mac move host dest1""",
                        device_group_multiplier = "1",
                        device_group_enabled= "1"
                        )
            deviceGroup_handle_1 = device_group_1['device_group_handle']
            my_stream_handles['dest1_handle'] = deviceGroup_handle_1
            device_group_2 = stream_info['dest2']['tg_handle'].tg_topology_config(
                            topology_handle= stream_info['dest2']['topo_handle'],
                            device_group_name= """mac move host dest2""",
                            device_group_multiplier = "1",
                            device_group_enabled= "1"
                            )
            deviceGroup_handle_2 = device_group_2['device_group_handle']
            my_stream_handles['dest2_handle'] = deviceGroup_handle_2
            device_group_3 = stream_info['src']['tg_handle'].tg_topology_config(
                        topology_handle= stream_info['src']['topo_handle'],
                        device_group_name= """mac move host src""",
                        device_group_multiplier = "1",
                        device_group_enabled= "1"
                        )
            deviceGroup_handle_3 = device_group_3['device_group_handle']
            my_stream_handles['src'] = deviceGroup_handle_3
            ###Creating ethernet stack for the Device Group###
            l2_protocol_1 = stream_info['dest1']['tg_handle'].tg_interface_config(
                protocol_name= """Eth macmove dest1""",
                protocol_handle= deviceGroup_handle_1,mtu= "1500",
                src_mac_addr= stream_info['dest1']['mac_src'],
                src_mac_addr_step= "00.00.00.00.00.01", 
                vlan=1,
                vlan_id="910", 
                vlan_id_step=0,
                vlan_id_count=1
                )
            ethernet_handle_1 = l2_protocol_1['ethernet_handle']

            l2_protocol_2 = stream_info['dest2']['tg_handle'].tg_interface_config(
                protocol_name= """Eth macmove dest2""",
                protocol_handle= deviceGroup_handle_2,mtu= "1500",
                src_mac_addr= stream_info['dest2']['mac_src'],
                src_mac_addr_step= "00.00.00.00.00.01", 
                vlan=1,
                vlan_id="910", 
                vlan_id_step=0,
                vlan_id_count=1
                )
            ethernet_handle_2 = l2_protocol_2['ethernet_handle']
            l2_protocol_3 = stream_info['src']['tg_handle'].tg_interface_config(
                protocol_name= """Eth macmove src""",
                protocol_handle= deviceGroup_handle_3,mtu= "1500",
                src_mac_addr= stream_info['src1']['mac_src'],
                src_mac_addr_step= "00.00.00.00.00.01", 
                vlan=1,
                vlan_id="910", 
                vlan_id_step=0,
                vlan_id_count=1
                )
            ethernet_handle_3 = l2_protocol_3['ethernet_handle']
            #L3 device
            device_group_4 = stream_info['src']['tg_handle'].tg_topology_config(
                        topology_handle= stream_info['src']['topo_handle'],
                        device_group_name= """mac move host l3 src""",
                        device_group_multiplier = "1",
                        device_group_enabled= "1"
                        )
            deviceGroup_handle_4 = device_group_4['device_group_handle']
            my_stream_handles['l3_src'] = deviceGroup_handle_4

            l2_protocol_4 = stream_info['src']['tg_handle'].tg_interface_config(
                protocol_name= """Eth macmove l3 src""",
                protocol_handle= deviceGroup_handle_4,mtu= "1500",
                src_mac_addr= stream_info['src3']['mac_src'],
                src_mac_addr_step= "00.00.00.00.00.01", 
                vlan=1,
                vlan_id="920", 
                vlan_id_step=0,
                vlan_id_count=1
                )
            ethernet_handle_4 = l2_protocol_4['ethernet_handle']

            if host_type in ["mac+ipv4","ipv4_only","ipv4_changes"]:
                ### Creating IPv4 Stack for the Device Group###
                l3_protocol_1 = stream_info['dest1']['tg_handle'].tg_interface_config(
                    protocol_name= """v4 Stack macmove dest1""",
                    protocol_handle=ethernet_handle_1,
                    ipv4_resolve_gateway= "1",
                    gateway= "91.91.91.1",
                    gateway_step= "0.0.0.0",
                    intf_ip_addr = stream_info['dest1']['ip_src'],
                    intf_ip_addr_step= "0.0.0.1"
                    )
                l3_protocol_2 = stream_info['dest2']['tg_handle'].tg_interface_config(
                    protocol_name= """v4 Stack macmove dest2""",
                    protocol_handle=ethernet_handle_2,
                    ipv4_resolve_gateway= "1",
                    gateway= "91.91.91.1",
                    gateway_step= "0.0.0.0",
                    intf_ip_addr = stream_info['dest2']['ip_src'],
                    intf_ip_addr_step= "0.0.0.1"
                    )
                
                l3_protocol_3 = stream_info['src']['tg_handle'].tg_interface_config(
                    protocol_name= """v4 Stack macmove src""",
                    protocol_handle=ethernet_handle_3,
                    ipv4_resolve_gateway= "1",
                    gateway= "91.91.91.1",
                    gateway_step= "0.0.0.0",
                    intf_ip_addr = stream_info['src1']['ip_src'],
                    intf_ip_addr_step= "0.0.0.1"
                    )
                l3_protocol_4 = stream_info['src']['tg_handle'].tg_interface_config(
                    protocol_name= """v4 Stack macmove l3 src""",
                    protocol_handle=ethernet_handle_4,
                    ipv4_resolve_gateway= "1",
                    gateway= "92.92.92.1",
                    gateway_step= "0.0.0.0",
                    intf_ip_addr = stream_info['src3']['ip_src'],
                    intf_ip_addr_step= "0.0.0.1"
                    )
            if host_type in ["mac+ipv6",'ipv6_changes','ipv6_only']:
                ### Creating IPv6 Stack for the Device Group###
                l3_protocol_1 = stream_info['dest1']['tg_handle'].tg_interface_config(
                    protocol_name= """v6 Stack macmove dest1""",
                    protocol_handle=ethernet_handle_1,
                    ipv6_resolve_gateway= "1",
                    ipv6_gateway= "91:91:91::1",
                    ipv6_gateway_step= "0::0",
                    ipv6_intf_addr = stream_info['dest1']['ip_src'],
                    ipv6_intf_addr_step= "0::1"
                    )
                l3_protocol_2 = stream_info['dest2']['tg_handle'].tg_interface_config(
                    protocol_name= """v6 Stack macmove dest2""",
                    protocol_handle=ethernet_handle_2,
                    ipv6_resolve_gateway= "1",
                    ipv6_gateway= "91:91:91::1",
                    ipv6_gateway_step= "0::0",
                    ipv6_intf_addr = stream_info['dest2']['ip_src'],
                    ipv6_intf_addr_step= "0::1"
                    )
                
                l3_protocol_3 = stream_info['src']['tg_handle'].tg_interface_config(
                    protocol_name= """v6 Stack macmove src""",
                    protocol_handle=ethernet_handle_3,
                    ipv6_resolve_gateway= "1",
                    ipv6_gateway= "91:91:91::1",
                    ipv6_gateway_step= "0::0",
                    ipv6_intf_addr = stream_info['src1']['ip_src'],
                    ipv6_intf_addr_step= "0::1"
                    )
                l3_protocol_3 = stream_info['src']['tg_handle'].tg_interface_config(
                    protocol_name= """v6 Stack macmove l3 src""",
                    protocol_handle=ethernet_handle_4,
                    ipv6_resolve_gateway= "1",
                    ipv6_gateway= "92:92:92::1",
                    ipv6_gateway_step= "0::0",
                    ipv6_intf_addr = stream_info['src3']['ip_src'],
                    ipv6_intf_addr_step= "0::1"
                    )

            stream_info['src']['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", handle=my_stream_handles['src'])
            stream_info['src']['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", handle=my_stream_handles['l3_src'])
            stream_info['src']['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", handle=my_stream_handles['dest2_handle'])
            stream_info['src']['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", handle=my_stream_handles['dest1_handle'])
            
            if host_type in ["mac+ipv6",'ipv6_changes','ipv6_only']:
                src_stream_1 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle1'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src1']['mac_src'] , 
                                        mac_dst= stream_info['src1']['mac_dst'],
                                        ipv6_src_addr = stream_info['src1']['ip_src'],
                                        ipv6_dst_addr = stream_info['src1']['ip_dst'],
                                        vlan_id = 910,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_2 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle2'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src2']['mac_src'] , 
                                        mac_dst= stream_info['src2']['mac_dst'],
                                        ipv6_src_addr = stream_info['src2']['ip_src'],
                                        ipv6_dst_addr = stream_info['src2']['ip_dst'],
                                        vlan_id = 910,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_3 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle1'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src3']['mac_src'] , 
                                        mac_dst= stream_info['src3']['mac_dst'],
                                        ipv6_src_addr = stream_info['src3']['ip_src'],
                                        ipv6_dst_addr = stream_info['src3']['ip_dst'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_4 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle2'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src4']['mac_src'] , 
                                        mac_dst= stream_info['src4']['mac_dst'],
                                        ipv6_src_addr = stream_info['src4']['ip_src'],
                                        ipv6_dst_addr = stream_info['src4']['ip_dst'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_5 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle1'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src3']['mac_src'] , 
                                        mac_dst= stream_info['src3']['mac_dst'],
                                        ipv6_src_addr = stream_info['src3']['ip_src'],
                                        ipv6_dst_addr = stream_info['src3']['ip_dst2'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_6 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle2'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src4']['mac_src'] , 
                                        mac_dst= stream_info['src4']['mac_dst'],
                                        ipv6_src_addr = stream_info['src4']['ip_src'],
                                        ipv6_dst_addr = stream_info['src4']['ip_dst2'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
            else:
                src_stream_1 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle1'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src1']['mac_src'] , 
                                        mac_dst= stream_info['src1']['mac_dst'],
                                        ip_src_addr = stream_info['src1']['ip_src'],
                                        ip_dst_addr = stream_info['src1']['ip_dst'],
                                        vlan_id = 910,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_2 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle2'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src2']['mac_src'] , 
                                        mac_dst= stream_info['src2']['mac_dst'],
                                        ip_src_addr = stream_info['src2']['ip_src'],
                                        ip_dst_addr = stream_info['src2']['ip_dst'],
                                        vlan_id = 910,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_3 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle1'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src3']['mac_src'] , 
                                        mac_dst= stream_info['src3']['mac_dst'],
                                        ip_src_addr = stream_info['src3']['ip_src'],
                                        ip_dst_addr = stream_info['src3']['ip_dst'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_4 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle2'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src4']['mac_src'] , 
                                        mac_dst= stream_info['src4']['mac_dst'],
                                        ip_src_addr = stream_info['src4']['ip_src'],
                                        ip_dst_addr = stream_info['src4']['ip_dst'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_5 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle1'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src3']['mac_src'] , 
                                        mac_dst= stream_info['src3']['mac_dst'],
                                        ip_src_addr = stream_info['src3']['ip_src'],
                                        ip_dst_addr = stream_info['src3']['ip_dst2'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)
                src_stream_6 = stream_info['src']['tg_handle'].tg_traffic_config(
                                        emulation_src_handle=stream_info['src']['src_handle'], 
                                        emulation_dst_handle=stream_info['src']['dest_handle2'], 
                                        mode='create',
                                        transmit_mode="single_burst", 
                                        pkts_per_burst=pkts_per_burst, 
                                        rate_percent = rate_percent, 
                                        circuit_type='raw', 
                                        frame_size=1000, 
                                        mac_src=stream_info['src4']['mac_src'] , 
                                        mac_dst= stream_info['src4']['mac_dst'],
                                        ip_src_addr = stream_info['src4']['ip_src'],
                                        ip_dst_addr = stream_info['src4']['ip_dst2'],
                                        vlan_id = 920,
                                        src_dest_mesh='one_to_one',
                                        track_by ="endpoint_pair"
                                        )
                st.wait(5)

            
            my_stream_handles['src1_stream_handle'] = src_stream_1["stream_id"]
            my_stream_handles['src2_stream_handle'] = src_stream_2["stream_id"]
            if not host_type == "mac_only":
                my_stream_handles['src3_stream_handle'] = src_stream_3["stream_id"]
                my_stream_handles['src4_stream_handle'] = src_stream_4["stream_id"]
                my_stream_handles['src5_stream_handle'] = src_stream_5["stream_id"]
                my_stream_handles['src6_stream_handle'] = src_stream_6["stream_id"]
        
        return my_stream_handles
    
    def verify_mac_move(self, tc_id = "", move_dir = "", host_type = ""):
        
        leaf_nodes = []
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        st.banner("Starting test for {} ".format(tc_id))
        flag = False
        mm_handles = self.get_stream_handles(move_dir = move_dir , host_type = host_type)
        tg_handle = mm_handles['tg_handle']
        if move_dir == "mh1_to_mh2":
            mm1_host_list = ['leaf2','leaf3']
            mm2_host_list = ['leaf0','leaf1']
        elif move_dir == "mh1_to_L1orp":
            mm1_host_list = ['leaf1']
            mm2_host_list = ['leaf0','leaf1']
        elif move_dir == "mh1_to_L3orp":
            mm1_host_list = ['leaf3']
            mm2_host_list = ['leaf0','leaf1']
        elif move_dir == "L1orp_to_L3orp":
            mm1_host_list = ['leaf3']
            mm2_host_list = ['leaf1']
        elif move_dir == "L1orp_to_S3orp":
            mm1_host_list = ['spine3']
            mm2_host_list = ['leaf1']
        elif move_dir == "mh1_to_mh1_2":
            mm1_host_list = ['leaf0','leaf1']
            mm2_host_list = ['leaf0','leaf1']

        #learn host at location 1
        if host_type == 'mac_only':
            self.send_traffic(tg_handle,[mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle']])
            self.send_traffic(tg_handle, mm_handles['dest1_handle'])
            self.verify_mac(mm_handles['mm_host']['mac'])
        else:
            all_traffic = [mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle'],mm_handles['src3_stream_handle'],mm_handles['src4_stream_handle']]
            l2_handles = [mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle']]
            l3_handles = [mm_handles['src3_stream_handle'],mm_handles['src4_stream_handle']]
            mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['src'])
            st.wait(5)
            mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['l3_src'])
            st.wait(5)
            mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['dest1_handle'])  
            st.wait(5)
        # verify no mac move
        #check traffic 
        if host_type == "mac_only":
            self.send_traffic(tg_handle,[mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle']])
            out_1 = vxlan_obj.validate_stats(tg_handle,mm_handles['src1_stream_handle'])
            out_2 = vxlan_obj.validate_stats(tg_handle,mm_handles['src2_stream_handle'])
            if out_1 and not out_2:
                st.banner(" {} : traffic passed as expected when no host move".format(host_type))
            else:
                st.banner(" {} : traffic failed when no host move".format(host_type))
                self.cleanup_tgen(mm_handles)
                return flag

        elif host_type in ["ipv4_only","ipv6_only"]:
            self.verify_mac(mm_handles['mm_host']['src2']['mac'], ip_addr = mm_handles['mm_host']['src2']['ip'])
            self.send_traffic(tg_handle,[mm_handles['src1_stream_handle'],mm_handles['src3_stream_handle']])
            out_1 = vxlan_obj.validate_stats(tg_handle,mm_handles['src1_stream_handle'])
            out_3 = vxlan_obj.validate_stats(tg_handle,mm_handles['src3_stream_handle'])
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['src'])
            st.wait(2)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['l3_src'])
            st.wait(2)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['dest1_handle'])
            st.wait(2)
            if out_1 and out_3:
                st.banner(" {} : traffic passed as expected when no host move".format(host_type))
            else:
                st.banner(" {} : traffic failed when no host move".format(host_type))
                self.cleanup_tgen(mm_handles)
                return flag
        else:
            self.verify_mac(mm_handles['mm_host']['src2']['mac'], ip_addr = mm_handles['mm_host']['src2']['ip'])
            self.send_traffic(tg_handle,all_traffic)
            l2_traffic = self._chk_stats(tg_handle, l2_handles, exp_traffic_on  = mm_handles['src1_stream_handle'])
            l3_traffic = self._chk_stats(tg_handle, l3_handles, exp_traffic_on  = mm_handles['src3_stream_handle'])
            st.banner("l2_traffic : {}, l3_traffic : {} ".format(l2_traffic,l3_traffic))
            self.verify_mac(mm_handles['mm_host']['src1']['mac'], ip_addr = mm_handles['mm_host']['src1']['ip'])
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['src'])
            st.wait(2)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['l3_src'])
            st.wait(2)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['dest1_handle'])
            st.wait(2)
            ###Check type 2 MM###
            if l2_traffic and l3_traffic:
                st.banner(" {} : traffic passed as expected when no host move".format(host_type))
            else:
                st.banner(" {} : traffic failed when no host move".format(host_type))
                self.cleanup_tgen(mm_handles)
                return flag
        for node in leaf_nodes:
            st.show(node,"show evpn es", skip_tmpl=True)
            st.show(node,"show vxlan l2nexthopgroup", skip_tmpl=True)
        #host moves from mh1 to mh2
        if host_type == 'mac_only':
            self.send_traffic(tg_handle,mm_handles['dest2_handle'])
            self.verify_mac(mm_handles['mm_host']['mac'])
        else:
            mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['dest2_handle'])  
            st.wait(5)
            self.verify_mac(mm_handles['mm_host']['src2']['mac'], ip_addr = mm_handles['mm_host']['src2']['ip'])
        #verify mac move MM1
        #check traffic after host move
        st.banner("check ES state after the mac move")
        for node in leaf_nodes:
            st.show(node,"show evpn es", skip_tmpl=True)
            st.show(node,"show vxlan l2nexthopgroup", skip_tmpl=True)
        if host_type == "mac_only":
            self.send_traffic(tg_handle,[mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle']])
            out_1 = vxlan_obj.validate_stats(tg_handle,mm_handles['src1_stream_handle'])
            out_2 = vxlan_obj.validate_stats(tg_handle,mm_handles['src2_stream_handle'])
            if not out_1 and out_2:
                st.banner(" {} : traffic passed as expected after first move".format(host_type))
            else:
                st.banner(" {} : traffic failed after first move".format(host_type))
                self.cleanup_tgen(mm_handles)
                return flag
        elif host_type in ["ipv4_only","ipv6_only"]:
            self.verify_mac(mm_handles['mm_host']['src2']['mac'], ip_addr = mm_handles['mm_host']['src2']['ip'])
            self.send_traffic(tg_handle,[mm_handles['src2_stream_handle'], mm_handles['src4_stream_handle']])
            out_2 = vxlan_obj.validate_stats(tg_handle,mm_handles['src2_stream_handle'])
            out_4 = vxlan_obj.validate_stats(tg_handle,mm_handles['src4_stream_handle'])
            if out_2 and out_4:
                st.banner("{} : traffic passed as expected after host move".format(host_type))
            else:
                st.banner("{} : traffic failed after host move".format(host_type))
        else:
            self.verify_mac(mm_handles['mm_host']['src2']['mac'], ip_addr = mm_handles['mm_host']['src2']['ip'])
            self.send_traffic(tg_handle,all_traffic)
            l2_traffic = self._chk_stats(tg_handle, l2_handles, exp_traffic_on  = mm_handles['src2_stream_handle'])
            l3_traffic = self._chk_stats(tg_handle, l3_handles, exp_traffic_on  = mm_handles['src4_stream_handle'])
            st.banner("l2_traffic : {}, l3_traffic : {} ".format(l2_traffic,l3_traffic))
            if l2_traffic and l3_traffic:
                st.banner(" {} : traffic passed as expected after host move".format(host_type))
            else:
                st.banner(" {} : traffic failed after host move".format(host_type))
        if host_type == 'mac_only':
            check_mm_1 = vxlan_obj.verify_mac_seq(mm_handles['mm_host']['mac'],mac_move_seq='1',host_local_node=mm1_host_list,host_type = host_type, is_mh_host = True)
            is_local = mac_obj.verify_mac_address('leaf1',910,mm_handles['mm_host']['mac'])
        else:
            check_mm_1 = vxlan_obj.verify_mac_seq(mm_handles['mm_host']['src2'],mac_move_seq='1',host_local_node=mm1_host_list,host_type = host_type)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['dest2_handle'])
            st.wait(2)
        
        st.banner("check_mm_1 : {}".format(check_mm_1))
        
        if not check_mm_1:
            self.cleanup_tgen(mm_handles)
            return flag
        #verify mac move MM2
        #Move host back to original location
        if host_type == 'mac_only':
            self.send_traffic(tg_handle, mm_handles['dest1_handle'])
            self.verify_mac(mm_handles['mm_host']['mac'])
        else:
            mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['dest1_handle'])  
            st.wait(5)

        if host_type == "mac_only":
            self.send_traffic(tg_handle,[mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle']])
        elif host_type in ["ipv4_only","ipv6_only"]:
            self.send_traffic(tg_handle,[mm_handles['src1_stream_handle'], mm_handles['src3_stream_handle']])
        else:
            self.send_traffic(tg_handle,all_traffic)

        if host_type == 'mac_only':
            check_mm_2 = vxlan_obj.verify_mac_seq(mm_handles['mm_host']['mac'],mac_move_seq='2',host_local_node=mm2_host_list, host_type = host_type, is_mh_host = True)
            is_local = mac_obj.verify_mac_address('leaf0',910, mm_handles['mm_host']['mac'])
        else:
            self.verify_mac(mm_handles['mm_host']['src1']['mac'], ip_addr = mm_handles['mm_host']['src1']['ip'])
            check_mm_2 = vxlan_obj.verify_mac_seq(mm_handles['mm_host']['src1'],mac_move_seq='2',host_local_node=mm2_host_list, host_type = host_type)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['dest1_handle'])
            st.wait(2)
        st.banner("check_mm_2 : {}".format(check_mm_2))
        if host_type == "mac_only":
            out_1 = vxlan_obj.validate_stats(tg_handle,mm_handles['src1_stream_handle'])
            out_2 = vxlan_obj.validate_stats(tg_handle,mm_handles['src2_stream_handle'])
            if out_1 and not out_2 and check_mm_2:
                st.banner(" {} : traffic passed as expected after mac move to original location".format(host_type))
                flag = True
            else:
                st.banner(" {} : traffic failed after mac move to original location".format(host_type))
        elif host_type in ["ipv4_only","ipv6_only"]:
            out_1 = vxlan_obj.validate_stats(tg_handle,mm_handles['src1_stream_handle'])
            out_3 = vxlan_obj.validate_stats(tg_handle,mm_handles['src3_stream_handle'])
            if out_1 and out_3 and check_mm_2:
                st.banner("traffic passed as expected after host move")
                flag = True
            else:
                st.banner("traffic failed after host move")
        else:
            l2_traffic = self._chk_stats(tg_handle, l2_handles, exp_traffic_on  = mm_handles['src1_stream_handle'])
            l3_traffic = self._chk_stats(tg_handle, l3_handles, exp_traffic_on  = mm_handles['src3_stream_handle'])
            st.banner("l2_traffic : {}, l3_traffic : {} ".format(l2_traffic,l3_traffic))
            
            if l2_traffic and l3_traffic and check_mm_2:
                st.banner("{} : traffic passed as expected after mac move to original location".format(host_type))
                flag = True
            else:
                st.banner("{} : traffic failed after mac move to original location".format(host_type))
        #tgen_cleanup
        self.cleanup_tgen(mm_handles)
        return flag


    ###MH to MH###

    def test_mac_move_mh_to_mh_mac_and_ipv4(self):
        tc_id = "Mac+ipv4 move from MH to MH "
        move_dir = "mh1_to_mh2"
        host_type = 'mac+ipv4'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_mh_mac_and_ipv6(self):
        tc_id = "Mac+ipv6 move from MH to MH "
        move_dir = "mh1_to_mh2"
        host_type = 'mac+ipv6'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_mh_mac_only(self):
        tc_id = "mac_only move from MH to MH "
        move_dir = "mh1_to_mh2"
        host_type = 'mac_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_mh_ipv4_changes(self):
        tc_id = "ipv4_changes move from MH to MH "
        move_dir = "mh1_to_mh2"
        host_type = 'ipv4_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_mh_ipv6_changes(self):
        tc_id = "ipv6_changes move from MH to MH "
        move_dir = "mh1_to_mh2"
        host_type = 'ipv6_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_mh_ipv4_only(self):
        tc_id = "ipv4_only move from MH to MH "
        move_dir = "mh1_to_mh2"
        host_type = 'ipv4_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_mh_ipv6_only(self):
        tc_id = "ipv6_only move from MH to MH "
        move_dir = "mh1_to_mh2"
        host_type = 'ipv6_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    ### MH to L1orp ###
    def test_mac_move_mh_to_local_orp_mac_and_ipv4(self):
        tc_id = "Mac+ipv4 move from MH to L1 orp "
        move_dir = "mh1_to_L1orp"
        host_type = 'mac+ipv4'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_local_orp_mac_and_ipv6(self):
        tc_id = "Mac+ipv6 move from MH to  L1 orp "
        move_dir = "mh1_to_L1orp"
        host_type = 'mac+ipv6'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_local_orp_mac_only(self):
        tc_id = "mac_only move from MH to  L1 orp "
        move_dir = "mh1_to_L1orp"
        host_type = 'mac_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_local_orp_ipv4_changes(self):
        tc_id = "ipv4_changes move from MH to  L1 orp "
        move_dir = "mh1_to_L1orp"
        host_type = 'ipv4_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_local_orp_ipv6_changes(self):
        tc_id = "ipv6_changes move from MH to  L1 orp "
        move_dir = "mh1_to_L1orp"
        host_type = 'ipv6_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_local_orp_ipv4_only(self):
        tc_id = "ipv4_only move from MH to  L1 orp "
        move_dir = "mh1_to_L1orp"
        host_type = 'ipv4_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_local_orp_ipv6_only(self):
        tc_id = "ipv6_only move from MH to  L1 orp "
        move_dir = "mh1_to_L1orp"
        host_type = 'ipv6_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    ###MH to L3 orp###
    def test_mac_move_mh_to_remote_orp_mac_and_ipv4(self):
        tc_id = "Mac+ipv4 move from MH to L3 orp "
        move_dir = "mh1_to_L3orp"
        host_type = 'mac+ipv4'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_remote_orp_mac_and_ipv6(self):
        tc_id = "Mac+ipv6 move from MH to L3 orp "
        move_dir = "mh1_to_L3orp"
        host_type = 'mac+ipv6'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_remote_orp_mac_only(self):
        tc_id = "mac_only move from MH to L3 orp "
        move_dir = "mh1_to_L3orp"
        host_type = 'mac_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_remote_orp_ipv4_changes(self):
        tc_id = "ipv4_changes move from MH to L3 orp "
        move_dir = "mh1_to_L3orp"
        host_type = 'ipv4_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_remote_orp_ipv6_changes(self):
        tc_id = "ipv6_changes move from MH to L3 orp "
        move_dir = "mh1_to_L3orp"
        host_type = 'ipv6_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_remote_orp_ipv4_only(self):
        tc_id = "ipv4_only move from MH to L3 orp "
        move_dir = "mh1_to_L3orp"
        host_type = 'ipv4_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_mh_to_remote_orp_ipv6_only(self):
        tc_id = "ipv6_only move from MH to L3 orp "
        move_dir = "mh1_to_L3orp"
        host_type = 'ipv6_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

     ###Between orphan###
    def test_mac_move_between_orphan_mac_and_ipv4(self):
        tc_id = "Mac+ipv4 move between_orphan "
        move_dir = "L1orp_to_L3orp"
        host_type = 'mac+ipv4'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_orphan_mac_and_ipv6(self):
        tc_id = "Mac+ipv6 move between_orphan "
        move_dir = "L1orp_to_L3orp"
        host_type = 'mac+ipv6'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_orphan_mac_only(self):
        tc_id = "mac_only move between_orphan "
        move_dir = "L1orp_to_L3orp"
        host_type = 'mac_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_orphan_ipv4_changes(self):
        tc_id = "ipv4_changes move between_orphan "
        move_dir = "L1orp_to_L3orp"
        host_type = 'ipv4_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_orphan_ipv6_changes(self):
        tc_id = "ipv6_changes move between_orphan "
        move_dir = "L1orp_to_L3orp"
        host_type = 'ipv6_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_orphan_ipv4_only(self):
        tc_id = "ipv4_only move between_orphan "
        move_dir = "L1orp_to_L3orp"
        host_type = 'ipv4_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_orphan_ipv6_only(self):
        tc_id = "ipv6_only move between_orphan "
        move_dir = "L1orp_to_L3orp"
        host_type = 'ipv6_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    ###L1 orp to Spine orp###
    @pytest.mark.skip
    def test_mac_move_L1orp_to_S3orp_mac_and_ipv4(self):
        tc_id = "Mac+ipv4 move L1orp_to_S3orp "
        move_dir = "L1orp_to_S3orp"
        host_type = 'mac+ipv4'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)
    
    @pytest.mark.skip
    def test_mac_move_L1orp_to_S3orp_mac_and_ipv6(self):
        tc_id = "Mac+ipv6 move L1orp_to_S3orp "
        move_dir = "L1orp_to_S3orp"
        host_type = 'mac+ipv6'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    @pytest.mark.skip
    def test_mac_move_L1orp_to_S3orp_mac_only(self):
        tc_id = "mac_only move L1orp_to_S3orp "
        move_dir = "L1orp_to_S3orp"
        host_type = 'mac_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    @pytest.mark.skip
    def test_mac_move_L1orp_to_S3orp_ipv4_changes(self):
        tc_id = "ipv4_changes move L1orp_to_S3orp "
        move_dir = "L1orp_to_S3orp"
        host_type = 'ipv4_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    @pytest.mark.skip
    def test_mac_move_L1orp_to_S3orp_ipv6_changes(self):
        tc_id = "ipv6_changes move L1orp_to_S3orp "
        move_dir = "L1orp_to_S3orp"
        host_type = 'ipv6_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    @pytest.mark.skip
    def test_mac_move_L1orp_to_S3orp_ipv4_only(self):
        tc_id = "ipv4_only move L1orp_to_S3orp "
        move_dir = "L1orp_to_S3orp"
        host_type = 'ipv4_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    @pytest.mark.skip
    def test_mac_move_L1orp_to_S3orp_ipv6_only(self):
        tc_id = "ipv6_only move L1orp_to_S3orp "
        move_dir = "L1orp_to_S3orp"
        host_type = 'ipv6_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    ### MAc move between es###
    def test_mac_move_between_es_mac_and_ipv4(self):
        tc_id = "Mac+ipv4 move between_es "
        move_dir = "mh1_to_mh1_2"
        host_type = 'mac+ipv4'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_es_mac_and_ipv6(self):
        tc_id = "Mac+ipv6 move between_es "
        move_dir = "mh1_to_mh1_2"
        host_type = 'mac+ipv6'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_es_mac_only(self):
        tc_id = "mac_only move between_es "
        move_dir = "mh1_to_mh1_2"
        host_type = 'mac_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_es_ipv4_changes(self):
        tc_id = "ipv4_changes move between_es "
        move_dir = "mh1_to_mh1_2"
        host_type = 'ipv4_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_es_ipv6_changes(self):
        tc_id = "ipv6_changes move between_es "
        move_dir = "mh1_to_mh1_2"
        host_type = 'ipv6_changes'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_es_ipv4_only(self):
        tc_id = "ipv4_only move between_es "
        move_dir = "mh1_to_mh1_2"
        host_type = 'ipv4_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    def test_mac_move_between_es_ipv6_only(self):
        tc_id = "ipv6_only move between_es "
        move_dir = "mh1_to_mh1_2"
        host_type = 'ipv6_only'
        result = self.verify_mac_move(tc_id, move_dir, host_type)
        vxlan_obj.report_result(result, tc_id)

    @pytest.mark.skip
    def test_mac_freeze(self):
        '''
        
        '''
        tc_id = "mac freeze"
        item = 'mac+ipv4'
        st.banner("Starting test for {}".format(tc_id))
        result_flag = False
        mm_handles = self.get_stream_handles(move_dir = "mac_freeze" , host_type = item)
        tg_handle = mm_handles['tg_handle']
        
        #learn host at location 1
        all_traffic = [mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle'],mm_handles['src3_stream_handle'],mm_handles['src4_stream_handle']]
        l2_handles = [mm_handles['src1_stream_handle'],mm_handles['src2_stream_handle']]
        l3_handles = [mm_handles['src3_stream_handle'],mm_handles['src4_stream_handle']]
        mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['src'])
        st.wait(5)
        mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['l3_src'])
        st.wait(5)
        mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['dest1_handle'])  
        st.wait(5)
        mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['src'])
        st.wait(2)
        mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['l3_src'])
        st.wait(2)
        mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['dest1_handle'])
        st.wait(2)
        # verify no mac move
        #check traffic 
        
        self.send_traffic(tg_handle,all_traffic)
        l2_traffic = self._chk_stats(tg_handle, l2_handles, exp_traffic_on  = mm_handles['src1_stream_handle'])
        l3_traffic = self._chk_stats(tg_handle, l3_handles, exp_traffic_on  = mm_handles['src3_stream_handle'])
        st.banner("l2_traffic : {}, l3_traffic : {} ".format(l2_traffic,l3_traffic))
        self.verify_mac(mm_handles['mm_host']['src1']['mac'], ip_addr = mm_handles['mm_host']['src1']['ip'])
        ###Check type 2 MM###
        if l2_traffic and l3_traffic:
            st.banner(" {} : traffic passed as expected when no host move".format(item))
        else:
            st.banner(" {} : traffic failed when no host move".format(item))
            result_flag = False
            self.cleanup_tgen(mm_handles) 
        seq = 1
        for _cnt in range(1,4):
            #host moves from mh1 to mh2
            mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['dest2_handle'])  
            st.wait(5)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['dest2_handle'])
            st.wait(2)
            self.verify_mac(mm_handles['mm_host']['src2']['mac'], ip_addr = mm_handles['mm_host']['src2']['ip'])
            
            check_mm = vxlan_obj.verify_mac_seq(mm_handles['mm_host']['src2'],mac_move_seq=str(seq),host_local_node=['leaf2','leaf3'],host_type = item)
            
            st.banner("check_mm : {}".format(check_mm))
            if seq < 4:
                seq +=1
            #verify mac move MM2
            #Move host back to original location
            
            mm_handles['tg_handle'].tg_test_control(action="start_protocol", handle=mm_handles['dest1_handle'])  
            st.wait(5)
            mm_handles['tg_handle'].tg_test_control(action="stop_protocol", handle=mm_handles['dest1_handle'])
            st.wait(2)

            self.verify_mac(mm_handles['mm_host']['src1']['mac'], ip_addr = mm_handles['mm_host']['src1']['ip'])
            check_mm = vxlan_obj.verify_mac_seq(mm_handles['mm_host']['src1'],mac_move_seq=str(seq),host_local_node=['leaf0','leaf1'], host_type = item)
            st.banner("check_mm : {}".format(check_mm))
            if seq < 4:
                seq +=1
    
        self.send_traffic(tg_handle,all_traffic)
        l2_traffic = self._chk_stats(tg_handle, l2_handles, exp_traffic_on  = mm_handles['src2_stream_handle'])
        l3_traffic = self._chk_stats(tg_handle, l3_handles, exp_traffic_on  = mm_handles['src4_stream_handle'])
        st.banner("l2_traffic : {}, l3_traffic : {} ".format(l2_traffic,l3_traffic))
        if l2_traffic and l3_traffic:
            st.banner(" {} : traffic passed as expected after mac freeze".format(item))
            result_flag = True
        else:
            st.banner(" {} : traffic failed after mac freeze".format(item))
        #tgen_cleanup
        self.cleanup_tgen(mm_handles)
        vxlan_obj.report_result(result_flag, tc_id)
     
        
@pytest.mark.usefixtures("tgen_health_check_class")
class TestVxlanNegativeTriggers():

    def extract_lines_after_start(self,text, start_string, num_lines=10):
        # Pattern to match the start string followed by the next `num_lines` lines
        pattern = re.compile(r"({})\s*((?:.*\n){{{}}})".format(re.escape(start_string), num_lines))

        # Search for the pattern in the given text
        match = pattern.search(text)

        if match:
            # Return the matched lines
            return match.group(2)
        else:
            return None  # Return None if the start string is not found
    
    def test_duplicate_esid(self):
        '''

        '''
        flag = True
        dut = 'leaf0'
        ref_esid = test_cfg['leaf0']['port_channels'][0]['evpn_esi']
        match = "Error: The ESI '{}' is already in use".format(ref_esid)
        #config sytem mac
        pc_obj.create_portchannel(dut, "PortChannel10")
        cmd_1 = "sudo config interface sys-mac add PortChannel10 00:44:33:22:99:99\n"
        out_1 = st.config(dut, cmd_1, skip_error_check=True)
        #config dup esid
        cmd_2 = "sudo config interface evpn-esi add PortChannel10 {}\n".format(ref_esid)
        out_2 = st.config(dut, cmd_2, skip_error_check=True)
        if match in out_2:
            st.banner("Test passed , duplicate esid is not allowed")
        else:
            st.banner("Test failed , duplicate esid is allowed")
            flag = False
        out_3 = basic_obj.get_show_run_all(dut)
        result = self.extract_lines_after_start(out_3, "EVPN_ETHERNET_SEGMENT", num_lines=20)
        matches = re.findall(ref_esid,result)
        if len(matches) == 1:
            st.banner("Test passed , duplicate esid is not allowed, running config don't have entry")
        else:
            st.banner("Test failed , duplicate esid is allowed, running config have multiple entry")
            flag = False
        #unconfig
        cmd_1 = "sudo config interface sys-mac remove PortChannel10 00:44:33:22:99:99\n"
        st.config(dut, cmd_1, skip_error_check=True)
        pc_obj.delete_portchannel(dut, "PortChannel10")
        vxlan_obj.report_result(flag)
         

    def test_reserved_esid(self):
        flag = True
        dut = 'leaf0'
        match = "Error: Not allowed to configure a reserved ESI"
        ref_esid = ["00:00:00:00:00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff"]
        pc_obj.create_portchannel(dut, "PortChannel10")
        cmd_1 = "sudo config interface sys-mac add PortChannel10 00:44:33:22:99:99\n"
        out_1 = st.config(dut, cmd_1, skip_error_check=True)
        #config reserved esid
        for item in ref_esid:
            cmd_2 = "sudo config interface evpn-esi add PortChannel10 {}\n".format(item)
            out_2 = st.config(dut, cmd_2, skip_error_check=True)
            if match in out_2:
                st.banner("Test passed , {} esid is not allowed").format(item)
            else:
                st.banner("Test failed , {} esid is allowed").format(item)
                flag = False
            out_3 = basic_obj.get_show_run_all(dut)
            result = self.extract_lines_after_start(out_3, "EVPN_ETHERNET_SEGMENT", num_lines=20)
            matches = re.findall(item,result)
            if len(matches) == 0:
                st.banner("Test passed , {} esid is not allowed, running config don't have entry").format(item)
            else:
                st.banner("Test failed , {} esid is allowed, running config have entry").format(item)
                flag = False
        #unconfig
        cmd_1 = "sudo config interface sys-mac remove PortChannel10 00:44:33:22:99:99\n"
        st.config(dut, cmd_1, skip_error_check=True)
        pc_obj.delete_portchannel(dut, "PortChannel10")
        vxlan_obj.report_result(flag)

@pytest.fixture(scope="class")
def setup_devices_for_timer_check():
    '''
    setup vlan and devices
    '''
    ### ADD DUT CONFIGS ###
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    
    int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
    dut_int_data = vxlan_obj.get_dut_interfaces(vars)
    vrf_id = "Vrf101"
    for node in leaf_nodes:
        #add l2vni
        leaf_data = test_cfg['testcases']['mac_move_test'][node]
        config_out = vxlan_obj.generate_l2vni_config(leaf_data,int_config_dict[node]['l2vni_int'],dut_int_data[node])
        vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
        #bindvrf and  add svi
        for vlan, info in leaf_data['host_info'].items():
            ref_int = "Vlan"+str(vlan)
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =ref_int)
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=info['v4_svi'], subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=info['v6_svi'], subnet='64', family="ipv6", config='add', skip_error=True)
            cmd = "sudo config vlan static-anycast-gateway enable {}\n".format(vlan)
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
    
    yield 
    ###CLEANUP DUT CONFIGS###
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
    dut_int_data = vxlan_obj.get_dut_interfaces(vars)
    #unbind vlan from vrf
    for node in leaf_nodes:
        leaf_data = test_cfg['testcases']['mac_move_test'][node]
        for vlan, info in leaf_data['host_info'].items():
            cmd = "sudo config vlan static-anycast-gateway disable {}\n".format(vlan)
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            ref_int = "Vlan"+str(vlan)
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =ref_int,config = 'no')
        ##remove l2vni
        config_out = vxlan_obj.generate_l2vni_config(leaf_data,int_config_dict[node]['l2vni_int'],dut_int_data[node], mode='del')
        vxlan_obj.config_dut(node, 'sonic', config_out, add=True)


@pytest.mark.usefixtures("tgen_health_check_class", "setup_devices_for_timer_check")
class TestVxlanEvpnTimerChecks():
    @pytest.fixture
    def setup_tgen(self):
        #Config Tgen on MH1
        topo_handles = tgen_handles["topo_handles"]
        device_handles = {}
        for key, value in topo_handles['leaf0'].items():
            if 'PortChannel' in key:
                port_handle = value['port_handle']
                tg_handle = value['tg_handle']
                topo_handle = value['topology_handle']
        device_group_1 = tg_handle.tg_topology_config(
                        topology_handle= topo_handle,
                        device_group_name= """Timer check v4 Device group""",
                        device_group_multiplier = "10",
                        device_group_enabled= "1"
                        )
        deviceGroup_handle_1 = device_group_1['device_group_handle']
        device_handles['ipv4'] = deviceGroup_handle_1
        device_group_2 = tg_handle.tg_topology_config(
                        topology_handle= topo_handle,
                        device_group_name= """Timer check v6 Device group""",
                        device_group_multiplier = "10",
                        device_group_enabled= "1"
                        )
        deviceGroup_handle_2 = device_group_2['device_group_handle']
        device_handles['ipv6'] = deviceGroup_handle_2
        ###Creating ethernet stack for the Device Group###
        l2_protocol_1 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack #{}""".format('910'),
            protocol_handle= deviceGroup_handle_1,mtu= "1500",
            src_mac_addr= "00.00.00.91.04.01",
            src_mac_addr_step= "00.00.00.00.00.01", 
            vlan=1,
            vlan_id="910", 
            vlan_id_step=0,
            vlan_id_count=1
            )
        ethernet_handle_1 = l2_protocol_1['ethernet_handle']

        l2_protocol_2 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack #{}""".format('910'),
            protocol_handle= deviceGroup_handle_2,mtu= "1500",
            src_mac_addr= "00.00.00.91.06.01",
            src_mac_addr_step= "00.00.00.00.00.01", 
            vlan=1,
            vlan_id="910", 
            vlan_id_step=0,
            vlan_id_count=1
            )
        ethernet_handle_2 = l2_protocol_2['ethernet_handle']
        ### Creating IPv4 Stack for the Device Group###
        l3_protocol_1 = tg_handle.tg_interface_config(
            protocol_name= """v4 Stack #910""",
            protocol_handle=ethernet_handle_1,
            ipv4_resolve_gateway= "1",
            gateway= "91.91.91.1",
            gateway_step= "0.0.0.0",
            intf_ip_addr = "91.91.91.91",
            intf_ip_addr_step= "0.0.0.1"
            )
        ipv4_handle = l3_protocol_1['ipv4_handle']
        st.log("ipv4_handle-->{}".format(ipv4_handle))

        ### Creating IPv6 Stack for the Device Group###
        l3_protocol_2 = tg_handle.tg_interface_config(
                        protocol_name= """v6 Stack #910""",
                        protocol_handle=ethernet_handle_2,
                        ipv6_resolve_gateway= "1",
                        ipv6_gateway= '91:91:91::1',
                        ipv6_gateway_step = "0::0",
                        ipv6_intf_addr = '91:91:91::91',
                        ipv6_intf_addr_step = '0::1'
                        )
        ipv6_handle = l3_protocol_2['ipv6_handle']
        device_handles['tg_handle'] = tg_handle

        yield device_handles

        st.log("self.cleanup_tgen")
        for key, value in device_handles.items():
            if key != 'tg_handle':
                vxlan_obj.delete_device_groups(device_handles['tg_handle'], value)

    def test_mac_holdime(self, setup_tgen):
        '''
        verify mac ageout timer
        learn host
        wait till ageout 
        dynamic learnt hosts should flush
        static learnt host will wait till mac-holdtime and flush
        http://10.29.158.34/run_logs/rraguraj/rraguraj/up_link_1/results_2025_02_02_13_50_32_stats.html
        
        '''
        selected_duts = ['leaf0', 'leaf1']
        mac_age_time =  vxlan_obj.get_mac_agetime('leaf0')
        cli_output = st.show('leaf0', "show evpn", skip_tmpl=True)
        evpn_timers = vxlan_obj.get_evpn_timers('leaf0')
        #change mac aging to 100 seconds
        vxlan_obj.change_fdb_ageout(ageout_time = "100")
        mac_age_time =  vxlan_obj.get_mac_agetime('leaf0')
        st.banner("mac aging set to {}".format(mac_age_time))
        #Learn host
        
        setup_tgen['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", handle=setup_tgen['ipv4'])
        st.wait(5)
        setup_tgen['tg_handle'].tg_test_control(action="start_protocol", handle=setup_tgen['ipv4'])
        st.wait(5)
        setup_tgen['tg_handle'].tg_test_control(action="stop_protocol", handle=setup_tgen['ipv4'])
        st.wait(2)
        leaf0_out = st.show('leaf0', "show mac -l", skip_tmpl=False)
        leaf1_out = st.show('leaf1', "show mac -l", skip_tmpl=False)
        leaf0_ref_mac_list = []
        
        leaf1_ref_mac_list = [] 
        for item in leaf0_out:
            if "00:00:00:91:04" in item['macaddress']:
                if item['type'] != 'Static' and item['type'] != '':
                    leaf0_ref_mac_list.append(item['macaddress'])

        st.banner("Leaf0 Dynamic {}".format(leaf0_ref_mac_list))
        for item in leaf1_out:
            if "00:00:00:91:04" in item['macaddress']:
                if item['type'] != 'Dynamic' and item['type'] != '':
                    leaf1_ref_mac_list.append(item['macaddress'])
        st.banner("Leaf1 static {}".format(leaf1_ref_mac_list))
        if len(leaf0_ref_mac_list) != 0:
            if sorted(leaf0_ref_mac_list) == sorted(leaf1_ref_mac_list): 
                st.log("mac is dynamic/static as expected")
        else:
            st.log("mac is not dynamic/static as expected")
        #wait for mac ageout
        st.wait(mac_age_time)
        leaf0_out = st.show('leaf0', "show mac -l", skip_tmpl=False)
        leaf1_out = st.show('leaf1', "show mac -l", skip_tmpl=False)
        leaf0_age_out_list = []
        for item in leaf0_out:
            if "00:00:00:91:04" in item['macaddress']:
                if item['type'] != 'Static' and item['type'] != '':
                    leaf0_age_out_list.append(item['macaddress'])
        st.log(leaf0_age_out_list)
        if len(leaf0_age_out_list) > 0:
            st.banner("local mac ageout failed")
            vxlan_obj.report_result('False')
        else:
            st.banner("local mac ageout passed")

        #Check remote mac flushed
        remote_flag = True
        for dut in st.get_dut_names():
            if "leaf" in dut and dut not in selected_duts:
                mac_list = st.show(dut, "show mac -l", skip_tmpl=False)
                for item in mac_list:
                    if item['macaddress'] in leaf0_ref_mac_list:
                        remote_flag = False
                        st.banner("{} address present in {} whoch is not expected ".format(item['macaddress'],dut))
        if remote_flag:
            st.banner("remote mac ageout Passed")
        else:
            st.banner("remote mac ageout Failed")
            vxlan_obj.report_result('False')
                        
        st.wait(int(evpn_timers['mac-holdtime']))
        leaf1_out = st.show('leaf1', "show mac -l", skip_tmpl=False)
        leaf1_age_out_list = []
        for item in leaf1_out:
            if "00:00:00:91:04" in item['macaddress']:
                if item['type'] != 'Dynamic' and item['type'] != '':
                    leaf1_age_out_list.append(item['macaddress'])
        st.log(leaf1_age_out_list)
        if len(leaf1_age_out_list) > 0:
            st.banner("mac holdtime test failed")
            st.log("following mac present after holdtime expired {}".format(leaf1_age_out_list))
            vxlan_obj.report_result('False')
        else:
            st.banner(("mac holdtime test passed"))
            vxlan_obj.report_result('True')

    def test_startup_delay(self):
        '''
        http://10.29.158.34/run_logs/rraguraj/rraguraj/up_link_3/results_2025_02_02_18_00_10_stats.html

        '''
        leaf0_interfaces = vxlan_obj.get_config_interfaces_list(vars)['leaf0']['underlay']
        evpn_timers = vxlan_obj.get_evpn_timers('leaf0')
        default_startup_delay = int(evpn_timers['startup-delay'])
        #check uplink-cfg-cnt
        if int(evpn_timers['uplink-cfg-cnt']) == len(leaf0_interfaces):
            st.log("uplink tracking is configured")  
        elif int(evpn_timers['uplink-cfg-cnt']) == 0:
            st.log("uplink tracking is not configured")
        else:
            st.log("uplink tracking is not configured on some of the uplinks")
        pc_id = "PortChannel"+str(test_cfg['leaf0']['port_channels'][0]['port_channel_num'])
        #check Portchannel status
        verify_pc = pc_obj.verify_portchannel('leaf0', portchannel_name = pc_id)
        if not verify_pc:
            st.banner("Portchannel not up : Not expected")
            vxlan_obj.report_result(False)
            
        flag = True
        for delay_timer in [default_startup_delay, 30, 0]:
            st.banner("Configuring delay timer on leaf0  : {} seconds".format(delay_timer))
            if delay_timer != default_startup_delay:
                st.config('leaf0', "evpn mh startup-delay "+str(delay_timer), type='vtysh')
            #check PO interface status
            out1 = intf_obj.interface_status_show('leaf0', interfaces=[pc_id])
            if out1[0]['admin'] == 'up' and out1[0]['oper'] == 'up':
                st.banner("Portchannel is up as expected before shutting uplinks")
            else:
                st.banner("Portchannel is down before shutting uplinks : not expected")
                flag = False

            for interface in leaf0_interfaces:
                intf_obj.interface_shutdown('leaf0',interface)
            out2 = intf_obj.interface_status_show('leaf0', interfaces=[pc_id])
            if out2[0]['admin'] == 'down':
                st.banner("Portchannel went down as expected")
            else:
                st.banner("Portchannel didn't go down as expected")
                flag = False
            for interface in leaf0_interfaces:
                intf_obj.interface_noshutdown('leaf0',interface)
            #show evpn
            st.show('leaf0', "show evpn", type='vtysh', skip_tmpl=True)
            st.wait(delay_timer + test_cfg['global']['plus_bringup_time'])
            out3 = intf_obj.interface_status_show('leaf0', interfaces=[pc_id])
            if out3[0]['admin'] == 'up' and out3[0]['oper'] == 'up':
                st.banner("Portchannel came up as expected after startup delay")
            else:
                st.banner("Portchannel didn't come up afterstartup delay")
                flag = False

        vxlan_obj.report_result(flag)  

@pytest.mark.usefixtures("tgen_health_check_class", "setup_df_ndf_failure")
class TestVxlanDfNdfFailure():

    def test_mh_df_node_failure(self, pause_run):
        """
        Testcase: Solution_test:MH:152 :  Verify DF election with Node Failures of original -DF
        Description:
            1)Bring up the Multi-homing profile
            2)Reboot original NDF which is L1 .
            3)Verify that other leaf0 (DF) of dual homed host stays DF and no traffic impact.
            4)Verify no core/crash
        Steps:
            start continuous traffic steam
            reload df = leaf 0
            check traffic
            verify basic checks 
        """
        tc_id = 'test_mh_df_node_failure'
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params('test_df_ndf_node_failure')
        df_dut = tc_cfg['df_dut']
        result_str = ''

        st.banner('Testcase : Verify DF election with Node Failures of original DF ({})'.format(tc_id))
        st.log('Starting traffic')
        try:
            vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], 
                                    regenerate_traffic_items=True, action='start',
                                    stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        except Exception as err:
            st.error('Traffic stream start error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

        st.log('Rebooting DF node : {}'.format(df_dut))
        vxlan_obj.config_dut(df_dut,'bgp', 'do write') 
        docker_cnt = basic_obj.get_and_match_docker_count(df_dut)
        reboot_obj.dut_reboot(df_dut)
        restore_helper_file(df_dut)
        st.wait(60)
        #check docker status
        st.log('Checking if dockers are up after reload on DF node : {}'.format(df_dut))
        if not poll_wait(basic_obj.verify_docker_status, 180, df_dut, 'Exited'):
            vxlan_obj.report_result(False, tc_id, 'Docker status not up after reboot')

        st.log('Checking docker count reload on DF node : {}'.format(df_dut))
        if not poll_wait(basic_obj.get_and_match_docker_count, 180, df_dut, docker_cnt):
            vxlan_obj.report_result(False, tc_id, 'Not all dockers are up after reboot. Expected {}'.format(docker_cnt))

        #check vtep status 
        max = 5
        for cntr in range(1,max+1):
            vtep_state = vxlan_obj.verify_vtep(test_cfg['nodes']['leaf'])
            if vtep_state:
                st.log('All remote vteps are found')
                break
            st.log('Not all or no remote vteps are found. Retry {}/{}'.format(cntr, max+1))
            st.wait(60)
        else:
            vxlan_obj.report_result(False, tc_id, 'Not all vteps are found after reboot.')

        st.log('Checking status of continuous traffic after reboot')
        if vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], action='check', min_perc=99.6):
            st.banner('Continuous Traffic check passed')
        else:
            log = 'Continuous Traffic check failed'
            st.banner(log)
            result_str += '{}\n'.format(log)
        ### add base verifications here
        st.log('Checking status of all traffic reboot')
        if pf.verify_traffic(tgen_handles, bum=True):
            st.banner('All Traffic Check Passed')
        else:
            log = 'All Traffic check Failed'
            st.banner(log)
            result_str += '{}\n'.format(log)

        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)

    def test_mh_ndf_node_failure(self, pause_run):
        """
        Testcase: Solution_test:MH:152 :  Verify DF election with Node Failures of original Non-DF
        Description:
            1)Bring up the Multi-homing profile
            2)Reboot original NDF which is L1 .
            3)Verify that other leaf0 (DF) of dual homed host stays DF and no traffic impact.
            4)Verify no core/crash
        Steps:
            start continuous traffic steam
            reload ndf = leaf 1
            check traffic
            verify basic checks 
        """
        tc_id = 'test_mh_ndf_node_failure'
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params('test_df_ndf_node_failure')
        ndf_dut = tc_cfg['ndf_dut']
        result_str = ''

        st.banner('Testcase : Verify DF election with Node Failures of original Non-DF ({})'.format(tc_id))
        st.log('Starting traffic')
        try:
            vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], 
                                    regenerate_traffic_items=True, action='start',
                                    stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        except Exception as err:
            st.error('Traffic stream start error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

        st.log('Rebooting NDF node : {}'.format(ndf_dut))
        vxlan_obj.config_dut(ndf_dut,'bgp', 'do write') 
        docker_cnt = basic_obj.get_and_match_docker_count(ndf_dut)
        reboot_obj.dut_reboot(ndf_dut)
        restore_helper_file(ndf_dut)
        #todo -->Check whether this wait is needed
        st.wait(60)

        #check docker status
        st.log('Checking if dockers are up after reload on NDF node : {}'.format(ndf_dut))
        if not poll_wait(basic_obj.verify_docker_status, 180, ndf_dut, 'Exited'):
            vxlan_obj.report_result(False, tc_id, 'Docker status not up after reboot')

        st.log('Checking docker count reload on NDF node : {}'.format(ndf_dut))
        if not poll_wait(basic_obj.get_and_match_docker_count, 180, ndf_dut, docker_cnt):
            vxlan_obj.report_result(False, tc_id, 'Not all dockers are up after reboot. Expected {}'.format(docker_cnt))

        #check vtep status 
        max = 5
        for cntr in range(1,max+1):
            vtep_state = vxlan_obj.verify_vtep(test_cfg['nodes']['leaf'])
            if vtep_state:
                st.log('All remote vteps are found')
                break
            st.log('Not all or no remote vteps are found. Retry {}/{}'.format(cntr, max+1))
            st.wait(60)
        else:
            vxlan_obj.report_result(False, tc_id, 'Not all vteps are found after reboot.')

        

        st.log('Checking status of continuous traffic after reboot')
     
        if vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], action='check', min_perc=99.6):
            st.banner('Continuous Traffic check passed')
        else:
            log = 'Continuous Traffic check failed'
            st.banner(log)
            result_str += '{}\n'.format(log)

        ### todo add base verifications here
        st.log('Checking status of all traffic reboot')
        if pf.verify_traffic(tgen_handles, bum=True):
            st.banner('All Traffic Check Passed')
        else:
            log = 'All Traffic check Failed'
            st.banner(log)
            result_str += '{}\n'.format(log)

        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)

    def test_mh_df_switchover(self, pause_run, cleanup_DF_preference):
        """
        Testcase: Solution_test:MH:152 :  Verify DF election with Node Failures of original Non-DF
        Description:
            1)Bring up the Multihoming profile .
            2)The DF election happens based on DF preference value . 
            3)If DF pref value is same , the DF election happens based on lower Vtep IP .
            4)Change the DF pref value and check how long does it take to change the DF .
            5)Verify DF election process (V mod N). Have 2 Leaf and Vlan as 100 and verify that leaf with 
            lower IP(say L0) is DF
            6)change Vlan to 101, Leaf with higher IP should be DF based on formula (V mod N)
            7)change higher IP of L0 to lower and  and verify if DF changes
            Verify the DF election wait time before a DF is elected ."

        Steps:
            1)Change DF preference on DF leaf 0 . 
            2)Check Leaf 1 is new DF
            3)Verify no traffic loss
            1)remove DF preference on DF leaf 0 . 
            3)Verify no traffic loss
        """
        tc_id = 'test_mh_df_switchover'
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params('test_df_ndf_node_failure')
        df_dut = tc_cfg['df_dut']
        ndf_dut = tc_cfg['ndf_dut']
        tc_cfg['df_pref'] = 100
        tc_cfg['ndf_pref'] = 10
        tc_cfg['interface'] = 'PortChannel{}'.format(tc_cfg['port_channel_num'])
        result_str = ''
        tc_cfg['uncfg'] = False

        st.banner('Testcase : Verify DF election with DF switchover ({})'.format(tc_id))
        st.log('Starting traffic')
        try:
            vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], 
                                    regenerate_traffic_items=True, action='start',
                                    stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        except Exception as err:
            st.error('Traffic stream start error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

        st.log('Changing DF prority on DF node : {}'.format(df_dut))
        st.config(df_dut, 'interface {} \nevpn mh es-df-pref {}\n\
                  end\nexit\n'.format(tc_cfg['interface'], tc_cfg['ndf_pref']), type='vtysh')

        st.log('Changing DF prority on NDF node : {}'.format(ndf_dut))
        st.config(ndf_dut, 'interface {} \nevpn mh es-df-pref {}\n\
                  end\nexit\n'.format(tc_cfg['interface'], tc_cfg['df_pref']), type='vtysh')
        tc_cfg['uncfg'] = True
        st.wait(10)

        st.log('Verify DF state on {}'.format(df_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(df_dut)
            for es_data in exp_data:
                if es_data['es_if'] == tc_cfg['interface']:
                    es_data['type'] = 'LRN'
                    break
            vxlan_obj.verify_evpn_es(df_dut, exp_data, vl_retries=3)
            st.log('DF state verification on {} : Pass'.format(df_dut))
        except vxlan_obj.CompareFailed as err:
            log = 'DF state verification on {} : Fail'.format(df_dut)
            st.log(log)
            result_str += '{}\n'.format(log)

        st.log('Verify EVPN ES peering state on {}'.format(ndf_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(ndf_dut)
            for es_data in exp_data:
                if es_data['es_if'] == tc_cfg['interface']:
                    es_data['type'] = 'LR'
                    break
            vxlan_obj.verify_evpn_es(ndf_dut, exp_data, vl_retries=3)
            st.log('DF state verification on {} : Pass'.format(ndf_dut))
        except vxlan_obj.CompareFailed as err:
            log = 'DF state verification on {} : Fail'.format(ndf_dut)
            st.log(log)
            result_str += '{}\n'.format(log)

        st.log('Checking status of continuous traffic after DF change')
        if vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], action='check'):
            st.banner('Continuous Traffic check passed')
        else:
            log = 'Continuous Traffic check failed after DF change'
            st.banner(log)
            result_str += '{}\n'.format(log)

        ### add base verifications here
        st.log('Checking status of all traffic after DF change')
        if pf.verify_traffic(tgen_handles, bum=True):
            st.banner('All Traffic Check Passed')
        else:
            log = 'All Traffic check Failed after DF change'
            st.banner(log)
            result_str += '{}\n'.format(log)

        st.wait(120)
        st.log('Restoring DF and NDF nodes')
        st.log('Starting traffic')
        try:
            vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], 
                                    regenerate_traffic_items=True, action='start',
                                    stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        except Exception as err:
            st.error('Traffic stream start error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

        st.log('Removing DF prority on NDF node : {}'.format(ndf_dut))
        st.config(ndf_dut, 'interface {} \nno evpn mh es-df-pref {}\n\
                  end\nexit\n'.format(tc_cfg['interface'], tc_cfg['df_pref']), type='vtysh')
        st.log('Removing DF prority on DF node : {}'.format(df_dut))
        st.config(df_dut, 'interface {} \nno evpn mh es-df-pref {}\n\
                  end\nexit\n'.format(tc_cfg['interface'], tc_cfg['ndf_pref']), type='vtysh')
        tc_cfg['uncfg'] = False

        st.log('Verify DF state on {}'.format(df_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(df_dut)
            vxlan_obj.verify_evpn_es(df_dut, exp_data, vl_retries=3)
            st.log('DF state verification on {} : Pass'.format(df_dut))
        except vxlan_obj.CompareFailed as err:
            log = 'DF state verification on {} : Fail'.format(df_dut)
            st.log(log)
            result_str += '{}\n'.format(log)

        st.log('Verify EVPN ES peering state on {}'.format(ndf_dut))
        try:
            exp_data = vxlan_obj.get_expected_evpn_es(ndf_dut)
            vxlan_obj.verify_evpn_es(ndf_dut, exp_data, vl_retries=3)
            st.log('DF state verification on {} : Pass'.format(ndf_dut))
        except vxlan_obj.CompareFailed as err:
            log = 'DF state verification on {} : Fail'.format(ndf_dut)
            st.log(log)
            result_str += '{}\n'.format(log)

        st.log('Checking status of continuous traffic after DF restored')
        if vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], action='check'):
            st.banner('Continuous Traffic check passed')
        else:
            log = 'Continuous Traffic check failed after DF restored'
            st.banner(log)
            result_str += '{}\n'.format(log)

        ### add base verifications here
        st.log('Checking status of all traffic after DF restored')
        if pf.verify_traffic(tgen_handles, bum=True):
            st.banner('All Traffic Check Passed')
        else:
            log = 'All Traffic check Failed after DF restored'
            st.banner(log)
            result_str += '{}\n'.format(log)

        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)

    def test_mh_sh_migration(self):
        """
        Testcase: Solution_test:MH:283 : Multi-Homing host to Single-Homing host migration
        Description:
        Steps:
            1)Shut down PortChannel port on leaf1 to simulate the link is down
            2)Then Multil-Homing will become Single-Homing
            3)Verify traffic streams
            4)Verify CLI

        Testcase: Solution_test:MH:282 : Single-Homing host to Multi-Homing host migration
        Description:
        Steps:
            1)Bring back PortChannel port on leaf1 to simulate the link is up
            2)Then Single-Homing will become Multil-Homing
            3)Verify traffic streams
            4)Verify CLI
        """

        tc_id = 'test_mh_sh_migration'
        tc_cfg_name = 'test_df_ndf_node_failure'
        test_cfg['tc_id'] = tc_cfg_name
        tc_cfg = vxlan_obj.get_tc_params(tc_cfg_name)
        dut = tc_cfg["mh_sh_dut"]
        dut_id = vxlan_obj.get_device_id(dut,vars)
        int_id = dut_id + tc_cfg['mh_sh_port']
        intfs = [vars[int_id]] + vxlan_obj.get_config_interfaces_list(vars)[dut]['underlay']
        result_str = ''
        other_dut = []
        for d in test_cfg['nodes']['l2l3vni']:
            if ("leaf" in d) and (dut not in d):
                other_dut.append(d)

        st.banner("Testcase MH:283: moving Multi-Homing host to Single-Homing host")

        # Set ignore link status 1
        tg_handle, port_handle = tgapi.get_handle_byname(vxlan_obj.get_peer_port_id(int_id, vars, dut))
        tg_handle.tg_interface_config(mode='modify', port_handle=port_handle, ignore_link=1)

        # start traffic
        try:
            vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'],
                                    regenerate_traffic_items=True, action='start',
                                    stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        except Exception as err:
            st.error('Traffic stream start error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

        st.log('Shutting down interfaces {} on {}'.format(intfs, dut))
        for intf in intfs:
            intf_obj.interface_shutdown(dut=dut, interfaces=intf)
        st.wait(5)

        # check CLI of other leafs
        st.log('Verify status on {} after shutdown'.format(dut))
        for intf in intfs:
            if not intf_obj.verify_interface_status(dut, intf, 'admin', 'down'):
                log = 'Shutdown {} {} ports failed'.format(dut, intf)
                st.banner(log)
                result_str += '{}\n'.format(log)
        st.log('Show cli output on {}'.format(other_dut))
        vxlan_obj.get_cli_out(other_dut)

        # stop traffic
        st.log('Checking status of continuous traffic after {} ports down.'.format(dut))
        if vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], action='check'):
            st.banner('Continuous Traffic check passed')
        else:
            log = 'Continuous Traffic check failed after {} ports down'.format(dut)
            st.banner(log)
            result_str += '{}\n'.format(log)
        st.wait(120)

        st.banner("Testcase MH:282: moving Single-Homing host to Multi-Homing host")
        # start traffic
        try:
            vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'],
                                    regenerate_traffic_items=True, action='start',
                                    stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        except Exception as err:
            log = 'Traffic stream start error: {}'.format(str(err))
            st.banner(log)
            result_str += '{}\n'.format(log)

        st.log('Starting up interfaces {} on {}'.format(intfs, dut))
        for intf in intfs:
            intf_obj.interface_noshutdown(dut=dut, interfaces=intf)
        st.wait(5)

        # check CLI of other leafs
        st.log('Verify status on {} after startup'.format(dut))
        for intf in intfs:
            if not intf_obj.verify_interface_status(dut, intf, 'admin', 'up'):
                log = 'Startup {} {} ports failed'.format(dut, intf)
                st.banner(log)
                result_str += '{}\n'.format(log)
        st.log('Show cli output on {}'.format(other_dut))
        vxlan_obj.get_cli_out(other_dut)

        # stop traffic
        st.log('Checking status of continuous traffic after {} ports up.'.format(dut))
        if vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], action='check'):
            st.banner('Continuous Traffic check passed')
        else:
            log = 'Continuous Traffic check failed after {} ports up'.format(dut)
            st.banner(log)
            result_str += '{}\n'.format(log)

        ### add base verifications here
        st.log('Checking status of all traffic after vlan restored')
        if pf.verify_traffic(tgen_handles, bum=True):
            st.banner('All Traffic Check Passed')
        else:
            log = 'All Traffic check Failed after vlan restored'
            st.banner(log)
            result_str += '{}\n'.format(log)

        # Set ignore link status 0
        tg_handle.tg_interface_config(mode='modify', port_handle=port_handle, ignore_link=0)

        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)

    @pytest.fixture
    def cleanup_DF_preference(self):
        """
        DUT DF preference unconfig
        """

        yield

        tc_cfg = vxlan_obj.get_tc_params('test_df_ndf_node_failure')
        if tc_cfg['uncfg']:
            df_dut = tc_cfg['df_dut']
            ndf_dut = tc_cfg['ndf_dut']
            st.log('Removing DF prority on DF node : {}'.format(df_dut))
            st.config(df_dut, 'interface {} \nno evpn mh es-df-pref {}\n\
                    end\nexit\n'.format(tc_cfg['interface'], tc_cfg['ndf_pref']), type='vtysh')

            st.log('Removing DF prority on NDF node : {}'.format(ndf_dut))
            st.config(ndf_dut, 'interface {} \nno evpn mh es-df-pref {}\n\
                    end\nexit\n'.format(tc_cfg['interface'], tc_cfg['df_pref']), type='vtysh')

    @pytest.fixture(scope="class")
    def setup_df_ndf_failure(self):
        """
            Fixture to setup/teardown traffic streams to test df failure testcases
        """
        tc_id = 'test_df_ndf_node_failure'
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        df_dut = tc_cfg['df_dut']
        tgen_port_channel = find_tgen_port_name(tc_cfg['port_channel_num'], df_dut)
        if not tgen_port_channel:
            vxlan_obj.report_result(False, tc_id, 'Port channel {} not configured on TGEN'.format(tc_cfg['port_channel_num']))
        result = True

        l2_endpoints = dict()
        l3_endpoints = dict()
        cntr = 1
        for l2_endpoint_info in tc_cfg['l2_endpoints']:
            dst_tgen_port = find_tgen_port_name(l2_endpoint_info['dst_int'], l2_endpoint_info['dst_node'])
            l2_endpoints['traffic_item_{}'.format(cntr)] = {
                                'dst_int': dst_tgen_port,
                                'dst_vlan': l2_endpoint_info['vlan'],
                                'src_int': tgen_port_channel,
                                'src_vlan': l2_endpoint_info['vlan']
            }
            cntr += 1

        for l3_endpoint_info in tc_cfg['l3_endpoints']:
            dst_tgen_port = find_tgen_port_name(l3_endpoint_info['dst_int'], l3_endpoint_info['dst_node'])
            l3_endpoints['traffic_item_{}'.format(cntr)] = {
                                'dst_int': dst_tgen_port,
                                'dst_vlan': l3_endpoint_info['dst_vlan'],
                                'src_int': tgen_port_channel,
                                'src_vlan': l3_endpoint_info['src_vlan']
            }
            cntr += 1
        """ Example
        l2_endpoints = {'traffic_item_1': {'dst_int': 'T1D8P1', 
                                           'dst_vlan': 30, 
                                           'src_int': 'PortChannel1_D6D5', 
                                           'src_vlan': 30}, 
                        'traffic_item_2': {'dst_int': 'PortChannel3_D8D7', 
                                           'dst_vlan': 4, 
                                           'src_int': 'PortChannel1_D6D5', 
                                           'src_vlan': 4}}
        """
        tc_cfg['stream_handles'] = {'DF_NDF': {}}
        cntr = 1
        vxlan_obj.start_stop_protocols(tgen_handles['tg_handle'], 'stop')
        try:
            stream_id = 'DFNDF_L2'
            streams = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v4_device_handles'],
                                                    endpoints=l2_endpoints,
                                                    topo_handles=tgen_handles['topo_handles'],
                                                    name_prfx=stream_id, transmit_mode='continuous',
                                                    rate_percent=test_cfg['global']['bum']['rate_percent'], 
                                                    )
            for stream_cntr, stream_info in streams.items():
                tc_cfg['stream_handles']['DF_NDF'][cntr] = stream_info
                cntr += 1
            stream_id = 'DFNDF_L2'
            streams = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v6_device_handles'],
                                                    endpoints=l2_endpoints, version = 'ipv6',
                                                    topo_handles=tgen_handles['topo_handles'],
                                                    name_prfx=stream_id, transmit_mode='continuous',
                                                    rate_percent=test_cfg['global']['bum']['rate_percent'], 
                                                    )
            for stream_cntr, stream_info in streams.items():
                tc_cfg['stream_handles']['DF_NDF'][cntr] = stream_info
                cntr += 1
            stream_id = 'DFNDF_L3'
            streams = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v4_device_handles'],
                                                    endpoints=l3_endpoints,
                                                    topo_handles=tgen_handles['topo_handles'],
                                                    name_prfx=stream_id, transmit_mode='continuous',
                                                    rate_percent=test_cfg['global']['bum']['rate_percent'], 
                                                    )
            for stream_cntr, stream_info in streams.items():
                tc_cfg['stream_handles']['DF_NDF'][cntr] = stream_info
                cntr += 1
            stream_id = 'DFNDF_L3'
            streams = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v6_device_handles'],
                                                    endpoints=l3_endpoints, version = 'ipv6',
                                                    topo_handles=tgen_handles['topo_handles'],
                                                    name_prfx=stream_id, transmit_mode='continuous',
                                                    rate_percent=test_cfg['global']['bum']['rate_percent'], 
                                                    )
            for stream_cntr, stream_info in streams.items():
                tc_cfg['stream_handles']['DF_NDF'][cntr] = stream_info
                cntr += 1

            st.wait(30)

            ### todo add bum traffic
        except Exception as err:
            st.error('Traffic stream config error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

        yield

        try:
            vxlan_obj.check_traffic(tc_cfg['stream_handles']['DF_NDF'], action='stop')
        except Exception as err:
            st.error('Traffic stream start error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

        st.wait(30)
        #vxlan_obj.start_stop_protocols(tgen_handles['tg_handle'], 'stop')
        if tc_cfg.get('stream_handles'):
            st.log('Delete traffic items')
            try:
                for traffic_type, traffic_items in tc_cfg['stream_handles'].items():
                    vxlan_obj.delete_traffic_item(tc_cfg['tg_handle'], traffic_items)
            except Exception as err:
                st.error('traffic item cleanup failed')
        #vxlan_obj.start_stop_protocols(tgen_handles['tg_handle'], 'start')

@pytest.mark.usefixtures('tgen_health_check_class')
class TestVxlanTriggers():

    def parse_output(self, dut, cmd, template_file):

        output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        parsed = st.parse_show(dut, cmd, output, template_file)
        parsed_converted = [{str(key): str(value) for key, value in item.items()} for item in parsed]
        return parsed_converted
    
    def recover_from_flap(self, dut, uplink_intfs):
        for key, value in uplink_intfs.items():
            uplink_port = uplink_intfs[key]
            #shut the member interface
            intf_obj.interface_noshutdown(dut, uplink_port)
            st.wait(10)
        return
    
    
    def test_flap_PO_member_links(self):
        global tgen_handles
        
        st.banner("Test 40: V6vtep :DF change trigger with member PC shut")
        leaf_nodes=[]
        spine_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        po_list = pc_obj.get_portchannel_list(leaf_nodes[2])
        for each_po in po_list:
            po_member_list = pc_obj.get_portchannel_members(leaf_nodes[2], each_po['teamdev'])
            if len(po_member_list) <= 1:
                st.report_fail("Portchannel needs atleast 2 members for this test")
            for each_member in po_member_list:
                st.log("Shutting down member interface {}".format(each_member))
                intf_obj.interface_shutdown(leaf_nodes[2], each_member)
                st.wait(10)
                if not intf_obj.verify_interface_status(leaf_nodes[2], each_member, 'oper', 'down'):
                    st.report_fail("member interface {} did not go down".format(each_member))
                if not pc_obj.verify_portchannel(leaf_nodes[2], portchannel_name = each_po['teamdev']):
                    st.report_fail("Portchannel should not down after 1 member went down")
                st.log("After 10 sec sleep")
                evpn_cmd = 'show evpn es'
                template_file = 'show_evpn_es.tmpl'
                parsed_converted = self.parse_output(leaf_nodes[2], evpn_cmd, template_file)
                st.log("Parsed output: {}".format(parsed_converted))
                if len(parsed_converted) == 0:
                    st.report_fail(leaf_nodes[2], 'evpn es output did not return anything')
                expected_po_found = 0
                for each_item in parsed_converted:
                    if each_item['es_if'] == each_po['teamdev']:
                        expected_po_found = 1
                        df_state = each_item['type']
                        if df_state != 'LR':
                            st.report_fail("df_state should not change to no-df. but df_state is {}".format(df_state))
                    else:
                        continue
                st.log("Now performing noshutdown on the member interface")
                intf_obj.interface_noshutdown(leaf_nodes[2], each_member)
                st.wait(10)
                if not expected_po_found:
                    st.report_fail("Expected portchannel not found in evpn es output")
         #verifying everything if all member ports are backup after flap:
        for each_po in po_list:
            if not pc_obj.verify_portchannel(leaf_nodes[2], portchannel_name = each_po['teamdev']):
                    st.report_fail("Portchannel should not down after the flap trigger")
        
        if not pf.verify_traffic(traffic_handles=tgen_handles, bum=False):
            st.report_fail("Traffic failed after flap trigger")

        st.banner("Flap trigger passed")
        st.report_pass("test_case_passed")

    def test_upstream_intf_flap(self):
        global tgen_handles
        st.banner("Test 46: V6vtep : upstream interface shut/no shut")
        leaf_nodes=[]
        spine_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        dut_interfaces = vxlan_obj.get_dut_interfaces(vars)
        uplink_intfs = dut_interfaces['leaf0']['underlay_dict']
        pf.verify_traffic(traffic_handles=tgen_handles, bum=False)
        for key, value in uplink_intfs.items():
            uplink_port = uplink_intfs[key]
            #shut the member interface
            intf_obj.interface_shutdown(leaf_nodes[0], uplink_port)
            st.wait(30)
            if not pf.verify_traffic(traffic_handles=tgen_handles, bum=False):
                intf_obj.interface_noshutdown(leaf_nodes[0], uplink_port)
                st.report_fail("Traffic failed after flap trigger")
            #unshut the member interface
            intf_obj.interface_noshutdown(leaf_nodes[0], uplink_port)
            st.wait(30)
            if not intf_obj.verify_interface_status(leaf_nodes[0], uplink_port, 'oper', 'up'):
                st.report_fail("member interface {} did not come up".format(uplink_port))
            
            if not pf.verify_traffic(traffic_handles=tgen_handles, bum=False):
                st.report_fail("Traffic failed after link up trigger")
            
        st.report_pass("test_case_passed")
    
    def test_all_upstream_intf_flap(self):
        global tgen_handles
        st.banner("Test 45: V6vtep : All upstream interface shut/no shut") 
        leaf_nodes=[]
        spine_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        dut_interfaces = vxlan_obj.get_dut_interfaces(vars)
        uplink_intfs = dut_interfaces['leaf0']['underlay_dict']
        for key, value in uplink_intfs.items():
            uplink_port = uplink_intfs[key]
            #shut the member interface
            intf_obj.interface_shutdown(leaf_nodes[0], uplink_port)
            st.wait(30)
        dut_tgen_interfaces = dut_interfaces['leaf0']['dut_port_dict']
        found_po = 0
        pc_id = "PortChannel"+str(test_cfg['leaf0']['port_channels'][0]['port_channel_num'])
        po_members = pc_obj.get_portchannel_members(leaf_nodes[0], pc_id)
        if pc_obj.verify_portchannel_and_member_status(leaf_nodes[0], pc_id, po_members[0], state='up'):
            self.recover_from_flap(leaf_nodes[0], uplink_intfs)
            st.report_fail("Uplink tracking did not bring down portchannel after all uplinks failed")
        else:
            st.log("Status is oper state and admin state is down due to Uplink tracking")

        #Need to understand how to isolate stream that go from orphan port to portchannel
        '''
        if not pf.verify_traffic(traffic_handles=tgen_handles, bum=False):
            self.recover_from_flap(leaf_nodes[0], uplink_intfs)
            st.report_fail("Traffic failed after flap trigger")
        '''
        
         #bring up all uplinks and verify portchannel is coming up after delay
        self.recover_from_flap(leaf_nodes[0], uplink_intfs)
        
        evpn_cmd = "show evpn"
        evpn_template_file = "show_evpn.tmpl"

        parsed_output = self.parse_output('leaf0', evpn_cmd, evpn_template_file)
        startup_delay_timer = parsed_output[0]['startup_delay']
        st.log("waiting until delay timer expires to verify portchannel status")
        st.wait(int(startup_delay_timer))
    
        if not pc_obj.verify_portchannel_and_member_status(leaf_nodes[0], pc_id, po_members[0], state='up'):
            st.report_fail("Uplink tracking did not bring up portchannel after all uplinks came up")
        else:
            st.log("Status is oper state and admin state is up due to Uplink tracking")
        if not pf.verify_traffic(traffic_handles=tgen_handles, bum=False):
            st.report_fail("Traffic failed after flap trigger")

        st.report_pass("test_case_passed")
 

def enable_or_disable_existing_streams(mode='disable'):
    """
    Disable or enable existing streams.
    :param: mode <str> 'disable' or 'enable' options are acceptable.
    """
    if mode.lower() not in ('disable', 'enable'):
        raise ValueError("Unexpected mode: {}! Available ony 'disable' or 'enable' options!".format(mode))
    streams = []
    tg_handle = tgen_handles['topo_handles']['leaf0'][list(tgen_handles['topo_handles']['leaf0'].keys())[0]]['tg_handle']
    #tg_handle = tgen_handles['topo_handles']['leaf0']tgen_handles['topo_handles']['leaf0'].keys())[0]]['tg_handle']
    for traffic_type, item in tgen_handles.items():
        if traffic_type not in ['v6_device_handles', 'v4_device_handles', 'topo_handles', 'tg_handle']:
            for key, value in item.items():
                streams.append(value['stream_id'])
    st.log("{} all existing streams...".format(mode.capitalize()))
    tg_handle.tg_traffic_config(mode=mode.lower(), stream_id=streams)
    tg_handle.tg_traffic_control(action='apply', stream_handle=streams)

def validate_stats(tg_handle,traffic_item):
    traffic_stat = tg_handle.tg_traffic_stats(mode='traffic_item', streams=traffic_item)
    flag = True 
    for key , values in traffic_stat['traffic_item'].items():
        if key == traffic_item:
            st.banner("TRAFFIC ITEM {}".format(traffic_item))
            st.log("Received traffic: {}".format(values['rx']['total_pkts']))
            st.log("Sent traffic: {}".format(values['tx']['total_pkts']))
            st.log(int(values['rx']['total_pkts'])/int(values['tx']['total_pkts']))
            if int(values['rx']['total_pkts']) > 0.998*int(values['tx']['total_pkts']) and \
                int(values['rx']['total_pkts']) < 1.002*int(values['tx']['total_pkts']):
                st.log(" TRAFFIC ITEM {} PASSED".format(traffic_item))
            else:
                st.log(" TRAFFIC ITEM {} FAILED".format(traffic_item))
                flag = False
    return flag 

def sb_static_setup_traffic_streams(traffic_mesh=False, alternate_nh = False):
    enable_or_disable_existing_streams()
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])
    if dut_type == 'hw':
        pkts_per_burst=100
        rate_percent = 2
    else:
        pkts_per_burst=200
        rate_percent = 0.01
    topo_handles = tgen_handles["topo_handles"]
    for src_node in sb_static_leaf_nodes:
        #IPv4 Streams
        for src_port in pf.v4_host_info_dict[src_node].keys():
            tg = topo_handles[src_node][src_port]['tg_handle']
            tg_stream_map = {}
            tg_stream_map["tg"] = tg
            streams = []
            for vlan in pf.v4_host_info_dict[src_node][src_port].keys():
                for dst_ipv4 in sb_static_static_routes[sb_static_vlan_vrf_map[src_node][vlan]]['v4_addrs']: 
                    src_ipv4 = pf.v4_host_info_dict[src_node][src_port][vlan]["host_ip"]

                    if not alternate_nh:
                        dst_node = sb_static_gw_port_map[dst_ipv4]['node']
                        dst_port = sb_static_gw_port_map[dst_ipv4]['port']
                    else:
                        dst_node = sb_static_gw_port_map[dst_ipv4]['alt_node']
                        dst_port = sb_static_gw_port_map[dst_ipv4]['alt_port']

                    #skip local routing
                    if src_node == dst_node:
                        continue

                    name='{}-{}-{}-to-{}-{}-{}'.format(src_node, src_port, src_ipv4.replace('.', '_'), dst_node, dst_port, dst_ipv4.replace('.','_'))
                    try:
                        stream = tg.tg_traffic_config(name = name,
                                                    emulation_src_handle=topo_handles[src_node][src_port]['port_handle'], 
                                                    emulation_dst_handle=topo_handles[dst_node][dst_port]['port_handle'],
                                                    mac_src=pf.v4_host_info_dict[src_node][src_port][vlan]["src_mac"],
                                                    mac_dst="00:11:22:33:44:55",
                                                    vlan_id = vlan,
                                                    ip_src_addr=src_ipv4, 
                                                    ip_dst_addr=dst_ipv4, 
                                                    transmit_mode="single_burst", 
                                                    pkts_per_burst=pkts_per_burst, 
                                                    rate_percent=rate_percent,
                                                    circuit_type='raw',
                                                    frame_size=1000,
                                                    src_dest_mesh='one_to_one',
                                                    track_by ="endpoint_pair",
                                                    mode="create")
                        streams.append(stream["stream_id"])
                    except:
                        st.banner("ERROR: Unable to add traffic to {}".format(dst_ipv4))
                        continue
                    if not traffic_mesh:
                        break
            if len(streams):
                if not alternate_nh:
                    tg_stream_map["streams"] = streams
                else:
                    tg_stream_map["alt_streams"] = streams
                sb_static_tg_stream_maps.append(tg_stream_map)

        #IPv6 Streams
        for src_port in pf.v6_host_info_dict[src_node].keys():
            tg = topo_handles[src_node][src_port]['tg_handle']
            tg_stream_map = {}
            tg_stream_map["tg"] = tg
            streams = []
            for vlan in pf.v6_host_info_dict[src_node][src_port].keys():
                for dst_ipv6 in sb_static_static_routes[sb_static_vlan_vrf_map[src_node][vlan]]['v6_addrs']: 
                    src_ipv6 = pf.v6_host_info_dict[src_node][src_port][vlan]["host_ip"]

                    if not alternate_nh:
                        dst_node = sb_static_gw_port_map[dst_ipv6]['node']
                        dst_port = sb_static_gw_port_map[dst_ipv6]['port']
                    else:
                        dst_node = sb_static_gw_port_map[dst_ipv6]['alt_node']
                        dst_port = sb_static_gw_port_map[dst_ipv6]['alt_port']

                    #skip local routing
                    if src_node == dst_node:
                        continue

                    name='{}-{}-{}-to-{}-{}-{}'.format(src_node, src_port, src_ipv6.replace(':', '_'), dst_node, dst_port, dst_ipv6.replace(':','_'))
                    try:
                        stream = tg.tg_traffic_config(name = name,
                                                    emulation_src_handle=topo_handles[src_node][src_port]['port_handle'], 
                                                    emulation_dst_handle=topo_handles[dst_node][dst_port]['port_handle'],
                                                    mac_src=pf.v6_host_info_dict[src_node][src_port][vlan]["src_mac"],
                                                    mac_dst="00:11:22:33:44:55",
                                                    vlan_id = vlan,
                                                    ipv6_src_addr=src_ipv6, 
                                                    ipv6_dst_addr=dst_ipv6, 
                                                    transmit_mode="single_burst", 
                                                    pkts_per_burst=pkts_per_burst, 
                                                    rate_percent=rate_percent,
                                                    circuit_type='raw',
                                                    frame_size=1000,
                                                    src_dest_mesh='one_to_one',
                                                    track_by ="endpoint_pair",
                                                    mode="create")
                        streams.append(stream["stream_id"])
                    except:
                        st.banner("ERROR: Unable to add traffic to {}".format(dst_ipv6))
                        continue
                    if not traffic_mesh:
                        break
        
            if len(streams):
                if not alternate_nh:
                    tg_stream_map["streams"] = streams
                else:
                    tg_stream_map["alt_streams"] = streams
                sb_static_tg_stream_maps.append(tg_stream_map)


@pytest.fixture(scope="class")
def setup_sb_static():
    global sb_static_leaf_nodes
    global sb_static_static_routes
    global sb_static_gw_port_map
    global sb_static_vlan_vrf_map
    global sb_static_host_port_map
    global sb_static_tg_stream_maps
    global sb_static_errors

    sb_static_leaf_nodes = []
    sb_static_errors = []

    for dut in st.get_dut_names():
        if "leaf" in dut:
            sb_static_leaf_nodes.append(dut)

    sb_static_static_routes = {}
    sb_static_gw_port_map = {}
    sb_static_vlan_vrf_map = {}
    sb_static_host_port_map = {}
    for node in sb_static_leaf_nodes:
        sb_static_vlan_vrf_map[node] = {}
        for item in test_cfg[node]['l3vni']:
            if not item['vrf_id'] in sb_static_static_routes:
                sb_static_static_routes[item['vrf_id']] = { 'v4_addrs' : [], 'v4_nexthops' : [], 'v6_addrs' : [], 'v6_nexthops' : [] }

            for vlan in item['vlan_bindings']:
                sb_static_vlan_vrf_map[node][vlan] = item['vrf_id']

        for port in pf.v4_host_info_dict[node].keys():
            for vlan in pf.v4_host_info_dict[node][port].keys():
                host = pf.v4_host_info_dict[node][port][vlan]["host_ip"]
                gw = host.replace('.0.','.{}.'.format(host.split('.')[0]))
                sb_static_gw_port_map[gw] = {}
                sb_static_host_port_map[host] = {}
                sb_static_gw_port_map[gw]['node'] = node
                sb_static_gw_port_map[gw]['port'] = port
                sb_static_host_port_map[host]['node'] = node
                sb_static_host_port_map[host]['port'] = port
                sb_static_static_routes[sb_static_vlan_vrf_map[node][vlan]]['v4_addrs'].append(gw)
                sb_static_static_routes[sb_static_vlan_vrf_map[node][vlan]]['v4_nexthops'].append(host)

        for port in pf.v6_host_info_dict[node].keys():
            for vlan in pf.v6_host_info_dict[node][port].keys():
                host = pf.v6_host_info_dict[node][port][vlan]["host_ip"]
                gw = host.replace('::',':{}::'.format(host.split(':')[0]))
                sb_static_gw_port_map[gw] = {}
                sb_static_host_port_map[host] = {}
                sb_static_gw_port_map[gw]['node'] = node
                sb_static_gw_port_map[gw]['port'] = port
                sb_static_host_port_map[host]['node'] = node
                sb_static_host_port_map[host]['port'] = port
                sb_static_static_routes[sb_static_vlan_vrf_map[node][vlan]]['v6_addrs'].append(gw)
                sb_static_static_routes[sb_static_vlan_vrf_map[node][vlan]]['v6_nexthops'].append(host)

    sb_static_tg_stream_maps = []
    sb_static_setup_traffic_streams()

@pytest.mark.usefixtures('tgen_health_check_class', "setup_sb_static")
class TestVxlanSBStaticRoute():       
    def add_or_del_static_routes_single_nh(self, delete=False, subnet_route=False):
        for node in sb_static_leaf_nodes:
            for vrf in sb_static_static_routes.keys():

                family = 'ipv4'
                mask  = '24' if subnet_route else '32'
                for addr, nexthop in zip(sb_static_static_routes[vrf]['v4_addrs'], sb_static_static_routes[vrf]['v4_nexthops']):
                    if not delete:
                        ip_obj.create_static_route(node, next_hop = nexthop, static_ip = addr  + '/' + mask, vrf = 'Vrf{}'.format(vrf), family = family)
                    else:
                        ip_obj.delete_static_route(node, next_hop = nexthop, static_ip = addr + '/' +  mask, vrf = 'Vrf{}'.format(vrf), family = family)
                
                family = 'ipv6'
                mask  = '64' if subnet_route else '128'
                for addr, nexthop in zip(sb_static_static_routes[vrf]['v6_addrs'], sb_static_static_routes[vrf]['v6_nexthops']):
                    if not delete:
                        ip_obj.create_static_route(node, next_hop = nexthop, static_ip = addr  + '/' + mask, vrf = 'Vrf{}'.format(vrf), family = family)
                    else:
                        ip_obj.delete_static_route(node, next_hop = nexthop, static_ip = addr + '/' +  mask, vrf = 'Vrf{}'.format(vrf), family = family)
        

    def add_or_del_static_routes_alternate_nh(self, delete=False, subnet_route=False):
        for node in sb_static_leaf_nodes:
            for vrf in sb_static_static_routes.keys():
                
                family = 'ipv4'
                mask  = '24' if subnet_route else '32'
                for addr in sb_static_static_routes[vrf]['v4_addrs']:
                    for nexthop in sb_static_static_routes[vrf]['v4_nexthops']:

                        #need to move GW behind a host on a different leaf node
                        if sb_static_gw_port_map[addr]['node'] == sb_static_host_port_map[nexthop]['node']:
                            continue

                        sb_static_gw_port_map[addr]['alt_node'] = sb_static_host_port_map[nexthop]['node']
                        sb_static_gw_port_map[addr]['alt_port'] = sb_static_host_port_map[nexthop]['port']
                        if not delete:
                            ip_obj.create_static_route(node, next_hop = nexthop, static_ip = addr  + '/' + mask, vrf = 'Vrf{}'.format(vrf), family = family)
                        else:
                            ip_obj.delete_static_route(node, next_hop = nexthop, static_ip = addr + '/' +  mask, vrf = 'Vrf{}'.format(vrf), family = family)
                        break
                
                family = 'ipv6'
                mask  = '64' if subnet_route else '128'
                for addr in sb_static_static_routes[vrf]['v6_addrs']:
                    for nexthop in sb_static_static_routes[vrf]['v6_nexthops']:

                        #need to move GW behind a host on a different leaf node
                        if sb_static_gw_port_map[addr]['node'] == sb_static_host_port_map[nexthop]['node']:
                            continue

                        sb_static_gw_port_map[addr]['alt_node'] = sb_static_host_port_map[nexthop]['node']
                        sb_static_gw_port_map[addr]['alt_port'] = sb_static_host_port_map[nexthop]['port']
                        if not delete:
                            ip_obj.create_static_route(node, next_hop = nexthop, static_ip = addr  + '/' + mask, vrf = 'Vrf{}'.format(vrf), family = family)
                        else:
                            ip_obj.delete_static_route(node, next_hop = nexthop, static_ip = addr + '/' +  mask, vrf = 'Vrf{}'.format(vrf), family = family)
                        break
    
    def config_nexthop_resolve_via_adjacency(self):
        for node in sb_static_leaf_nodes:
            config_cmds = ['zebra nexthop resolve-via-adjacency']

            for vlan in sb_static_vlan_vrf_map[node].keys():
                config_cmds.append('interface Vlan{}'.format(vlan))
                config_cmds.append('host-routes-enable')
            
            vxlan_obj.config_dut(node, 'bgp', config_cmds)

    def add_or_del_static_routes_multiple_nh(self, delete=False, subnet_route=False):

        "Add static routes with single nh"  
        self.add_or_del_static_routes_single_nh(delete=delete, subnet_route=subnet_route)

        "Add static routes with alternate NH to move the GW"
        self.add_or_del_static_routes_alternate_nh(delete=delete, subnet_route=subnet_route)

    def del_and_add_all_vrf_configs(self):
        selected_leaf_dict = {}
        #Gather facts
        cli_output = st.show('leaf0', "show vrf", skip_tmpl=True)
        parsed_output = st.parse_show('leaf0', "show vrf",cli_output, "show_vrf.tmpl")
        ref_vrf = parsed_output[0]['vrfname']
        temp_list = []
        for item in parsed_output:
            if item['vrfname'] == ref_vrf:
                for interface in item['interfaces']:
                    if not ref_vrf.split("Vrf")[1] in interface:
                        temp_list.append(interface)
        st.banner("selected vrf is {}".format(ref_vrf))
        
        start_vlan = int(ref_vrf.split("Vrf")[1])
        for node in sb_static_leaf_nodes:
            cli_output = st.show(node, "show vrf", skip_tmpl=True)
            parsed_output = st.parse_show(node, "show vrf",cli_output, "show_vrf.tmpl")
            for item in parsed_output:
                if item['vrfname'] == ref_vrf:
                    selected_leaf_dict[node]={}
                    selected_leaf_dict[node]['interfaces']=item['interfaces']
        #Del VRF
        flag = True
        for node in selected_leaf_dict:
            out = vxlan_obj.delete_vrf(node, ref_vrf)
            # verify_vrf(dut1,vrfname="Vrf-103")
            if not out:
                flag = False
            ##--> CHeck for core
        if flag:
            st.log("VRF deletion Success")
            st.wait(10)
            #Add back vrf
            #sonic configs
            for node in selected_leaf_dict:
                cfg_dict = {}
                cfg_dict['l2vni'] = ['dummy']
                for key, value in test_cfg.items():
                    if key == node:
                        cfg_dict['l3vni'] = [item for item in value['l3vni'] if item['vrf_id'] == start_vlan]
                        for item in cfg_dict['l3vni']:
                            if item['vrf_id'] == start_vlan:
                                vlan_list = item['vlan_bindings'] 
                cmd_out = vxlan_obj.generate_l3vni_config(cfg_dict)
                vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)     
                #sag_config
                v4_sag_dict = vxlan_obj.generate_svi_ip_sag(test_cfg[node],'ipv4')
                v6_sag_dict = vxlan_obj.generate_svi_ip_sag(test_cfg[node],'ipv6')

                if v4_sag_dict != None:
                    new_dict = {}
                    for vlan ,value in v4_sag_dict.items():
                        if vlan in vlan_list:
                            new_dict[vlan] = value
                    config_out = vxlan_obj.generate_sag_config(new_dict,'ipv4')
                    vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
                if v6_sag_dict != None:
                    new_dict = {}
                    for vlan ,value in v6_sag_dict.items():
                        if vlan in vlan_list:
                            new_dict[vlan] = value
                    config_out = vxlan_obj.generate_sag_config(new_dict,'ipv6')
                    vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
                
            #vtysh configs
            for node in selected_leaf_dict:
                config_out = vxlan_obj.bgp_vrf_config(node, ref_vrf)
                vxlan_obj.config_dut(node, 'bgp', config_out)
        else:
            sb_static_errors.append("VRF deletion Failed")

    def check_show_ip_route_single_nh (self, subnet_route=False):
        "Check if the  static routes for GWs behind hosts are active for all nodes for all Vrfs."
        for node in sb_static_leaf_nodes:
            for vrf in sb_static_static_routes:

                route_cmd = 'vtysh -c "show ip route vrf Vrf{} json"'.format(vrf)
                show_route = json.loads("\n".join(st.show(node, route_cmd, skip_tmpl=True).split("\n")[:-1]))
                mask  = '24' if subnet_route else '32'
                for addr, nexthop in zip(sb_static_static_routes[vrf]['v4_addrs'], sb_static_static_routes[vrf]['v4_nexthops']): 
                    try:                 
                        for nh in show_route[addr +'/'+ mask][0]["nexthops"]:
                            if nh['ip'] == nexthop:
                                if nh ['ip'] != nexthop:
                                    sb_static_errors.append("Unexpected NH {} for prefix {}/{} in vrf  Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                                if 'active' not in nh:
                                    sb_static_errors.append("NH {} is not active fore prefix {}/{} vrf Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                    except KeyError as ke:
                        sb_static_errors.append("Route not found for prefix {} in {}".format(ke.__str__(), node))                            
                        continue
                
                route_cmd = 'vtysh -c "show ipv6 route vrf Vrf{} json"'.format(vrf)
                show_route = json.loads("\n".join(st.show(node, route_cmd, skip_tmpl=True).split("\n")[:-1]))
                mask  = '64' if subnet_route else '128'
                for addr, nexthop in zip(sb_static_static_routes[vrf]['v6_addrs'], sb_static_static_routes[vrf]['v6_nexthops']):  
                    try:                 
                        for nh in show_route[addr +'/'+ mask][0]["nexthops"]:
                            if nh['ip'] == nexthop:
                                if nh ['ip'] != nexthop:
                                    sb_static_errors.append("Unexpected NH {} for prefix {}/{} in vrf  Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                                if 'active' not in nh:
                                    sb_static_errors.append("NH {} is not active fore prefix {}/{} vrf Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                    except KeyError as ke:
                        sb_static_errors.append("Route not found for prefix {} in {}".format(ke.__str__(), node))                            
                        continue

    def check_show_ip_route_alternate_nh (self, subnet_route=False):
        "Check if the  static routes for GWs behind hosts are active for all nodes for all Vrfs."
        for node in sb_static_leaf_nodes:
            for vrf in sb_static_static_routes:

                route_cmd = 'vtysh -c "show ip route vrf Vrf{} json"'.format(vrf)
                show_route = json.loads("\n".join(st.show(node, route_cmd, skip_tmpl=True).split("\n")[:-1]))
                mask  = '24' if subnet_route else '32'
                for addr in sb_static_static_routes[vrf]['v4_addrs']:
                    for nexthop in sb_static_static_routes[vrf]['v4_nexthops']:

                        #need to move GW behind a host on a different leaf node
                        if sb_static_gw_port_map[addr]['node'] == sb_static_host_port_map[nexthop]['node']:
                            continue
                        try:                 
                            for nh in show_route[addr +'/'+ mask][0]["nexthops"]:
                                if nh['ip'] == nexthop and 'active' not in nh:
                                    sb_static_errors.append("NH {} is not active fore prefix {}/{} vrf Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                        except KeyError as ke:
                            sb_static_errors.append("Route not found for prefix {} in {}".format(ke.__str__(), node))                            
                            continue
                        break

                route_cmd = 'vtysh -c "show ipv6 route vrf Vrf{} json"'.format(vrf)
                show_route = json.loads("\n".join(st.show(node, route_cmd, skip_tmpl=True).split("\n")[:-1]))
                mask  = '64' if subnet_route else '128'
                for addr in sb_static_static_routes[vrf]['v6_addrs']:
                    for nexthop in sb_static_static_routes[vrf]['v6_nexthops']:

                        #need to move GW behind a host on a different leaf node
                        if sb_static_gw_port_map[addr]['node'] == sb_static_host_port_map[nexthop]['node']:
                            continue
                        try:                 
                            for nh in show_route[addr +'/'+ mask][0]["nexthops"]:
                                if nh['ip'] == nexthop and 'active' not in nh:
                                    sb_static_errors.append("NH {} is not active fore prefix {}/{} vrf Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                        except KeyError as ke:
                            sb_static_errors.append("Route not found for prefix {} in {}".format(ke.__str__(), node))                            
                            continue
                        break

    def check_show_ip_route_multiple_nh (self, subnet_route=False):
        "Check if the  static routes for GWs behind hosts are active for all nodes for all Vrfs."
        for node in sb_static_leaf_nodes:
            for vrf in sb_static_static_routes:
                route_cmd = 'vtysh -c "show ip route vrf Vrf{} json"'.format(vrf)
                show_route = json.loads("\n".join(st.show(node, route_cmd, skip_tmpl=True).split("\n")[:-1]))
                mask  = '24' if subnet_route else '32'                
                for addr, nexthop in zip(sb_static_static_routes[vrf]['v4_addrs'], sb_static_static_routes[vrf]['v6_nexthops']): 
                    try:                 
                        for nh in show_route[addr +'/'+ mask][0]["nexthops"]:
                            if nh['ip'] == nexthop and 'active' in nh and ('onLink' not in nh or 'recursive' not in nh):
                                sb_static_errors.append("Non Local adacency NH {} is active for prefix {}/{} vrf Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                    except KeyError as ke:
                        sb_static_errors.append("Route not found for prefix {} in {}".format(ke.__str__(), node))                            
                        continue

                route_cmd = 'vtysh -c "show ipv6 route vrf Vrf{} json"'.format(vrf)
                show_route = json.loads("\n".join(st.show(node, route_cmd, skip_tmpl=True).split("\n")[:-1]))
                mask  = '64' if subnet_route else '128'
                for addr, nexthop in zip(sb_static_static_routes[vrf]['v6_addrs'], sb_static_static_routes[vrf]['v6_nexthops']): 
                    try:                 
                        for nh in show_route[addr +'/'+ mask][0]["nexthops"]:
                            if nh['ip'] in sb_static_static_routes[vrf]['v6_nexthops'] and 'active' in nh and 'onLink' not in nh:
                                sb_static_errors.append("Non Local adacency NH {} is active fore prefix {}/{} vrf Vrf{} in node {}".format(nh['ip'], addr, mask, vrf, node))
                    except KeyError as ke:
                        sb_static_errors.append("Route not found for prefix {} in {}".format(ke.__str__(), node))                            
                        continue

    def send_and_verify_traffic(sel, alternate_nh=False):
        st.banner("VXLAN MH SB STATIC: Sending and Verifying traffic")
        if not alternate_nh:
            stream_key = 'streams'
        else:
            stream_key = 'alt_streams'
        for tg_stream_map in sb_static_tg_stream_maps:
            if not stream_key in tg_stream_map:
                continue
            vxlan_obj.start_stop_protocols(tg_stream_map['tg'],'stop')
            st.wait(10)
            vxlan_obj.start_stop_protocols(tg_stream_map['tg'],'start')
            st.wait(10)
            tg_stream_map['tg'].tg_traffic_control(action='run', stream_handle=tg_stream_map[stream_key])
            st.wait(5)
            tg_stream_map['tg'].tg_traffic_control(action='stop', stream_handle=tg_stream_map[stream_key])
            st.wait(5)
            traffic_stat = tg_stream_map['tg'].tg_traffic_stats(mode='traffic_item', streams=tg_stream_map[stream_key])
            row_format = '|{:26}|{:26}|{:24}|'
            for stream_id in traffic_stat['traffic_item'].keys():
                if not stream_id.startswith('TI'): continue

                st.banner("TRAFFIC ITEM {}".format(stream_id))
                st.log(row_format.format('Expected Rx' , 'Actual Rx', 'Result'))
                exp_rx = int(traffic_stat['traffic_item'][stream_id]['tx']['total_pkts'])
                rx = int(traffic_stat['traffic_item'][stream_id]['rx']['total_pkts'])
                min_tol_rx = 0.998 * exp_rx
                max_tol_rx = 1.002 * exp_rx
                if  rx > min_tol_rx and rx < max_tol_rx:
                    st.log(row_format.format(str(exp_rx), str(rx), 'PASS'))
                    st.log("TRAFFIC ITEM {} PASSED".format(stream_id))
                else:
                    st.log(row_format.format(str(exp_rx), str(rx), 'FAIL'))
                    st.log("ERROR: TRAFFIC ITEM {} FAILED".format(stream_id)) 
                    sb_static_errors.append("Traffic Item {} failed".format(stream_id))

    @pytest.mark.skip
    def reload_config(self):
        for node in sb_static_leaf_nodes:
            reboot_obj.config_save(node)
            vxlan_obj.config_dut(node,"bgp", "do write") 
            count = basic_obj.get_and_match_docker_count(node)
            status = reboot_obj.config_reload(node)
            if status:
                st.banner("config reload cmd success!")
            else:
                st.banner("config reload cmd failed!")
                st.report_fail("test_case_failed")
            #change hostname to sonic
            vxlan_obj.config_dut(node,"sonic", "sudo hostname sonic") 

            #check docker statusdef test
            result = True
            if not poll_wait(basic_obj.verify_docker_status, 180, node, 'Exited'):
                st.error("Post 'config reload', dockers are not auto recovered.")
                result = False
            if result:
                if not poll_wait(basic_obj.get_and_match_docker_count, 180, node, count):
                    st.error("Post 'config reload', ALL dockers are not UP.")
                    st.report_fail("test_case_failed")
        st.wait(180)
        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(sb_static_leaf_nodes)

        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail("test_case_failed")
        
        for node in sb_static_leaf_nodes:
            vxlan_obj.get_cli_out(node)

    @pytest.mark.skip
    def reboot_nodes(self):
        for node in sb_static_leaf_nodes:
            vxlan_obj.config_dut(node,"bgp", "do write") 
            count = basic_obj.get_and_match_docker_count(node)
            status = reboot_obj.config_save_reboot(node)
            #change hostname to sonic
            vxlan_obj.config_dut(node,"sonic", "sudo hostname sonic")

        #check docker status
        result = True
        for node in sb_static_leaf_nodes:
            if not poll_wait(basic_obj.verify_docker_status, 180, node, 'Exited'):
                st.error("Post 'config reload', dockers are not auto recovered.")
                result = False
            if result:
                if not poll_wait(basic_obj.get_and_match_docker_count, 180, node, count):
                    st.error("Post 'config reload', ALL dockers are not UP.")
                    st.report_fail("test_case_failed")

        st.wait(300)
        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(sb_static_leaf_nodes)
        
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail("test_case_failed")
        
        for node in sb_static_leaf_nodes:
            vxlan_obj.get_cli_out(node)

    def get_sb_port_list(self):
        self.sb_port_list = {}
        dut_int_data = vxlan_obj.get_dut_interfaces(vars)
        for node in sb_static_leaf_nodes:
            self.sb_port_list[node] = list(dut_int_data[node]['dut_port_dict'].values())
        # ...existing code...
        dut_int_data = vxlan_obj.get_dut_interfaces(vars)
        for node in sb_static_leaf_nodes:
            self.sb_port_list[node] = list(dut_int_data[node]['dut_port_dict'].values())

        for gw in sb_static_gw_port_map.keys():
            node = sb_static_gw_port_map[gw]['node']
            port = sb_static_gw_port_map[gw]['port']
            if 'PortChannel' in port:
                intf_name  = port.split('_')[0]
                self.sb_port_list[node].append(intf_name)
        
    def shut_no_shut_all_sb_ports(self):
        self.get_sb_port_list()
        for node in sb_static_leaf_nodes:
            cmd_list = []
            for interface in self.sb_port_list[node]:
                cmd_list.append("sudo config interface shutdown {}".format(interface))
            st.config(node, cmd_list)

        for node in sb_static_leaf_nodes:
            cmd_list = []
            for interface in self.sb_port_list[node]:
                cmd_list.append("sudo config interface startup {}".format(interface))
            st.config(node, cmd_list)

    def check_and_report_result(self, tc_id):
        global sb_static_errors
        if len(sb_static_errors):
            print(sb_static_errors)                
            st.banner( tc_id + "ERRORS:")
            for error in sb_static_errors:
                st.log(error)
            sb_static_errors = []
            vxlan_obj.report_result(False, tc_id=tc_id)
        else:
            vxlan_obj.report_result(True, tc_id=tc_id)

    def test_sb_static_route_basic(self):
        tc_id = "VXLAN MH SB STATIC 1: Add a new Southbound Static routes with Single NH"
        st.banner(tc_id)

        global sb_static_errors
        if pf.verify_base_setup():
            st.banner('Verify base setup: Pass')
        else:
            st.banner('Verify base setup: Fail')
            sb_static_errors.append("Verify base setup: Fail")

        "Add static routes with single local adj nh"
        self.add_or_del_static_routes_single_nh()
    
        "Check show ip route for the active NH"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_single_nh(delete=True)

        "Add static routes with single local adj nh again"
        self.add_or_del_static_routes_single_nh()
        
        "Check show ip route for the active NH again"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_single_nh(delete=True)

        self.check_and_report_result(tc_id)

    def test_sb_static_route_vrf_add_del(self):
        tc_id = "VXLAN MH SB STATIC 2: Add/Del VRF with Southbound Static routes"
        st.banner(tc_id)
    
        "Add static routes with single local adj nh"
        self.add_or_del_static_routes_single_nh()
        
        "Check show ip route for the active NH"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()
        
        "Delete the routes"
        self.add_or_del_static_routes_single_nh(delete=True)

        "Delete the Vrfs"
        self.del_and_add_all_vrf_configs()

        st.wait(10)

        "Add static routes with single local adj nh again"
        self.add_or_del_static_routes_single_nh()
        
        "Check show ip route for the active NH again"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_single_nh(delete=True)

        self.check_and_report_result(tc_id)

    def test_sb_static_route_sb_port_shut(self):
        tc_id = "VXLAN MH SB STATIC 3: Shut/no shut on all southbound ports Southbound Static routes"
        st.banner(tc_id) 

        "Add static routes with single local adj nh"
        self.add_or_del_static_routes_single_nh()

        "Reload configs on all leaves"
        self.shut_no_shut_all_sb_ports()

        "Check show ip route for the active NH again"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_single_nh(delete=True)

        self.check_and_report_result(tc_id)

    def test_sb_static_route_alternate_nh(self):
        tc_id = "VXLAN MH SB STATIC 5: Add a new Southbound Static routes with Alternate Next-hop"
        st.banner(tc_id) 

        "Add static routes with single nh"
        self.add_or_del_static_routes_single_nh()

        "Check show ip route for the active NH"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete one NH"
        self.add_or_del_static_routes_single_nh(delete=True)

        "Add static routes with alternate NH to move the GW"
        self.add_or_del_static_routes_alternate_nh()

        "Check show ip route for the active NH again"
        self.check_show_ip_route_alternate_nh()

        "Setup traffic streams to flow to alternate NH node"
        sb_static_setup_traffic_streams(alternate_nh=True)
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic(alternate_nh = True)

        "Delete the routes with alternate NH"
        self.add_or_del_static_routes_alternate_nh(delete=True)

        "Add static routes with original nh again"
        self.add_or_del_static_routes_single_nh()

        "Check show ip route for the active NH"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        self.check_and_report_result(tc_id)

    def test_sb_static_route_multiple_nh(self):
        tc_id = "VXLAN MH SB STATIC 4: Add a new Southbound Static routes with multiple Next-hops"
        st.banner(tc_id) 

        "Configure resolve nexthop via ajacency to prefer local NHs"
        self.config_nexthop_resolve_via_adjacency()

        "Add static routes with multiple nh"
        self.add_or_del_static_routes_multiple_nh()
    
        "Check show ip route for the active NH"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_multiple_nh(delete=True)

        "Add static routes with multiple nh again"
        self.add_or_del_static_routes_multiple_nh()


        "Check show ip route for the active NH again"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_multiple_nh(delete=True)

        self.check_and_report_result(tc_id)

    @pytest.mark.skip
    def test_config_reload(self):
        tc_id = "VXLAN MH SB STATIC 6: Reload configs with Southbound Static routes"
        st.banner(tc_id) 

        "Add static routes with single local adj nh"
        self.add_or_del_static_routes_single_nh()

        "Reload configs on all leaves"
        self.reload_config()

        "Check show ip route for the active NH again"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_single_nh(delete=True)

        self.check_and_report_result(tc_id)
    
    @pytest.mark.skip
    def test_reboot(self):
        tc_id = "VXLAN MH SB STATIC 7: Reboot Leaf nodes with Southbound Static routes"
        st.banner(tc_id) 
        
        "Add static routes with single local adj nh"
        self.add_or_del_static_routes_single_nh()

        "Reboot all leaves"
        self.reboot_nodes()

        "Check show ip route for the active NH again"
        self.check_show_ip_route_single_nh()
    
        "generate traffic from all hosts to all the GWs within the Vrfs"
        self.send_and_verify_traffic()

        "Delete the routes"
        self.add_or_del_static_routes_single_nh(delete=True)

        self.check_and_report_result(tc_id)
        result = self.verify_dhcp_bindings(server_port = ["orphan","mh"], vni_type = "L3")
        vxlan_obj.report_result(result, tc_id)

@pytest.mark.usefixtures('tgen_health_check_class')
class TestRemoveAddCfgTriggers():
    def verify_traffic_retry(self, tgen_handles, retries=3, delay=5):
        """
        Verifies traffic with a specified number of retries.

        :param tgen_handles: Traffic generator handles.
        :param retries: Number of retry attempts (default: 3).
        :param delay: Delay in seconds between retries (default: 5).
        :return: True if traffic verification succeeds, False otherwise.
        """

        for attempt in range(1, retries + 1):
            st.log("Attempt {} / {}: Verifying traffic...".format(attempt, retries))
            if pf.verify_traffic(tgen_handles):
                st.log("Traffic verification passed in attempt - {} .".format(attempt))
                return True
            else:
                st.log("Traffic verification failed on attempt - {}.".format(attempt))
                if attempt < retries:
                    st.log("Retrying after {} seconds...".format(delay))
                    st.wait(delay)
        st.log("Traffic verification failed after {} retries.".format(retries))
        return False

    def test_remove_add_vlan_members(self):
        """
        Testcase: Solution_test:MH:141 : Remove and add VLAN members
        Description:
            Verify traffic after removing and re-adding VLAN members.
        Steps:
            1. Verify traffic before trigger.
            2. Remove VLAN members from the VLAN.
            3. Re-add VLAN members to the VLAN.
            4. Verify traffic is restored.
        """
        tc_id = "test_remove_add_vlan_members"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        duts = []
        result_str = ''
    
        st.banner("Testcase: Remove and add VLAN members")
        # Collect DUTs.. Leaf Nodes
        duts = test_cfg['nodes']['leaf']

        # Helper function to remove VLAN members
        def remove_vlan_members(dut, vlan_dict):
            for vlan, members in vlan_dict.items():
                st.log("Removing members from VLAN {} on {}: {}".format(vlan, dut, members))
                vlan_obj.delete_vlan_member(dut, vlan, members, tagging_mode=True)
    
        # Helper function to re-add VLAN members
        def add_vlan_members(dut, vlan_dict):
            for vlan, members in vlan_dict.items():
                st.log("Re-adding members to VLAN {} on {}: {}".format(vlan, dut, members))
                vlan_obj.add_vlan_member(dut, vlan, members, tagging_mode=True)

        # Helper function to update vlan dict with resolved vlan members
        def update_vlan_members(dut, vlan_dict):
            pattern = re.compile(r'T.*P.*')
            updated_vlan_dict = {}
            for v, m in vlan_dict.items():
                updated_member_list = []
                for member in m:
                    if pattern.match(member):
                        try:
                            new = vars[vars['dut_ids'][dut] + member]
                            updated_member_list.append(new)
                        except KeyError as e:
                            st.log("KeyError: {}  Skipping member {}.".format(e,member))
                            updated_member_list.append(member)
                    else:
                        updated_member_list.append(member)
                updated_vlan_dict[v] = updated_member_list
            return updated_vlan_dict
        
        # Making a local copy of test_cfg and use it locally
        config_dict = test_cfg
        
        # Remove VLAN members
        for dut in duts:
            # Create a dictionary of VLAN IDs and their members for the current DUT
            vlan_dict = {entry['vlan_id']: entry['members'] for entry in config_dict[dut]['l2vni']}

            # Replace the original VLAN dictionary with the updated one
            vlan_dict = update_vlan_members(dut, vlan_dict)

            try:
                st.log("Removing VLAN members on {}: {}".format(dut, list(vlan_dict.keys())))
                remove_vlan_members(dut, vlan_dict)
            except Exception as e:
                st.log("Error while removing VLAN members on {}: {}".format(dut, e))
                result_str += "Error while removing VLAN members on {}: {}\n".format(dut, e)

        st.wait(15) # Giving a wait time of 15 second before re-adding vlan members after the remove trigger.
        # Re-add VLAN members
        for dut in duts:
            vlan_dict = {entry['vlan_id']: entry['members'] for entry in config_dict[dut]['l2vni']}

            # Replace the original VLAN dictionary with the updated one
            vlan_dict = update_vlan_members(dut, vlan_dict)
            st.log("Re-adding VLAN members on {}: {}".format(dut, list(vlan_dict.keys())))

            try:
                add_vlan_members(dut, vlan_dict)
            except Exception as e:
                st.log("Error while re-adding VLAN members on {}: {}".format(dut, e))
                result_str += "Error while re-adding VLAN members on {}: {}\n".format(dut, e)

        # Verify traffic is restored after re-adding VLAN members
        st.log("Verifying traffic after re-adding VLAN members")
        if self.verify_traffic_retry(tgen_handles, retries=1, delay=5):
            log = "Traffic verification after re-adding VLAN members Passed..."
            st.log(log)
        else:
            log= "Traffic verification failed after the trigger, i.e re-adding VLAN members"
            st.log(log)
            result_str += '{}\n'.format(log)
        
        # Report results
        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)

    def test_remove_add_port_channel(self):
        """
        Testcase: Solution_test:MH:142 : Remove and add Port-Channel
        Description:
            Verify traffic after removing and re-adding a Port-Channel.
        Steps:
            1. Verify traffic before trigger.
            2. Remove the Port-Channel.
            3. Re-add the Port-Channel.
            4. Verify traffic is restored.
        """
        tc_id = "test_remove_add_port_channel"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        duts = []
        result_str = ''
    
        st.banner("Testcase: Remove and add Port-Channel")
    
        # Collect DUTs.. Leaf Nodes
        duts = test_cfg['nodes']['leaf']

        # Helper function to remove a Port-Channel
        def remove_port_channel(dut, port_channel_name):
            st.log("Removing Port-Channel {} on {}".format(port_channel_name, dut))
            pc_obj.delete_portchannel(dut, port_channel_name)
    
        # Helper function to re-add a Port-Channel
        def add_port_channel(dut, port_channel_name, members):
            st.log("Re-adding Port-Channel {} on {} with members: {}".format(port_channel_name, dut, members))
            pc_obj.create_portchannel(dut, port_channel_name)
            pc_obj.add_portchannel_member(dut, port_channel_name, members)

        # Helper function to remove members from a Port-Channel
        def remove_port_channel_members(dut, port_channel_name, members):
            for member in members:
                st.log("Removing member {} from Port-Channel {} on {}".format(member, port_channel_name, dut))
                pc_obj.delete_portchannel_member(dut, port_channel_name, member)
 
        # Helper function to resolve PC members
        def update_port_channel_members(dut, members):
            updated_member_list = []
            for member in members:
                try:
                    new = vars[vars['dut_ids'][dut] + member]
                    updated_member_list.append(new)
                except KeyError as e:
                    st.log("KeyError: {}. Skipping member {}.".format(e, member))
            return updated_member_list

        # Making a local copy of test_cfg and use it locally
        config_dict = test_cfg
        
        # Remove Port-Channel
        for dut in duts:
            # Create vlan dict with vlan id and members.
            vlan_dict = {entry['vlan_id']: entry['members'] for entry in config_dict[dut]['l2vni']}
            pattern = re.compile(r'PortChannel.*')
            # Finding Portchannels in the vlan and remove from VLAN
            for v, m in vlan_dict.items():
                for member in m:
                    if pattern.match(member):  # Check if the member matches the regex pattern
                        st.log("Removing members from VLAN {} on {}: {}".format(v, dut, member))
                        vlan_obj.delete_vlan_member(dut, v, member, tagging_mode=True)

            # Finding Portchannels and removing portchannel
            for pc_entry in config_dict[dut]['port_channels']:
                port_channel_name = 'PortChannel' + str(pc_entry['port_channel_num'])
                members = pc_entry['member_ids']
                members = update_port_channel_members(dut, members)
                # Remove members from the Port-Channel
                st.log("Removing Port-Channel members {} from {} on {}".format(members, port_channel_name, dut))
                try:
                    remove_port_channel_members(dut, port_channel_name, members)
                except Exception as e:
                    result_str += "One or more member ports missing PC config\n"
                    st.log("One or more member ports missing PC config on {}: {}".format(dut, e))
                st.log("Removing Port-Channel {} on {}".format(port_channel_name, dut))
                remove_port_channel(dut, port_channel_name)

        st.wait(15) # Giving 15 seconds wait before removing and adding.
        # Re-add Port-Channel
        for dut in duts:
            for pc_entry in config_dict[dut]['port_channels']:
                port_channel_name = 'PortChannel' + str(pc_entry['port_channel_num'])
                members = pc_entry['member_ids']
                members = update_port_channel_members(dut, members)
                st.log("Re-adding PortChannel {} on {}".format(port_channel_name, dut))
                try:
                    add_port_channel(dut, port_channel_name, members)
                except Exception as e:
                    result_str += "One or more member ports missing PC config while adding\n"
                    st.log("One or more member ports missing PC config on {}: {}".format(dut, e))

            # Create vlan dict with vlan id and members.
            vlan_dict = {entry['vlan_id']: entry['members'] for entry in config_dict[dut]['l2vni']}
            pattern = re.compile(r'PortChannel.*')

            # Finding Portchannels in the vlan and add to VLAN
            for v, m in vlan_dict.items():
                for member in m:
                    if pattern.match(member):  # Check if the member matches the regex pattern
                        st.log("Adding members to the VLAN {} on {}: {}".format(v, dut, member))
                        vlan_obj.add_vlan_member(dut, v, member, tagging_mode=True)
    
        # Verify traffic is restored after re-adding Port-Channel
        st.log("Verifying traffic after re-adding PortChannel")
        if self.verify_traffic_retry(tgen_handles, retries=1, delay=5):
            log = "Traffic verification after re-adding PortChannel Passed"
            st.log(log)
        else:
            log= "Traffic verification after re-adding PortChannel failed"
            st.log(log)
            result_str += '{}\n'.format(log)

        # Report results
        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)


    def test_pc_unconfig(self, pc_unconfig_context, pause_run):
        """
        Testcase: Verify that PC is unconfigured in vtysh and sonic shell

        Description: 
        Test case to verify Customer Found Bug: MIGSOFTWAR-34033 - config portchannel del <name> does not remove FRR entries.
        The bug found is that when a portchannel is deleted, the FRR entries are not removed from vtysh. 
        This test case is to verify that the FRR entries are removed from vtysh when a portchannel is deleted.
        These customer found bugs can be found in the sheet: https://cisco.sharepoint.com/:x:/r/sites/SONIC_on_SF/_layouts/15/doc2.aspx?sourcedoc=%7B5A9F315A-602A-4DA6-991B-A2A98539F269%7D&file=Controller%20Found%20Issues%20-%20Dec18.xlsx&action=default&mobileredirect=true

        Steps: 
            1. Verify PortChannel is active in sonic shell
            2. Delete PortChannel interface in sonic shell
            3. Verify that PC is unconfigured in sonic shell
            4. Verify that PC is unconfigured in vtysh
            5. Calls fixture pc_unconfig_context to bring PortChannel interface back in sonic shell
            6. Verify that PC is configured in sonic shell
            7. Verify that PC is configured in vtysh
        """

        tc_id = "test_pc_unconfig"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        tc_cfg['vlan_members'] = {}
        tc_cfg['eth_members'] = {}
        tc_cfg['pc_ids'] = {}
        tc_cfg['deleted'] = False
        summ = ''

        result = True

        st.banner('Customer Found Bug: MIGSOFTWAR-34033 - Verify PortChannel is down in sonic shell and vtysh ({})'.format(tc_id))

        for dut in ['leaf0', 'leaf2']: 
            pc_id = "PortChannel"+str(test_cfg[dut]['port_channels'][0]['port_channel_num'])
            tc_cfg['pc_ids'][dut] = pc_id # Save pc_id to context BEFORE deletion

            st.log(f'Verify {pc_id} is up in sonic shell and vtysh on {dut}')

            result = pc_obj.verify_portchannel(dut, pc_id)
            if not result:
                summ += f'{pc_id} has not been properly configured to test this case, is down in sonic shell on {dut}. '
                st.error(summ)
                vxlan_obj.report_result(result, tc_id, summ)
            else:
                st.log(f'{pc_id} is properly configured in sonic shell to test this case on {dut}.')

            output = st.vtysh_show(dut, 'show running', skip_tmpl=True) # checks vtysh config for the portchannel
            if 'interface ' + pc_id not in output:
                summ += f'{pc_id} has not been properly configured in vtysh to test this case on {dut}. '
                st.error(summ)
                vxlan_obj.report_result(False, tc_id, summ)
            else:
                st.log(f'{pc_id} is properly configured in vtysh to test this case on {dut}. ')
                
            vlan_ids = []
            for row in test_cfg[dut]['l2vni']:
                if pc_id in row['members']:
                    vlan_ids.append(row['vlan_id'])

            st.log(f'Delete vlan members from {pc_id} on {dut}')
            cmd = ''
            for vlan_id in vlan_ids: 
                cmd += 'config vlan member del ' + str(vlan_id) + ' ' + str(pc_id) + '\n'

            st.config(dut, cmd, skip_tmpl=True)
            tc_cfg['vlan_members'][dut] = vlan_ids # Save deleted vlan ids to context AFTER deletion

            tc_cfg['deleted'] = True # Save deleted flag to context AFTER deletion

            # Removing members/interfaces from portchannel
            members = pc_obj.get_portchannel_members(dut, pc_id)

            result = pc_obj.delete_portchannel_member(dut, pc_id, members)
            if not result:
                summ += f'Failed to remove members/interfaces from {pc_id} on {dut}. '
                st.error(summ)
                vxlan_obj.report_result(result, tc_id, summ)
            else:
                tc_cfg['eth_members'][dut] = members # Save members to context AFTER deletion

            # Deleting portchannel
            result = pc_obj.delete_portchannel(dut, pc_id)
            if not result:
                summ += f'{pc_id} was not properly deleted in sonic shell on {dut}. '
                st.error(summ)
                vxlan_obj.report_result(result, tc_id, summ)
            else:
                st.log(f'{pc_id} was properly deleted in sonic shell on {dut}')
                tc_cfg['pc_ids'][dut] = pc_id # Save pc_id to context AFTER deletion

            st.log(f'Verifying if {pc_id} is deleted in vtysh on {dut}')
            output = st.vtysh_show(dut, 'show running', skip_tmpl=True) # checks vtysh config for the portchannel
            if 'interface ' + pc_id not in output:
                st.log(f'{pc_id} was properly deleted in vtysh on {dut}') 
            else:
                st.error(f'{pc_id} has not been properly deleted in vtysh on {dut}.') # change to error for failed conditions!
                vxlan_obj.report_result(False, tc_id, summ)

        vxlan_obj.report_result(True, tc_id, summ)


    @pytest.fixture
    def pc_unconfig_context(self):
        """
        Portchannel clean up for testcase 'test_pc_unconfig'
        """
        yield 

        tc_id = "test_pc_unconfig"
        tc_cfg = vxlan_obj.get_tc_params(tc_id)


        if tc_cfg['deleted']:
            for dut in ['leaf0', 'leaf2']: 
                if dut in tc_cfg['pc_ids']: # check if dut has a portchannel to restore
                    pc_id = tc_cfg['pc_ids'][dut]
                    st.log(f'Restore {pc_id} on {dut}.')

                    result = pc_obj.create_portchannel(dut, pc_id)
                    if not result:
                        st.error(f'Failed to restore {pc_id} on {dut}.')
                    else:
                        st.log(f'Successfully restored {pc_id} on {dut}.')
                else:
                    st.log(f'No portchannel to restore on {dut}.')

                # Add back members to portchannel
                if dut in tc_cfg['eth_members']:
                    members = tc_cfg['eth_members'][dut]
                    pc_id = tc_cfg['pc_ids'][dut]
                    result = pc_obj.add_portchannel_member(dut, pc_id, members)
                    if not result:
                        st.error(f'Failed to add back members/interfaces to {pc_id} on {dut}. ')
                    else:
                        st.log(f'Successfully added back members/interfaces to {pc_id} on {dut}. ')

                # Add back vlan members to portchannel
                if dut in tc_cfg['vlan_members']:
                    vlan_ids = tc_cfg['vlan_members'][dut]
                    pc_id = tc_cfg['pc_ids'][dut]
                    cmd = ''
                    for vlan_id in vlan_ids:
                        cmd += 'config vlan member add ' + str(vlan_id) + ' ' + str(pc_id) + '\n'
                    st.config(dut, cmd, skip_tmpl=True) # Save vlan ids to context AFTER addition

                if dut in tc_cfg['pc_ids']: 
                    pc_id = tc_cfg['pc_ids'][dut]
                    result = pc_obj.verify_portchannel(dut, pc_id)
                    if not result:
                        st.error(f'Failed to verify {pc_id} on {dut}.')
                    else:
                        st.log(f'Successfully verified {pc_id} on {dut}.')

                    # Verify that the portchannel is restored in vtysh
                    output = st.vtysh_show(dut, 'show running', skip_tmpl=True) 
                    if 'interface ' + pc_id in output:
                        st.log(f'{pc_id} was properly restored in vtysh on {dut}')
                    else:
                        st.error(f'{pc_id} has not been properly restored in vtysh on {dut}.')
                else:
                    st.log(f'No portchannel is restored on {dut}.')
        else:
            st.log(f'No portchannel was deleted.')


    def test_remove_add_ethernet_segment(self):
        """
        Testcase: Solution_test:MH:143 : Remove and add Ethernet Segment (ES)
        Description:
            Verify traffic after removing and re-adding an Ethernet Segment (ES).
        Steps:
            1. Remove the Ethernet Segment (ES).
            2. Verify traffic fails.
            3. Re-add the Ethernet Segment (ES).
            4. Verify traffic is restored.
        """
        tc_id = "test_remove_add_ethernet_segment"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        duts = []
        result_str = ''
    
        st.banner("Testcase: Remove and add Ethernet Segment (ES)")
    
        # Collect DUTs.. Leaf Nodes
        duts = test_cfg['nodes']['leaf']
    
        # Helper function to change evpn_esi
        def change_evpn_esi(esi_address):
            esi_int = int(esi_address.replace(":", ""), 16)
            esi_int += 1
            changed_esi = ":".join("{:02x}".format((esi_int >> (8 * i)) & 0xFF) for i in reversed(range(10)))
            return changed_esi

        # Making a local copy of test_cfg and use it locally
        config_dict = test_cfg
    
        # Remove original Ethernet Segment and Add new Ether Segment
        for dut in duts:
            # Finding Portchannels and EVPN ESI
            for pc_entry in config_dict[dut]['port_channels']:
                port_channel_name = 'PortChannel' + str(pc_entry['port_channel_num'])
                pc_entry['pc_name'] = port_channel_name
                evpn_esi = str(pc_entry['evpn_esi'])
                new_evpn_esi = change_evpn_esi(evpn_esi)
                cli_cmd = ''
                # Remove ESI and add new ESI
                st.log("Removing current esi {} from {} on {}".format(evpn_esi, port_channel_name, dut))
                st.log("And adding new esi {} to {} on {}".format(new_evpn_esi, port_channel_name, dut))
                try:
                    cli_cmd += vxlan_obj.generate_evpn_esi_config(pc_entry, mode='del')
                    pc_entry['evpn_esi'] = new_evpn_esi
                    cli_cmd += vxlan_obj.generate_evpn_esi_config(pc_entry, mode='add')
                    vxlan_obj.config_dut(dut, 'sonic', cli_cmd, add=True)
                except Exception as e:
                    result_str += "One or more comands failing during esi remove, add\n"
                    st.log("One or more comands failing during esi remove, add on {}: {}".format(dut, e))

        st.wait(15) # Giving 15 seconds wait before removing and adding.

        # Verify traffic check passes after removing Ethernet Segment and adding new ES
        st.log("Verifying traffic after removing existing Ethernet Segment and adding new ES")
        if self.verify_traffic_retry(tgen_handles, retries=1, delay=5):
            log = "Traffic verification is Passed after removing Orginal ESI and add new ESI"
            st.log(log)
        else:
            log= "Traffic verification is Failed after removing Orginal ESI and add new ESI"
            st.log(log)
            result_str += '{}\n'.format(log)
    
        # Re-add Original Ethernet Segment
        for dut in duts:
            # Finding Portchannels and EVPN ESI
            for pc_entry in config_dict[dut]['port_channels']:
                port_channel_name = 'PortChannel' + str(pc_entry['port_channel_num'])
                pc_entry['pc_name'] = port_channel_name
                evpn_esi = str(pc_entry['evpn_esi'])
                new_evpn_esi = change_evpn_esi(evpn_esi)
                cli_cmd = ''
                # Remove new ESI and add old ESI
                st.log("Removing current new esi {} from {} on {}".format(new_evpn_esi, port_channel_name, dut))
                st.log("And adding original esi {} to {} on {}".format(evpn_esi, port_channel_name, dut))
                try:
                    pc_entry['evpn_esi'] = new_evpn_esi
                    cli_cmd += vxlan_obj.generate_evpn_esi_config(pc_entry, mode='del')
                    pc_entry['evpn_esi'] = evpn_esi
                    cli_cmd += vxlan_obj.generate_evpn_esi_config(pc_entry, mode='add')
                    vxlan_obj.config_dut(dut, 'sonic', cli_cmd, add=True)
                except Exception as e:
                    result_str += "One or more comands failing during new esi remove, adding original esi \n"
                    st.log("One or more comands failing during new esi {} remove, add original esi {} on {}: {}".format(new_evpn_esi, evpn_esi, dut, e))
    
        # Verify traffic is restored after re-adding Ethernet Segment
        st.wait(15) # Giving 15 seconds wait before removing and adding.

        st.log("Verifying traffic after re-adding original Ethernet Segment")
        if self.verify_traffic_retry(tgen_handles, retries=3, delay=5):
            log = "Traffic verification after re-adding original Ethernet Segment Passed"
            st.log(log)
        else:
            log= "Traffic verification after re-adding Ethernet Segment failed"
            st.log(log)
            result_str += '{}\n'.format(log)
    
        # Report results
        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)

@pytest.mark.usefixtures("tgen_health_check_class", "cfg_new_tgen_port_channel")
class TestVxlanES():
    def test_add_new_ES_new_vlan(self, cleanup_new_devices_streams, pause_run):
        """
        Testcase: Solution_test:MH:269 : Add a new ES and new Vlan
        Description:
            Add new ES on top of existing ES
            for a new Vlan on L2 and L3"
        Steps:
            Generate new ES and new vlan configuration on duts
            Configure Lag interface on TGEN
            Verify using CLI if Lag interfaces and ES is up
            Configure traffic streams for L2 and L3 destinations
            Verify traffic streams
        """
        tc_id = "test_add_new_ES_new_vlan"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        tc_cfg['uncfg_cli'] = dict()
        dut = tc_cfg['dut']
        result = True

        st.banner('Testcase MH:269: Add a new ES and new Vlan ({})'.format(tc_id))

        # calling common api to configure ES and add vlan
        self._cfg_add_new_ES_new_vlan(tc_id = tc_id, tc_cfg=tc_cfg, new_vlan=True)

        st.log('Verify traffic')
        if pf.verify_traffic(tc_cfg['stream_handles'], regenerate=True, stop_start_protocols=True):
            st.banner('Traffic Check Passed')
        else:
            st.banner('Traffic Check Failed')
            result = False

        vxlan_obj.report_result(result, tc_id)

    def test_add_new_ES_add_vlan(self, cleanup_new_devices_streams, pause_run):
        """
        Testcase: Solution_test:MH:270 : Add a new ES and add existing vlan
        Description: 
            Add new ES on top of existing ES
            for a existing Vlan on L2 and L3"
        Steps:
            Generate new ES and vlan configuration for duts
            Configure Lag interface on TGEN
            Verify using CLI if Lag interfaces and ES is up
            Configure traffic streams for L2 and L3 destinations
            Verify traffic streams
        """
        tc_id = "test_add_new_ES_add_vlan"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        tc_cfg['uncfg_cli'] = dict()
        dut = tc_cfg['dut']
        result = True

        st.banner('Testcase MH:270: Add a new ES and add existing Vlan ({})'.format(tc_id))

        for l2_info in test_cfg[dut]['l2vni']:
            if tc_cfg['vlan_id'] == l2_info['vlan_id']:
                tc_cfg['vxlan_id'] = l2_info['vxlan_id']
                break
        else:
            vxlan_obj.report_result(False, tc_id, 'Vlan {} not configured on dut {}'.format(tc_cfg['vlan_id'], dut))
        
        for l3_info in test_cfg[dut]['l3vni']:
            if tc_cfg['vlan_id'] in l3_info['vlan_bindings']:
                tc_cfg['vrf_id'] = l3_info['vrf_id']
                break
        else:
            vxlan_obj.report_result(False, tc_id, 'Vlan {} not configured on any vrf on dut {}'.format(tc_cfg['vlan_id'], dut))
            
        # calling common api to configure ES and add vlan
        self._cfg_add_new_ES_new_vlan(tc_id=tc_id, tc_cfg=tc_cfg, new_vlan=False)

        st.log('Verify traffic')
        if pf.verify_traffic(tc_cfg['stream_handles'], regenerate=True, stop_start_protocols=True):
            st.banner('Traffic Check Passed')
        else:
            st.banner('Traffic Check Failed')
            result = False

        vxlan_obj.report_result(result, tc_id)

    def test_add_new_ES_remove_add_vlan(self, cleanup_new_devices_streams, pause_run):
        """
        Testcase: Solution_test:MH:271 : Add a new ES and move existing vlan to new ES
        Description:
            Move Vlans from existing ES to new ES
        Steps:
            Remove vlan from existing ES
            Generate new ES configuration for duts
            Configure Lag interface on TGEN
            Verify using CLI if Lag interfaces and ES is up
            Configure traffic streams for L2 and L3 destinations
            Verify traffic streams
        """
        tc_id = "test_add_new_ES_remove_add_vlan"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        tc_cfg['uncfg_cli'] = dict()
        dut = tc_cfg['dut']
        result = True

        st.banner('Testcase MH:271: Add a new ES and move existing Vlan ({})'.format(tc_id))

        st.log('Remove vlan {} from port {}'.format(tc_cfg['vlan_id'], tc_cfg['port_remove_from']))
        dut_int_data = vxlan_obj.get_dut_interfaces(vars)
        cfg_cli = {dut: ''}
        tc_cfg['uncfg_cli'][dut] = ''
        for port in tc_cfg['port_remove_from']:
            for port_id, int_name in dut_int_data[dut]['all_port_dict'].items():
                if port in port_id:
                    break
            else:
                int_name = port
            cfg_cli[dut] += 'sudo config vlan member del {} {} \n'.format(tc_cfg['vlan_id'], int_name)
            tc_cfg['uncfg_cli'][dut] += 'sudo config vlan member add {} {} \n'.format(tc_cfg['vlan_id'], int_name)

        st.log('Configuring dut')
        if not config_nodes(cfg_cli):
            vxlan_obj.report_result(False, tc_id, 'DUT config operation failed')

        for l2_info in test_cfg[dut]['l2vni']:
            if tc_cfg['vlan_id'] == l2_info['vlan_id']:
                tc_cfg['vxlan_id'] = l2_info['vxlan_id']
                break
        else:
            vxlan_obj.report_result(False, tc_id, 'Vlan {} not configured on dut {}'.format(tc_cfg['vlan_id'], dut))
        
        for l3_info in test_cfg[dut]['l3vni']:
            if tc_cfg['vlan_id'] in l3_info['vlan_bindings']:
                tc_cfg['vrf_id'] = l3_info['vrf_id']
                break
        else:
            vxlan_obj.report_result(False, tc_id, 'Vlan {} not configured on any vrf on dut {}'.format(tc_cfg['vlan_id'], dut))

        # calling common api to configure ES and add vlan
        self._cfg_add_new_ES_new_vlan(tc_id=tc_id, tc_cfg=tc_cfg, new_vlan=False)

        st.log('Verify traffic')
        if pf.verify_traffic(tc_cfg['stream_handles'], regenerate=True, stop_start_protocols=True):
            st.banner('Traffic Check Passed')
        else:
            st.banner('Traffic Check Failed')
            result = False

        vxlan_obj.report_result(result, tc_id)

    @pytest.fixture(scope="class")
    def cfg_new_tgen_port_channel(self):
        """
            Fixture to setup/teardown new portchanell
        """
        tc_id = 'test_add_new_ES_new_vlan'
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        tc_cfg['node_tgen_ports'] = list()
        dut = tc_cfg['dut']
        dut_ids = list()
        for member_info in tc_cfg['members']:
            node = member_info['node']
            dut_ids.append(vxlan_obj.get_device_id(node, vars))
            for port_id in member_info['member_ids']:
                tc_cfg['node_tgen_ports'].append((node, vxlan_obj.get_peer_port_id(port_id, vars, node)))

        lag_name = 'PortChannel{}_{}'.format(tc_cfg['port_channel_num'], ''.join(dut_ids))
        tc_cfg['lag_name'] = lag_name
        st.log('Configuring Port channel on TGEN') 
        tgen_port_ids = list()
        for node, tgen_port in tc_cfg['node_tgen_ports']:
            tgen_port_ids.append(tgen_port)
            st.log('Destroy existing tgen topo on LAG port: {}:{}'.format(node,tgen_port))
            tg_handle, port_handle = tgapi.get_handle_byname(tgen_port)
            if tgen_handles['topo_handles'][node][tgen_port].get('topology_handle'):
                tg_handle.tg_topology_config(mode='destroy',
                      topology_handle=tgen_handles['topo_handles'][node][tgen_port]['topology_handle'])

        tgen_int_dict = {dut: [{'port_channel_num': tc_cfg['port_channel_num'],
                               'name': lag_name,
                               'ports': tgen_port_ids}]}
        try:
            tc_cfg['tg_handle'] = tgen_handles['tg_handle']
            st.log('Creating lag port and creating topology : {}'.format(lag_name))
            topo_handles = vxlan_obj.create_topology_handles(tgen_int_dict)
            tgen_handles['topo_handles'][dut][lag_name] = topo_handles[dut][lag_name]
            tc_cfg['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", 
                                                handle=topo_handles[dut][lag_name]['topology_handle'])

        except Exception as err:
            vxlan_obj.report_result(False, tc_id, str(err))

        yield

        tc_id = 'test_add_new_ES_new_vlan'
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        dut = tc_cfg['dut']
        lag_name = 'PortChannel{}_{}'.format(tc_cfg['port_channel_num'], ''.join(dut_ids))
            
        if tgen_handles['topo_handles'][dut].get(lag_name):
            st.log('Delete tgen LAG topology ')
            try:
                vxlan_obj.start_stop_protocols(tgen_handles['tg_handle'], 'stop')
                st.wait(10)
                st.log('Destroying LAG topology on the ports')
                tc_cfg['tg_handle'].tg_topology_config(mode='destroy', 
                        topology_handle=tgen_handles['topo_handles'][dut][lag_name]['topology_handle'])
                tc_cfg['tg_handle'].tg_emulation_lag_config(mode= "delete", lag_name= """{}""".format(lag_name),
                                                            lag_handle=tgen_handles['topo_handles'][dut][lag_name]['port_handle'])
                for vport in tgen_handles['topo_handles'][dut][lag_name]['vport_handles']:
                    tc_cfg['tg_handle'].tg_convert_vport_to_porthandle(vport = '::ixNet::OBJ-{}'.format(vport))
                st.log('Restoring topology on the ports')
                for node, tgen_port in tc_cfg['node_tgen_ports']:
                    tgen_int_dict = {node : [tgen_port]}
                    topo_handles = vxlan_obj.create_topology_handles(tgen_int_dict)
                    st.log('topo_handles = {}'.format(topo_handles))
                    tgen_handles['topo_handles'][node][tgen_port] = topo_handles[node][tgen_port]
                vxlan_obj.start_stop_protocols(tgen_handles['tg_handle'], 'start')
            except Exception as err:
                st.error('Tgen topology cleanup failed')
            del tgen_handles['topo_handles'][dut][lag_name]

    def _cfg_add_new_ES_new_vlan(self, tc_id, tc_cfg, new_vlan = True):

        dut_int_data = vxlan_obj.get_dut_interfaces(vars)
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
        cfg_cli = dict()
        dut_ids = list()
        tc_cfg['node_tgen_ports'] = list()
        dut = tc_cfg['dut']
        st.log('Generating port channel, ES, l2/l3 vlan configs')
        for member_info in tc_cfg['members']:
            node = member_info['node']
            dut_ids.append(vxlan_obj.get_device_id(node, vars))
            for port_id in member_info['member_ids']:
                tc_cfg['node_tgen_ports'].append((node, vxlan_obj.get_peer_port_id(port_id, vars, node)))
            cfg_dict = dict()
            cfg_dict['port_channels'] = [{'port_channel_num': tc_cfg['port_channel_num'],
                                        'member_ids': member_info['member_ids'],
                                        'sys_mac': tc_cfg['sys_mac'],
                                        'evpn_esi': tc_cfg['evpn_esi']}]
            cfg_dict['l2vni'] = [{'vlan_id':  tc_cfg['vlan_id'],
                                'members': ['PortChannel{}'.format(tc_cfg['port_channel_num'])],
                                'vxlan_id': tc_cfg['vxlan_id']}]
            cfg_dict['l3vni'] = [{'vrf_id':  tc_cfg['vrf_id'],
                                'vlan_bindings': [tc_cfg['vlan_id']],
                                'vxlan_id': tc_cfg['vxlan_id']}]
            sag_dict_v4 = vxlan_obj.generate_svi_ip_sag(cfg_dict,'ipv4')
            sag_dict_v6 = vxlan_obj.generate_svi_ip_sag(cfg_dict,'ipv6')

            # generating config cli
            cfg_cli[node] = vxlan_obj.generate_port_channel_config(node, cfg_dict, 
                                                             dut_int_data[node])
            if new_vlan:
                cfg_cli[node] += vxlan_obj.generate_l2vni_config(cfg_dict,
                                                                 int_config_dict[node]['l2vni_int'])
                cfg_cli[node] += 'sudo config interface vrf bind Vlan{} Vrf{}\n'.format(tc_cfg['vlan_id'], tc_cfg['vrf_id'])
                cfg_cli[node] += vxlan_obj.generate_sag_config(sag_dict_v4,'ipv4')
                cfg_cli[node] += vxlan_obj.generate_sag_config(sag_dict_v6,'ipv6',enable_on_vlan = False)
            else:
                cfg_cli[node] += 'sudo config vlan member add {} PortChannel{}\n'.format(tc_cfg['vlan_id'],
                                                                                       tc_cfg['port_channel_num'])

            cfg_cli[node] += vxlan_obj.generate_evpn_esi_config(cfg_dict)

            # generating unconfig cli
            uncfg_cli = vxlan_obj.generate_evpn_esi_config(cfg_dict, mode='del')
            if new_vlan:
                uncfg_cli += vxlan_obj.remove_sag_config(sag_dict_v6,'ipv6', disable_on_vlan = False)
                uncfg_cli += vxlan_obj.remove_sag_config(sag_dict_v4,'ipv4')
                uncfg_cli += 'sudo config interface vrf unbind Vlan{}\n'.format(tc_cfg['vlan_id'], tc_cfg['vrf_id'])
                uncfg_cli += vxlan_obj.generate_l2vni_config(cfg_dict,
                                                             int_config_dict[node]['l2vni_int'],
                                                             mode='del')
            else:
                uncfg_cli += 'sudo config vlan member del {} PortChannel{}\n'.format(tc_cfg['vlan_id'],
                                                                                     tc_cfg['port_channel_num'])
            uncfg_cli += vxlan_obj.generate_port_channel_config(node, cfg_dict,
                                                                      dut_int_data[node], 
                                                                      mode='del')
            if not tc_cfg['uncfg_cli'].get(node):
                tc_cfg['uncfg_cli'][node] = ''

            tc_cfg['uncfg_cli'][node] += uncfg_cli

        lag_name = 'PortChannel{}_{}'.format(tc_cfg['port_channel_num'], ''.join(dut_ids))
        tc_cfg['lag_name'] = lag_name

        st.log('Configuring dut')
        if not config_nodes(cfg_cli):
            vxlan_obj.report_result(False, tc_id, 'DUT config operation failed')

        st.log('Configuring TGEN') 
        vxlan_obj.start_stop_protocols(tgen_handles['tg_handle'], 'stop')
        st.wait(30)
        v4_host_info_dict = {dut : {lag_name: {tc_cfg['vlan_id']: {'src_mac': '00:{:02d}:00:00:04:95'.format(int(tc_cfg['vlan_id'])),
                                                'vlan': tc_cfg['vlan_id'], 'gateway': '80.{}.0.1'.format(tc_cfg['vlan_id']),
                                                'host_ip': '80.{}.0.205'.format(tc_cfg['vlan_id'])}}}}
        v6_host_info_dict = {dut : {lag_name: {tc_cfg['vlan_id']: {'src_mac': '00:{:02d}:00:00:06:95'.format(int(tc_cfg['vlan_id'])),
                                                'vlan': tc_cfg['vlan_id'], 'gateway': '8000:{}::1'.format(tc_cfg['vlan_id']),
                                                'host_ip': '8000:{}::205'.format(tc_cfg['vlan_id'])}}}}
        try:
            #add 10sec wait time
            st.wait(10)
            tc_cfg['tg_handle'] = tgen_handles['tg_handle']
            out_v4 = vxlan_obj.create_device_groups(tgen_handles['topo_handles'],v4_host_info_dict)
            v4_node_device_handles = out_v4[0]
            out_v6 = vxlan_obj.create_device_groups(tgen_handles['topo_handles'],v6_host_info_dict,version ="ipv6")
            v6_node_device_handles = out_v6[0]
            for node, interfaces in v4_node_device_handles.items():
                for interface,values in interfaces.items():
                    tgen_handles['v4_device_handles'][interface] =values
                    for idx, handle in values.items():
                        tc_cfg['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", handle=handle)

            for node, interfaces in v6_node_device_handles.items():
                for interface,values in interfaces.items():
                    tgen_handles['v6_device_handles'][interface] =values
                    for idx, handle in values.items():
                        tc_cfg['tg_handle'].tg_test_control(action="apply_on_the_fly_changes", handle=handle)
            st.wait(90)
            
        except Exception as err:
            vxlan_obj.report_result(False, tc_id, str(err))

        st.log('Creating traffic streams')

        # find l2 / l3 endpoints
        l2_endpoints = pf.find_traffic_enpoints(tgen_handles['topo_handles'], v4_host_info_dict, dut, 
                                             lag_name, tc_cfg['vlan_id'], tc_cfg['vlan_id'])
        l3_endpoints = pf.find_traffic_enpoints(tgen_handles['topo_handles'], v4_host_info_dict, dut, 
                                             lag_name, tc_cfg['vlan_id'], tc_cfg['l3_traffic_dst']['vlan_id'])

        tc_cfg['stream_handles'] = dict()
        try:
            stream_id = 'L2V4_PC{}'.format(tc_cfg['port_channel_num'])
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v4_device_handles'],
                                                                endpoints=l2_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                multi_dst = 'vlan', name_prfx=stream_id,
                                                                rate_percent=test_cfg['global']['bum']['rate_percent'],
                                                                pkts_per_burst=test_cfg['global']['bum']['pkts_per_burst'])
            tc_cfg['stream_handles']['New_ES'] = {1: stream_info[1]}
            stream_id = 'L2V6_PC{}'.format(tc_cfg['port_channel_num'])
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v6_device_handles'],
                                                                endpoints=l2_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                version = "ipv6", multi_dst = 'vlan', name_prfx=stream_id,
                                                                rate_percent=test_cfg['global']['bum']['rate_percent'],
                                                                pkts_per_burst=test_cfg['global']['bum']['pkts_per_burst'])
            tc_cfg['stream_handles']['New_ES'][2] = stream_info[1]
            stream_id = 'L3V4_PC{}'.format(tc_cfg['port_channel_num'])
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v4_device_handles'],
                                                                endpoints=l3_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                multi_dst = 'vrf', name_prfx=stream_id,
                                                                rate_percent=test_cfg['global']['bum']['rate_percent'],
                                                                pkts_per_burst=test_cfg['global']['bum']['pkts_per_burst'])
            tc_cfg['stream_handles']['New_ES'][3] = stream_info[1]
            stream_id = 'L3V6_PC{}'.format(tc_cfg['port_channel_num'])
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v6_device_handles'],
                                                                endpoints=l3_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                version = "ipv6", multi_dst = 'vrf', name_prfx=stream_id,
                                                                rate_percent=test_cfg['global']['bum']['rate_percent'],
                                                                pkts_per_burst=test_cfg['global']['bum']['pkts_per_burst'])
            tc_cfg['stream_handles']['New_ES'][4] = stream_info[1]
            vxlan_obj.start_stop_protocols(tgen_handles['tg_handle'], 'start')
            st.wait(15)
        except Exception as err:
            st.error('Traffic stream config error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))

    @pytest.fixture
    def cleanup_new_devices_streams(self):
        """
        DUT and Tgen clean up for testcase 'test_vtep_add_new_ES'
        """

        yield

        tc_id = test_cfg['tc_id'] 
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        lag_name = tc_cfg['lag_name'] 
        dut = tc_cfg['dut'] 
        if tc_cfg.get('stream_handles'):
            st.log('Delete traffic items')
            try:
                for traffic_type, traffic_items in tc_cfg['stream_handles'].items():
                    vxlan_obj.delete_traffic_item(tc_cfg['tg_handle'], traffic_items)
            except Exception as err:
                st.error('traffic item cleanup failed')
            
        st.log('Delete device groups')
        if lag_name in tgen_handles['v4_device_handles'].keys():
            for idx, handle in tgen_handles['v4_device_handles'][lag_name].items():
                tc_cfg['tg_handle'].tg_topology_config(device_group_handle = handle, mode = 'destroy')
            del tgen_handles['v4_device_handles'][lag_name]
        if lag_name in tgen_handles['v6_device_handles'].keys():
            for idx, handle in tgen_handles['v6_device_handles'][lag_name].items():
                tc_cfg['tg_handle'].tg_topology_config(device_group_handle = handle, mode = 'destroy')
            del tgen_handles['v6_device_handles'][lag_name]
        st.wait(15)

        if not config_nodes(tc_cfg['uncfg_cli']):
            st.error('Unconfig duts failed')


class TestVxlanRestartTriggers():
    @pytest.mark.parametrize("restart_type", ["bgp","swss","syncd"])
    def test_restart(self, restart_type):
        """
        Restarts a system service (bgp, swss, syncd) on all duts and verifies docker recovery after trigger.
        Then performs sanity checks and traffic validation
        """
        tc_id = "test_restart_{}".format(restart_type)
        st.banner("Checking base before trigger")
        result_before_trigger = pf.verify_base_setup()
        if not result_before_trigger:
            st.error("Base setup verification failed before trigger")
            vxlan_obj.report_result(result_before_trigger, tc_id, "Base Setup Failed")
        st.banner("Base setup verification passed before trigger")

        # Do the Restart
        st.banner("TEST 40:Trigger: Verify traffic after {} restart".format(restart_type))
        dut_count_arr = {}
        
        result_before_trigger = pf.verify_base_setup()
        if not result_before_trigger:
            st.error("Base setup verification failed before trigger")
            vxlan_obj.report_result(result_before_trigger, tc_id, "Base Setup Failed")
        st.banner("Base setup verification passed before trigger")

        for dut in test_cfg['nodes']['l2l3vni']:
            dut_count_arr[dut] = basic_obj.get_and_match_docker_count(dut)
            vxlan_obj.config_dut(dut,'bgp', 'do write')
            restart_complete = basic_obj.systemctl_restart_service(dut, restart_type)
                
        for dut in test_cfg['nodes']['l2l3vni']:
            # Check Docker Status
            result = True
            if not poll_wait(basic_obj.verify_docker_status, 180, dut, 'Exited'):
                st.error("Post 'systemctl restart {} on {}', dockers are not auto recovered.".format(restart_type,dut))
                result = False
                vxlan_obj.report_result(result, tc_id, "Docker Status Failed")
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, dut, dut_count_arr[dut]):
                st.error("Post 'systemctl restart {} on {}', ALL dockers are not UP.".format(restart_type,dut))
                result = False
                vxlan_obj.report_result(result, tc_id, "Docker Status Failed")
        # PreSanity
        # For swss, retry 10 times because interfaces need to come up
        # For others, retry 5 times
        if restart_type == "swss":
            retry_count = 10
        else:
            retry_count = test_cfg['global']['proc_restart_retries']
        result_presanity = pf.verify_base_setup(retry=retry_count)
        st.banner(" Result AFTER PreSanity Checkrestart: {}".format(result_presanity))
        if not result_presanity :
            vxlan_obj.report_result(result_presanity, tc_id, "After restart {}, base setup check failed".format(restart_type))
        #Check Traffic
        traffic_result = pf.verify_traffic(tgen_handles, bum=True)
        #check for remote mac count on all leafs
        vxlan_obj.report_result(traffic_result, tc_id, "Traffic Failed")


class TestDelAddBGPConfigs():
    def test_del_add_bgp(self):
        '''
        First validate the base setup without any trigger
        On leaf0:
            Remove all BGP configs
            Reconfigure all BGP configs
        Validate the base setup
        Validate the traffic
        '''
        st.log("Starting test for del/add BGP configs")
        st.log("Verifying base setup")
        base_res = pf.verify_base_setup()
        st.log("Removing all BGP configs")
        cli_output = st.show("leaf0", "show vrf", skip_tmpl=True)
        parsed_output = st.parse_show('leaf0', "show vrf", cli_output, "show_vrf.tmpl")
        for entry in parsed_output:
            vxlan_obj.delete_vrf("leaf0", entry['vrfname'], True)

        vxlan_obj.config_feature("leaf0", 'delete_bgp_config')
        st.log("Configs removed from leaf0")
        st.wait(15)

        st.log("Reconfiguring all BGP configs")
        vxlan_obj.config_feature(["leaf0"],'bgp_underlay')
        vxlan_obj.config_feature(["leaf0"],'bgp_overlay')
        if test_cfg['global']['bfd_enable']:
            vxlan_obj.config_feature(["leaf0"],'bgp_bfd_underlay')
            vxlan_obj.config_feature(["leaf0"],'bgp_bfd_overlay')
        vxlan_obj.config_feature(["leaf0"],'bgp_l3vni_config')

        st.log("Reconfigured all BGP configs. Verifying base setup")
        base_res = pf.verify_base_setup(retry=test_cfg['global']['del_add_bgp_retries'])
        st.log("TEST 1: Verify base result after trigger:")
        st.log(base_res)

        if not base_res:
            vxlan_obj.report_result(False, "test_del_add_bgp_configs", 'Base configs not back up after del/add BGP configs')

        st.log("Now validating traffic")
        traffic_result = pf.verify_traffic(tgen_handles, bum=True)
        if not traffic_result:
            vxlan_obj.report_result(False, "test_del_add_bgp_configs", 'Traffic validation failed after del/add BGP configs')
        else:
            st.log("Traffic validation passed after del/add bgp configs")
            vxlan_obj.report_result(traffic_result, "test_del_add_bgp_configs")


@pytest.mark.usefixtures("tgen_health_check_class")
class TestVxlanReloadTriggers():

    def test_config_reload(self):
        st.banner("TEST 50:Trigger: Verify traffic after config reload ")
        leaf_nodes = []
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = 'leaf0'
        #config save sonic and frr
        reboot_obj.config_save(selected_dut)
        vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
        count = basic_obj.get_and_match_docker_count(selected_dut)
        status = reboot_obj.config_reload(selected_dut)
        if status:
            st.banner("config reload cmd success!")
        else:
            st.banner("config reload cmd failed!")
            st.report_fail("test_case_failed")

        #check docker status
        result = True
        if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
            st.error("Post 'config reload', dockers are not auto recovered.")
            result = False
        if result:
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
                st.error("Post 'config reload', ALL dockers are not UP.")
                st.report_fail("test_case_failed")
        st.wait(60)
        st.log("Verifying base setup")
        base_res = pf.verify_base_setup(retry=10)
        if base_res:
            st.banner("Base verification pass after config reload")
        else:
            vxlan_obj.get_cli_out(leaf_nodes)
            vxlan_obj.report_result(False, "test_config_reload", 'Base setup verification failed after config reload')

        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            vxlan_obj.get_cli_out(leaf_nodes)
            st.banner("Not all or no remote vteps are found")
            st.report_fail("test_case_failed")

        traffic_result = pf.verify_traffic(tgen_handles, bum=True)
        vxlan_obj.report_result(traffic_result)

    def test_reboot(self):
        st.banner("TEST 56:Trigger 24: Verify traffic after node reboot ")
        leaf_nodes = []
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = 'leaf0'
        vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
        count = basic_obj.get_and_match_docker_count(selected_dut)
        reboot_obj.dut_reboot(selected_dut)
        restore_helper_file(selected_dut)
        #check docker status
        result = True
        if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
            vxlan_obj.report_result(False, "test_reboot", 'Dockers not auto recovered after reboot')
        if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
            st.error("Post 'reboot', ALL dockers are not UP.")
            vxlan_obj.report_result(False, "test_reboot", 'All dockerts not up after reboot')
        st.log("Verifying base setup")
        base_res = pf.verify_base_setup(retry=10)
        if base_res:
            st.banner("Base verification pass after reboot found")
        else:
            vxlan_obj.get_cli_out(leaf_nodes)
            vxlan_obj.report_result(False, "test_reboot", 'Base setup verification failed after reboot')

        traffic_result = pf.verify_traffic(tgen_handles, bum=True)
        vxlan_obj.report_result(traffic_result)
    

    
@pytest.mark.skip
@pytest.mark.usefixtures("tgen_health_check_class")
class TestHostOnSpine():

    def test_host_on_spine_add_new_vlan(self, cleanup_add_vlan, pause_run):
        """
        Testcase: Solution_test: Add/remove new VLANs with hosts from connected to Spine
        Description:
            "Use the Base Profile: Spine w/Hosts for this TC
            - Verify L2VNI & L3VNI traffic for newly connected hosts+vlans
            - Verify the underlay Spine behavior for L2VNI+L3VNI between Hosts<> behind existing Leafs"
        Steps:
        """
        tc_id = "test_host_on_spine_add_vlan"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        tc_cfg['uncfg_cli'] = dict()
        dut = tc_cfg['dut']
        result = True
        topo_handles = tgen_handles["topo_handles"]
        tc_cfg['tgn_port_id'] = vxlan_obj.get_peer_port_id(tc_cfg['port_id'], vars, dut)
        tc_cfg['tg_handle'] = topo_handles[dut][tc_cfg['tgn_port_id']]['tg_handle']

        st.banner('Testcase : Add/remove new VLANs with hosts from connected to Spine ({})'.format(tc_id))
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
        dut_int_data = vxlan_obj.get_dut_interfaces(vars)
        cfg_dict = dict()
        cfg_dict['l2vni'] = [{'vlan_id':  tc_cfg['vlan_id'],
                              'members': [tc_cfg['port_id']],
                              'vxlan_id': tc_cfg['vxlan_id']}]
        cfg_dict['l3vni'] = [{'vrf_id':  tc_cfg['vrf_id'],
                            'vlan_bindings': [tc_cfg['vlan_id']],
                            'vxlan_id': tc_cfg['vxlan_id']}]
        sag_dict_v4 = vxlan_obj.generate_svi_ip_sag(cfg_dict,'ipv4')
        sag_dict_v6 = vxlan_obj.generate_svi_ip_sag(cfg_dict,'ipv6')
        cfg_cli = dict()
        cfg_cli[dut] = vxlan_obj.generate_l2vni_config(cfg_dict, int_config_dict[dut]['l2vni_int'], 
                                                       dut_int_data[dut])
        cfg_cli[dut] += 'sudo config interface vrf bind Vlan{} Vrf{}\n'.format(tc_cfg['vlan_id'], 
                                                                               tc_cfg['vrf_id'])
        cfg_cli[dut] += vxlan_obj.generate_sag_config(sag_dict_v4,'ipv4')
        cfg_cli[dut] += vxlan_obj.generate_sag_config(sag_dict_v6,'ipv6',enable_on_vlan = False)


        tc_cfg['uncfg_cli'][dut] = vxlan_obj.remove_sag_config(sag_dict_v6,'ipv6', disable_on_vlan = False)
        tc_cfg['uncfg_cli'][dut] += vxlan_obj.remove_sag_config(sag_dict_v4,'ipv4')
        tc_cfg['uncfg_cli'][dut] += 'sudo config interface vrf unbind Vlan{}\n'.format(tc_cfg['vlan_id'],
                                                                                             tc_cfg['vrf_id'])
        tc_cfg['uncfg_cli'][dut] += vxlan_obj.generate_l2vni_config(cfg_dict, 
                                                                    int_config_dict[dut]['l2vni_int'], 
                                                                    dut_int_data[dut], mode='del')

        st.log('Configuring dut')
        config_nodes(tc_cfg['uncfg_cli'])
        if not config_nodes(cfg_cli):
            vxlan_obj.report_result(False, tc_id, 'DUT config operation failed')

        v4_host_info_dict = {dut : {tc_cfg['tgn_port_id']: {tc_cfg['vlan_id']: {'src_mac': '00:{:02d}:00:00:04:94'.format(int(tc_cfg['vlan_id'])),
                                                'vlan': tc_cfg['vlan_id'], 'gateway': '80.{}.0.1'.format(tc_cfg['vlan_id']),
                                                'host_ip': '80.{}.0.204'.format(tc_cfg['vlan_id'])}}}}
        v6_host_info_dict = {dut : {tc_cfg['tgn_port_id']: {tc_cfg['vlan_id']: {'src_mac': '00:{:02d}:00:00:06:94'.format(int(tc_cfg['vlan_id'])),
                                                'vlan': tc_cfg['vlan_id'], 'gateway': '8000:{}::1'.format(tc_cfg['vlan_id']),
                                                'host_ip': '8000:{}::204'.format(tc_cfg['vlan_id'])}}}}

        try:
            out_v4 = vxlan_obj.create_device_groups(topo_handles,v4_host_info_dict)
            v4_node_device_handles = out_v4[0]
            out_v6 = vxlan_obj.create_device_groups(topo_handles,v6_host_info_dict,version ="ipv6")
            v6_node_device_handles = out_v6[0]
            for node, interfaces in v4_node_device_handles.items():
                for interface,values in interfaces.items():
                    tgen_handles['v4_device_handles'][interface].update(values)
            for node, interfaces in v6_node_device_handles.items():
                for interface,values in interfaces.items():
                    tgen_handles['v6_device_handles'][interface].update(values)

        except Exception as err:
            vxlan_obj.report_result(False, tc_id, str(err))

        st.log('Creating traffic streams')

        # find l2 / l3 endpoints
        l2_endpoints = pf.find_traffic_enpoints(tgen_handles['topo_handles'], v4_host_info_dict, dut, 
                                             tc_cfg['port_id'], tc_cfg['vlan_id'], tc_cfg['vlan_id'])
        l3_endpoints = pf.find_traffic_enpoints(tgen_handles['topo_handles'], v4_host_info_dict, dut, 
                                             tc_cfg['port_id'], tc_cfg['vlan_id'], tc_cfg['l3_traffic_dst']['vlan_id'])

        tc_cfg['stream_handles'] = dict()
        try:
            stream_id = 'L2V4_HonS'
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v4_device_handles'],
                                                                endpoints=l2_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                multi_dst = 'vlan', name_prfx=stream_id)
            tc_cfg['stream_handles']['HostOnSpine'] = {1: stream_info[1]}
            stream_id = 'L2V6_HonS'
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v6_device_handles'],
                                                                endpoints=l2_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                version = "ipv6", multi_dst = 'vlan', name_prfx=stream_id)
            tc_cfg['stream_handles']['HostOnSpine'][2] = stream_info[1]
            stream_id = 'L2V6_HonS'
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v4_device_handles'],
                                                                endpoints=l3_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                multi_dst = 'vrf', name_prfx=stream_id)
            tc_cfg['stream_handles']['HostOnSpine'][3] = stream_info[1]
            stream_id = 'L3V6_HonS'
            stream_info = vxlan_obj.create_traffic_item(device_handles = tgen_handles['v6_device_handles'],
                                                                endpoints=l3_endpoints,
                                                                topo_handles=tgen_handles['topo_handles'],
                                                                version = "ipv6", multi_dst = 'vrf', name_prfx=stream_id)
            tc_cfg['stream_handles']['HostOnSpine'][4] = stream_info[1]
        except Exception as err:
            st.error('Traffic stream config error: {}'.format(str(err)))
            vxlan_obj.report_result(False, tc_id, str(err))


        st.log('Verify traffic')
        if pf.verify_traffic(tc_cfg['stream_handles'], regenerate=True):
            st.banner('Traffic Check Passed')
        else:
            st.banner('Traffic Check Failed')
            result = False

        vxlan_obj.report_result(result, tc_id)


    @pytest.fixture
    def cleanup_add_vlan(self):
        """
        DUT and Tgen clean up for testcase 'test_host_on_spine_add_vlan'
        """

        yield

        tc_id = test_cfg['tc_id'] 
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        if tc_cfg.get('stream_handles'):
            st.log('Delete traffic items')
            try:
                for traffic_type, traffic_items in tc_cfg['stream_handles'].items():
                    vxlan_obj.delete_traffic_item(tc_cfg['tg_handle'], traffic_items)
            except Exception as err:
                st.error('traffic item cleanup failed')
            
        st.log('Delete tgen device groups ')
        vxlan_obj.delete_device_groups(tc_cfg['tg_handle'], tgen_handles['v4_device_handles'][tc_cfg['tgn_port_id']][tc_cfg['vlan_id']])
        vxlan_obj.delete_device_groups(tc_cfg['tg_handle'], tgen_handles['v6_device_handles'][tc_cfg['tgn_port_id']][tc_cfg['vlan_id']])
        del tgen_handles['v4_device_handles'][tc_cfg['tgn_port_id']][tc_cfg['vlan_id']]
        del tgen_handles['v6_device_handles'][tc_cfg['tgn_port_id']][tc_cfg['vlan_id']]

        if not config_nodes(tc_cfg['uncfg_cli']):
            st.error('Unconfig duts failed')

    
def config_nodes(cfg):
    ret_val = True
    for node in cfg.keys():
        try:
            vxlan_obj.config_node(node, cfg[node])
        except Exception as err:
            st.error('Error when configuring :{}:\nError{}'.format(cfg[node], err), node)
            ret_val = False
    return ret_val
    
def find_tgen_port_name(port, dut=None):  
    """
    Find the "tgen port channel name" given the port channel name / number
    """
    if not (str(port).startswith('PortChannel') or str(port).isdigit()):
        port_id = vxlan_obj.get_peer_port_id(port, vars, dut)
        return port_id

    duts = [dut] if dut else tgen_handles['topo_handles'].keys()
    match = re.match('^PortChannel([0-9]+)' , str(port))
    port_channel_num = match.group(1) if match else str(port)
    for dut in duts:
        for tgen_port , handles in tgen_handles['topo_handles'][dut].items():
            if tgen_port.startswith('PortChannel{}_'.format(port_channel_num)):
                return tgen_port
    else:
        return None

def verify_vxlan_neigh_groups(dut, retry=1):

    # find esi for dut:
    if test_cfg[dut] and test_cfg[dut].get('port_channels'):
        dut_esi = test_cfg[dut]['port_channels'][0]['evpn_esi']
    else:
        return

    loopback_ip = vxlan_obj.generate_loopback_ip(st.getenv("vtep"))

    exp_data = vxlan_obj.get_expected_vxlan_l2nexthopgroup(dut)
    act_data = vxlan_obj.verify_vxlan_l2nexthopgroup(dut, exp_data, id_keys=['tunnels'], vl_retries=retry)
    st.log('Verify Vxlan-VNI map on {}: Pass'.format(dut))

    dut_member_list = []
    ndut_member_list = []
    for item in act_data:
        if item['tunnels']:
            for node , ip in loopback_ip.items():
                if ip == item['tunnels']:
                    node_esi = test_cfg[node]['port_channels'][0]['evpn_esi']
                    if node_esi == dut_esi:
                        dut_member_list.append(item['nbr_grp'])
                    else:
                        ndut_member_list.append(item['nbr_grp'])

    # look for members
    err = ''
    for members in [dut_member_list, ndut_member_list]:
        for item in act_data:
            if sorted(members) == sorted(item['loc_mbrs'].split(',')):
                st.log('Local Members {} found. Neighbor group {}'.format(members, item['nbr_grp']))
                break
        else:
            err += 'Local Members {} not found\n'.format(members)
    if err:
        raise Exception(err)    

@pytest.fixture(scope="class")
def configure_external_router(request):
    
    tc_id = "base_config_ext_connectivity"
    test_cfg['tc_id'] = tc_id
    tc_cfg = vxlan_obj.get_tc_params(tc_id) 
    tc_cfg['hx1_vlan_int'] = "Vlan{}".format(tc_cfg['vlan_id_hx1'])
    tc_cfg['hx2_vlan_int'] = "Vlan{}".format(tc_cfg['vlan_id_hx2'])
    result = True
    selected_dut = ""
    for dut in st.get_dut_names():
        if "external" in dut:
            selected_dut = dut
    cli_output = st.show('leaf3', "show vrf", skip_tmpl=True)
    parsed_output = st.parse_show('leaf3', "show vrf", cli_output, "show_vrf.tmpl")
    ref_vrf_1 = parsed_output[0]['vrfname']
    ref_vrf_2 = parsed_output[1]['vrfname']
    
    #config loopback
    ip_obj.config_ip_addr_interface(selected_dut, interface_name="Loopback0", ip_address='30.100.100.100', subnet='32', family="ipv4", config='add', skip_error=True)
    #Config Vrf
    
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = ref_vrf_1, config = 'yes')
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = ref_vrf_2, config = 'yes')
    
    # find the port connected to leaf
    ext_dut_id = vars.dut_ids['external_router']
    leaf3_dut_id = vars.dut_ids['leaf3']
    for node,dut_id in vars.dut_ids.items():
        if dut_id == ext_dut_id or dut_id == leaf3_dut_id :
            for key,value in vars.items():
                if ext_dut_id+leaf3_dut_id in key:
                    ext_dut_int_vrf_1 = get_intf_short_name(value + '.' + str(tc_cfg['ext_sub_int_vlan_id_1']))
                    ext_dut_int_vrf_2 = get_intf_short_name(value + '.' + str(tc_cfg['ext_sub_int_vlan_id_2']))

                    continue
                if leaf3_dut_id+ext_dut_id in key:
                    leaf3_int_vrf_1 = get_intf_short_name(value + '.' + str(tc_cfg['ext_sub_int_vlan_id_1']))
                    leaf3_int_vrf_2 = get_intf_short_name(value + '.' + str(tc_cfg['ext_sub_int_vlan_id_2']))
                    continue
                if ext_dut_id+"T1P1" in key:
                    ext_tgen_int = value
                    continue
    #find the port connected to VM host
    #Config ip address on interfaces
    leaf3_interfaces = [
        {'intf': leaf3_int_vrf_1, 'vlan': tc_cfg['ext_sub_int_vlan_id_1'], 'vrf': ref_vrf_1, 'ipv4': tc_cfg['lb_addr_vrf_1'], 'ipv6': tc_cfg['lb_v6addr_vrf_1']},
        {'intf': leaf3_int_vrf_2, 'vlan': tc_cfg['ext_sub_int_vlan_id_2'], 'vrf': ref_vrf_2, 'ipv4': tc_cfg['lb_addr_vrf_2'], 'ipv6': tc_cfg['lb_v6addr_vrf_2']}
    ]

    ext_router_interfaces =[
        {'intf': ext_dut_int_vrf_1, 'vlan': tc_cfg['ext_sub_int_vlan_id_1'], 'vrf': ref_vrf_1, 'ipv4': tc_cfg['ext_addr_vrf_1'], 'ipv6': tc_cfg['ext_v6addr_vrf_1'], 'host_vlan': tc_cfg['vlan_id_hx1']},
        {'intf': ext_dut_int_vrf_2, 'vlan': tc_cfg['ext_sub_int_vlan_id_2'], 'vrf': ref_vrf_2, 'ipv4': tc_cfg['ext_addr_vrf_2'], 'ipv6': tc_cfg['ext_v6addr_vrf_2'], 'host_vlan': tc_cfg['vlan_id_hx2']}
    ]
    
    for iface in leaf3_interfaces:
        ip_obj.config_sub_interface(dut = 'leaf3', intf = iface['intf'], vlan = iface['vlan'])
        vrf_obj.bind_vrf_interface(dut = 'leaf3', vrf_name = iface['vrf'], intf_name =iface['intf'])
        ip_obj.config_ip_addr_interface('leaf3', interface_name = iface['intf'], ip_address = iface['ipv4'], subnet='24', family="ipv4", config='add', skip_error=True)
        ip_obj.config_ip_addr_interface('leaf3', interface_name = iface['intf'], ip_address = iface['ipv6'], subnet='64', family="ipv6", config='add', skip_error=True)
    
    for ext_iface in ext_router_interfaces:
        vlan_obj.create_vlan(selected_dut, ext_iface['host_vlan'])
        vlan_obj.add_vlan_member(selected_dut, ext_iface['host_vlan'], ext_tgen_int, tagging_mode=True)
        ip_obj.config_sub_interface(dut = selected_dut, intf = ext_iface['intf'], vlan = ext_iface['vlan'])
        vrf_obj.bind_vrf_interface(dut = selected_dut, vrf_name = ext_iface['vrf'], intf_name = ext_iface['intf'])
        ip_obj.config_ip_addr_interface(selected_dut, interface_name=ext_iface['intf'], ip_address=ext_iface['ipv4'], subnet='24', family="ipv4", config='add', skip_error=True)
        ip_obj.config_ip_addr_interface(selected_dut, interface_name=ext_iface['intf'], ip_address=ext_iface['ipv6'], subnet='64', family="ipv6", config='add', skip_error=True)
    
    #config external host int
    vrf_obj.bind_vrf_interface(dut = selected_dut, vrf_name = ref_vrf_1, intf_name = tc_cfg['hx1_vlan_int'])
    vrf_obj.bind_vrf_interface(dut = selected_dut, vrf_name = ref_vrf_2, intf_name = tc_cfg['hx2_vlan_int'])

    ip_obj.config_ip_addr_interface(selected_dut, interface_name= tc_cfg['hx1_vlan_int'], ip_address=tc_cfg['ext_host_info'][tc_cfg['vlan_id_hx1']][0]['v4_svi'], subnet='24', family="ipv4", config='add', skip_error=True)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name= tc_cfg['hx2_vlan_int'], ip_address=tc_cfg['ext_host_info'][tc_cfg['vlan_id_hx2']][0]['v4_svi'], subnet='24', family="ipv4", config='add', skip_error=True)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name= tc_cfg['hx1_vlan_int'], ip_address=tc_cfg['ext_host_info'][tc_cfg['vlan_id_hx1']][1]['v6_svi'], subnet='64', family="ipv6", config='add', skip_error=True)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name= tc_cfg['hx2_vlan_int'], ip_address=tc_cfg['ext_host_info'][tc_cfg['vlan_id_hx2']][1]['v6_svi'], subnet='64', family="ipv6", config='add', skip_error=True)
    
    #configure bgp on leaf3
    leaf3_asn_no = str(vxlan_obj.generate_bgp_underlay_info()['leaf3']['as_num'])
    cmd = "route-map RECEIVE-HOST-ROUTES-V6 permit 1\non-match next\nset ipv6 next-hop prefer-global\nexit\n"
    cmd += "router bgp {} vrf {}\nbgp router-id 50.50.50.2\n".format(leaf3_asn_no, ref_vrf_1)
    cmd += "no bgp ebgp-requires-policy\nno bgp network import-check\nno bgp default ipv4-unicast\n"
    cmd += "neighbor {} remote-as {}\n".format(tc_cfg['ext_addr_vrf_1'], tc_cfg['ext_asn_no'])
    cmd += "neighbor {} remote-as {}\n".format(tc_cfg['ext_v6addr_vrf_1'], tc_cfg['ext_asn_no'])
    cmd += "neighbor {} capability extended-nexthop\n".format(tc_cfg['ext_v6addr_vrf_1'])
    cmd += "address-family ipv4 unicast\nneighbor {} activate\nexit-address-family\n".format(tc_cfg['ext_addr_vrf_1'])
    cmd += "address-family ipv6 unicast\nneighbor {} activate\nneighbor {} route-map RECEIVE-HOST-ROUTES-V6 in\nexit-address-family\nexit\n".format(tc_cfg['ext_v6addr_vrf_1'], tc_cfg['ext_v6addr_vrf_1'])
    cmd += "router bgp {} vrf {}\nbgp router-id 50.50.50.2\n".format(leaf3_asn_no, ref_vrf_2)
    cmd += "no bgp ebgp-requires-policy\nno bgp network import-check\nno bgp default ipv4-unicast\n"
    cmd += "neighbor {} remote-as {}\n".format(tc_cfg['ext_addr_vrf_2'], tc_cfg['ext_asn_no'])
    cmd += "neighbor {} remote-as {}\n".format(tc_cfg['ext_v6addr_vrf_2'], tc_cfg['ext_asn_no'])
    cmd += "neighbor {} capability extended-nexthop\n".format(tc_cfg['ext_v6addr_vrf_2'])
    cmd += "address-family ipv4 unicast\nneighbor {} activate\nexit-address-family\n".format(tc_cfg['ext_addr_vrf_2'])
    cmd += "address-family ipv6 unicast\nneighbor {} activate\nneighbor {} route-map RECEIVE-HOST-ROUTES-V6 in\nexit-address-family\nexit\nend".format(tc_cfg['ext_v6addr_vrf_2'], tc_cfg['ext_v6addr_vrf_2'])

    st.banner(cmd)
    vxlan_obj.config_dut('leaf3', 'bgp', cmd)
    #configure bgp on external router
    org_bgp_cfg_ext = "route-map GLOBAL-NH-V6 permit 1\non-match next\nset ipv6 next-hop prefer-global\nexit\n"
    org_bgp_cfg_ext += "router bgp {} vrf {}\nbgp router-id 50.50.50.1\nno bgp ebgp-requires-policy\nno bgp network import-check\nno bgp default ipv4-unicast\n".format(tc_cfg['ext_asn_no'], ref_vrf_1)
    org_bgp_cfg_ext += "neighbor {} remote-as {}\n".format(tc_cfg['lb_addr_vrf_1'], leaf3_asn_no)
    org_bgp_cfg_ext += "neighbor {} remote-as {}\n".format(tc_cfg['lb_v6addr_vrf_1'], leaf3_asn_no)
    org_bgp_cfg_ext += "neighbor {} capability extended-nexthop\n".format(tc_cfg['lb_v6addr_vrf_1'])
    org_bgp_cfg_ext += "address-family ipv4 unicast\nnetwork 220.1.1.0/24\nneighbor {} activate\nexit-address-family\n".format(tc_cfg['lb_addr_vrf_1'])
    org_bgp_cfg_ext += "address-family ipv6 unicast\nnetwork 220:1:1::/64\nneighbor {} activate\nneighbor {} route-map GLOBAL-NH-V6 in\nexit-address-family\nexit\n".format(tc_cfg['lb_v6addr_vrf_1'], tc_cfg['lb_v6addr_vrf_1'])
    org_bgp_cfg_ext += "router bgp {} vrf {}\nbgp router-id 50.50.50.1\nno bgp ebgp-requires-policy\nno bgp network import-check\nno bgp default ipv4-unicast\n".format(tc_cfg['ext_asn_no'], ref_vrf_2)
    org_bgp_cfg_ext += "neighbor {} remote-as {}\n".format(tc_cfg['lb_addr_vrf_2'], leaf3_asn_no)
    org_bgp_cfg_ext += "neighbor {} remote-as {}\n".format(tc_cfg['lb_v6addr_vrf_2'], leaf3_asn_no)
    org_bgp_cfg_ext += "neighbor {} capability extended-nexthop\n".format(tc_cfg['lb_v6addr_vrf_2'])
    org_bgp_cfg_ext += "address-family ipv6 unicast\nnetwork 221:1:1::/64\nneighbor {} activate\nneighbor {} route-map GLOBAL-NH-V6 in\nexit-address-family\n".format(tc_cfg['lb_v6addr_vrf_2'], tc_cfg['lb_v6addr_vrf_2'])
    org_bgp_cfg_ext += "address-family ipv4 unicast\nnetwork 221.1.1.0/24\nneighbor {} activate\nexit-address-family\nend\nexit".format(tc_cfg['lb_addr_vrf_2'])

    vxlan_obj.config_dut(selected_dut, 'bgp', org_bgp_cfg_ext)
    st.wait(10)
    cmd1 = "show bgp vrf {} summary".format(ref_vrf_1)
    cmd2 = "show bgp vrf {} summary".format(ref_vrf_2)
    st.show('leaf3', cmd1, type='vtysh', skip_tmpl=True)
    st.show(selected_dut, cmd1, type='vtysh', skip_tmpl=True)
    st.show('leaf3', cmd2, type='vtysh', skip_tmpl=True)
    st.show(selected_dut, cmd2, type='vtysh', skip_tmpl=True)
    
    yield
    ###unconfig on leaf3
    #bgp
    leaf3_asn_no = str(vxlan_obj.generate_bgp_underlay_info()['leaf3']['as_num'])
    cmd = "no router bgp {} vrf {}".format(leaf3_asn_no, ref_vrf_1)
    cmd += "no router bgp {} vrf {}".format(leaf3_asn_no, ref_vrf_2)
    ###unconfig external router
    #bgp
    cmd = "no router bgp {} vrf {}\n".format(tc_cfg['ext_asn_no'], ref_vrf_1)
    cmd += "no router bgp {} vrf {}\nend\nexit\n".format(tc_cfg['ext_asn_no'], ref_vrf_2)
    vxlan_obj.config_dut(selected_dut, 'bgp', cmd)
    #interface
    ip_obj.config_sub_interface(dut = 'leaf3', intf = leaf3_int_vrf_1, vlan = tc_cfg['ext_sub_int_vlan_id_1'], config = 'no')
    ip_obj.config_sub_interface(dut = selected_dut, intf = ext_dut_int_vrf_1, vlan = tc_cfg['ext_sub_int_vlan_id_1'], config = 'no')
    ip_obj.config_sub_interface(dut = 'leaf3', intf = leaf3_int_vrf_2, vlan = tc_cfg['ext_sub_int_vlan_id_2'], config = 'no')
    ip_obj.config_sub_interface(dut = selected_dut, intf = ext_dut_int_vrf_2, vlan = tc_cfg['ext_sub_int_vlan_id_2'], config = 'no')
    #sonic
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = ref_vrf_1, config = 'no')
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = ref_vrf_2, config = 'no')

#@pytest.fixture(scope="class", autouse=True)
def set_frr_cfg_persistent():
    global vars
    lb_dut = 'leaf3'
    reboot_obj.config_save(lb_dut)
    vxlan_obj.config_dut(lb_dut,"bgp", "do write") 
    try:
        with vxlan_obj.ConfigDB(lb_dut, vars.mgmt_ipv4[lb_dut], username=st.get_username(lb_dut), 
                                password= st.get_password(lb_dut)) as cfgdb:
            cfgdb.set_leaf_value(['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode'], 
                                 'split-unified')
        count = basic_obj.get_and_match_docker_count(lb_dut)
        status = st.reboot(lb_dut)
        #check docker status
        if not poll_wait(basic_obj.get_and_match_docker_count, 300, lb_dut, count):
            raise Exception('Dockers not up after reboot')
    except Exception as err:
        st.error(err)
        st.report_fail("operation_failed")

@pytest.fixture(scope="class")
def tgen_ext_conn_preconfig():
    
    global tgen_handles, dut_type, host_addr_1, host_mask_1, host_gateway_1
    
    #Src port selection
    tc_id = "base_config_ext_connectivity"
    test_cfg['tc_id'] = tc_id
    tc_cfg = vxlan_obj.get_tc_params(tc_id) 
    result = True
    spine_testbed = True
    selected_leaf_list = ['leaf0']
    spine_node = 'spine3'
    topo_handles = tgen_handles['topo_handles']
    dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
    if dut_type == 'hw':
        pkts_per_burst=1000
        rate_percent = 1
    else:
        pkts_per_burst=200
        rate_percent = 0.01
    #intf = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')['leaf0']
    leaf0_tgen_intf = topo_handles['leaf0'].keys()
    
    
    for item in leaf0_tgen_intf:
        if "PortChannel" in item:
            src_port =item
    #Dst port selection
    tgen_ports = dict(vars.tgen_ports)
    ext_dut_id = vars.dut_ids['external_router']
    for key in tgen_ports:
        if ext_dut_id in key and "P1" in key:
            dst_port = key
    intf = {'leaf0':[src_port],'external_router':[dst_port]}
    ext_tgen_intf = {'external_router':[dst_port]}  

    
    if spine_node not in test_cfg['nodes']['l2l3vni']:
        spine_testbed = False
    else:
        try:
            spine_tgen_intf = topo_handles['spine3'].keys()
            for key in spine_tgen_intf:
                if "P1" in key:
                    spine_src_port = key    
        except Exception as err:
            st.error('Spine3 not found in topo_handles but spine configs are present')
        
    
    if spine_node not in test_cfg['nodes']['l2l3vni']:
        spine_testbed = False

    
    ext_topo_handles = vxlan_obj.create_topology_handles(ext_tgen_intf)
    #ext_tg_handle = ext_topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['topology_handle']
    tg_handle = topo_handles['leaf0'][intf['leaf0'][0]]['tg_handle'] 
    #Create device groups
    #device group handle for the host behinf Vrf101
    deviceGroup_handle_1 = tgen_handles['v4_device_handles'][intf['leaf0'][0]][tc_cfg['src_vlan_id_1']]
    deviceGroup_handle_4 = tgen_handles['v4_device_handles'][intf['leaf0'][0]][tc_cfg['src_vlan_id_2']]
    deviceGroupv6_handle_1 = tgen_handles['v6_device_handles'][intf['leaf0'][0]][tc_cfg['src_vlan_id_1']]
    deviceGroupv6_handle_4 = tgen_handles['v6_device_handles'][intf['leaf0'][0]][tc_cfg['src_vlan_id_2']]

    if spine_testbed:

        spine_deviceGroup_handle_1 = tgen_handles['v4_device_handles'][spine_src_port][tc_cfg['spine_host_vlan_1']]
        spine_deviceGroup_handle_4 = tgen_handles['v4_device_handles'][spine_src_port][tc_cfg['spine_host_vlan_2']] 
        spine_deviceGroupv6_handle_1 = tgen_handles['v6_device_handles'][spine_src_port][tc_cfg['spine_host_vlan_1']]
        spine_deviceGroupv6_handle_4 = tgen_handles['v6_device_handles'][spine_src_port][tc_cfg['spine_host_vlan_2']]   
    
    #creating device group handle for the host behind Vrf101 on external router
    device_group_2 = tg_handle.tg_topology_config(
                    topology_handle= ext_topo_handles['external_router'][ext_tgen_intf['external_router'][0]]['topology_handle'],
                    device_group_name= """external dst device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_2 = device_group_2['device_group_handle']

    device_group_v6_2 = tg_handle.tg_topology_config(
                    topology_handle= ext_topo_handles['external_router'][ext_tgen_intf['external_router'][0]]['topology_handle'],
                    device_group_name= """external dst device group vrf 101 """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
    deviceGroupv6_handle_2 = device_group_v6_2['device_group_handle']
    
    #creating device group handle for the host behind Vrf102 on external router

    device_group_3 = tg_handle.tg_topology_config(
                    topology_handle= ext_topo_handles['external_router'][ext_tgen_intf['external_router'][0]]['topology_handle'],
                    device_group_name= """external dst device group vrf 102 """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_3 = device_group_3['device_group_handle']

    device_group_v6_3 = tg_handle.tg_topology_config(
                    topology_handle= ext_topo_handles['external_router'][ext_tgen_intf['external_router'][0]]['topology_handle'],
                    device_group_name= """external dst device group vrf 102 """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )   
    deviceGroupv6_handle_3 = device_group_v6_3['device_group_handle']

    l2_protocol_2 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack 2 """,
            protocol_handle= deviceGroup_handle_2,mtu= "1500",
            vlan=1,
            vlan_id = tc_cfg['vlan_id_hx1'],
            vlan_id_step=1,
            vlan_id_count=1,
            src_mac_addr= '00:10:00:00:10:30',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
    ethernet_handle_2 = l2_protocol_2['ethernet_handle']

    l2_protocol_v6_2 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack 2 """,
            protocol_handle= deviceGroupv6_handle_2,mtu= "1500",
            vlan=1,
            vlan_id = tc_cfg['vlan_id_hx1'],
            vlan_id_step=1,
            vlan_id_count=1,
            src_mac_addr= '00:10:00:00:11:30',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
    ethernetv6_handle_2 = l2_protocol_v6_2['ethernet_handle']


    l2_protocol_3 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack 3 """,
            protocol_handle= deviceGroup_handle_3,mtu= "1500",
            vlan=1,
            vlan_id = tc_cfg['vlan_id_hx2'],
            vlan_id_step=1,
            vlan_id_count=1,
            src_mac_addr= '00:20:00:00:20:30',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
    ethernet_handle_3 = l2_protocol_3['ethernet_handle']

    l2_protocol_v6_3 = tg_handle.tg_interface_config(

            protocol_name= """Ethernet stack 3 """,
            protocol_handle= deviceGroupv6_handle_3,mtu= "1500",
            vlan=1,
            vlan_id = tc_cfg['vlan_id_hx2'],
            vlan_id_step=1,
            vlan_id_count=1,
            src_mac_addr= '00:20:00:00:21:30',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
    ethernetv6_handle_3 = l2_protocol_v6_3['ethernet_handle']

    
    l3_protocol_2 = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle_2,
            ipv4_resolve_gateway= "1",
            gateway= '220.1.1.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '220.1.1.2',
            intf_ip_addr_step= "0.0.0.1"
            )
    ipv4_handle_2 = l3_protocol_2['ipv4_handle']

    l3_protocol_v6_2 = tg_handle.tg_interface_config(
            protocol_name = """IPv6""",
            protocol_handle=ethernetv6_handle_2,
            ipv6_resolve_gateway= "1",
            ipv6_gateway= '220:1:1::1',
            ipv6_gateway_step= "0::0",
            ipv6_intf_addr = '220:1:1::2',
            ipv6_intf_addr_step= "0::1"
            )
    ipv6_handle_2 = l3_protocol_v6_2['ipv6_handle']

    l3_protocol_3 = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle_3,
            ipv4_resolve_gateway= "1",
            gateway= '221.1.1.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '221.1.1.2',
            intf_ip_addr_step= "0.0.0.1"
            )
    ipv4_handle_3 = l3_protocol_3['ipv4_handle']

    l3_protocol_v6_3 = tg_handle.tg_interface_config(
            protocol_name = """IPv6""",
            protocol_handle=ethernetv6_handle_3,
            ipv6_resolve_gateway= "1",
            ipv6_gateway= '221:1:1::1',
            ipv6_gateway_step= "0::0",
            ipv6_intf_addr = '221:1:1::2',
            ipv6_intf_addr_step= "0::1"
            )
    ipv6_handle_3 = l3_protocol_v6_3['ipv6_handle']
    
    vxlan_obj.start_stop_protocols(tg_handle,'start')
    st.wait(10)

    #create traffic item for vrf 101
    '''
    
    stream_handles = vxlan_obj.create_traffic_stream(
                    tg_handle, topo_handles, stream_handles, 1, 'leaf0', intf['leaf0'][0], pkts_per_burst, rate_percent)
    '''
    stream = tg_handle.tg_traffic_config(
                    mode='create', 
                    bidirectional=1,
                    transmit_mode='single_burst', 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type='ipv4', 
                    frame_size='500', 
                    emulation_src_handle=deviceGroup_handle_1, 
                    emulation_dst_handle=deviceGroup_handle_2,
                    track_by = 'traffic_item',
                    )
    stream_id = stream["stream_id"]
    stream_handles = {}
    stream_handles[1] = {}
    stream_handles[1]['stream_id'] = stream_id
    stream_handles[1]['tg_handle'] = tg_handle
    stream_handles[1]['verify_enabled'] = True
    stream_handles[1]['topo_handles'] = topo_handles
    stream_handles[1]['deviceGroup_handle_1'] = deviceGroup_handle_1
    stream_handles[1]['deviceGroup_handle_2'] = deviceGroup_handle_2
    stream_handles[1]['port_handle'] = topo_handles['leaf0'][intf['leaf0'][0]]['port_handle']


    #create traffic item 2 for different vrf 102
    stream = tg_handle.tg_traffic_config(
                    mode='create', 
                    bidirectional=1,
                    transmit_mode='single_burst', 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type='ipv4', 
                    frame_size='500', 
                    emulation_src_handle=deviceGroup_handle_4, 
                    emulation_dst_handle=deviceGroup_handle_3,
                    track_by = 'traffic_item',
                    )
    stream_id = stream["stream_id"]
    stream_handles[2] = {}
    stream_handles[2]['stream_id'] = stream_id
    stream_handles[2]['tg_handle'] = tg_handle
    stream_handles[2]['verify_enabled'] = True
    stream_handles[2]['topo_handles'] = topo_handles
    stream_handles[2]['deviceGroup_handle_4'] = deviceGroup_handle_4
    stream_handles[2]['deviceGroup_handle_3'] = deviceGroup_handle_3
    stream_handles[2]['port_handle'] = topo_handles['leaf0'][intf['leaf0'][0]]['port_handle']

    #create traffic item 3 for different vrf 101
    stream = tg_handle.tg_traffic_config(
                    mode='create',
                    bidirectional=1,
                    transmit_mode='single_burst',
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent,
                    circuit_endpoint_type='ipv6',
                    frame_size='500',
                    emulation_src_handle=deviceGroupv6_handle_1,
                    emulation_dst_handle=deviceGroupv6_handle_2,
                    track_by = 'traffic_item',
                    )
    stream_id = stream["stream_id"]
    stream_handles[3] = {}
    stream_handles[3]['stream_id'] = stream_id
    stream_handles[3]['tg_handle'] = tg_handle
    stream_handles[3]['verify_enabled'] = True
    stream_handles[3]['topo_handles'] = topo_handles
    stream_handles[3]['deviceGroupv6_handle_1'] = deviceGroupv6_handle_1
    stream_handles[3]['deviceGroupv6_handle_2'] = deviceGroupv6_handle_2
    stream_handles[3]['port_handle'] = topo_handles['leaf0'][intf['leaf0'][0]]['port_handle']

    #create traffic item 4 for different vrf 102
    stream = tg_handle.tg_traffic_config(
                    mode='create',
                    bidirectional=1,
                    transmit_mode='single_burst',
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent,
                    circuit_endpoint_type='ipv6',
                    frame_size='500',
                    emulation_src_handle=deviceGroupv6_handle_4,
                    emulation_dst_handle=deviceGroupv6_handle_3,
                    track_by = 'traffic_item',
                    )
    stream_id = stream["stream_id"]
    stream_handles[4] = {}
    stream_handles[4]['stream_id'] = stream_id
    stream_handles[4]['tg_handle'] = tg_handle
    stream_handles[4]['verify_enabled'] = True
    stream_handles[4]['topo_handles'] = topo_handles
    stream_handles[4]['deviceGroupv6_handle_4'] = deviceGroupv6_handle_4
    stream_handles[4]['deviceGroupv6_handle_3'] = deviceGroupv6_handle_3
    stream_handles[4]['port_handle'] = topo_handles['leaf0'][intf['leaf0'][0]]['port_handle']

    #create traffic item 5 for Spine to external router host"

    if spine_testbed:
    
        stream = tg_handle.tg_traffic_config(
                        mode='create',
                        bidirectional=1,
                        transmit_mode='single_burst',
                        pkts_per_burst=pkts_per_burst,
                        rate_percent =rate_percent,
                        circuit_endpoint_type='ipv4',
                        frame_size='500',
                        emulation_src_handle=spine_deviceGroup_handle_1,
                        emulation_dst_handle=deviceGroup_handle_2,
                        track_by = 'traffic_item',
                        )
        stream_id = stream["stream_id"]
        stream_handles[5] = {}
        stream_handles[5]['stream_id'] = stream_id
        stream_handles[5]['tg_handle'] = tg_handle
        stream_handles[5]['verify_enabled'] = True
        stream_handles[5]['topo_handles'] = topo_handles
        stream_handles[5]['spine_deviceGroup_handle_1'] = spine_deviceGroup_handle_1
        stream_handles[5]['deviceGroup_handle_2'] = deviceGroup_handle_2
        stream_handles[5]['port_handle'] = topo_handles['spine3'][spine_src_port]['port_handle']

        #create traffic item 6 for Spine to external router host"

        stream = tg_handle.tg_traffic_config(
                        mode='create',
                        bidirectional=1,
                        transmit_mode='single_burst',
                        pkts_per_burst=pkts_per_burst,
                        rate_percent =rate_percent,
                        circuit_endpoint_type='ipv4',
                        frame_size='500',
                        emulation_src_handle=spine_deviceGroup_handle_4,
                        emulation_dst_handle=deviceGroup_handle_3,
                        track_by = 'traffic_item',
                        )
        stream_id = stream["stream_id"]
        stream_handles[6] = {}
        stream_handles[6]['stream_id'] = stream_id
        stream_handles[6]['tg_handle'] = tg_handle
        stream_handles[6]['verify_enabled'] = True
        stream_handles[6]['topo_handles'] = topo_handles
        stream_handles[6]['spine_deviceGroup_handle_4'] = spine_deviceGroup_handle_4
        stream_handles[6]['deviceGroup_handle_3'] = deviceGroup_handle_3
        stream_handles[6]['port_handle'] = topo_handles['spine3'][spine_src_port]['port_handle']

        #create traffic item 7 for Spine to external router host"

        stream = tg_handle.tg_traffic_config(
                        mode='create',
                        bidirectional=1,
                        transmit_mode='single_burst',
                        pkts_per_burst=pkts_per_burst,
                        rate_percent =rate_percent,
                        circuit_endpoint_type='ipv6',
                        frame_size='500',
                        emulation_src_handle=spine_deviceGroupv6_handle_1,
                        emulation_dst_handle=deviceGroupv6_handle_2,
                        track_by = 'traffic_item',
                        )
        stream_id = stream["stream_id"]
        stream_handles[7] = {}
        stream_handles[7]['stream_id'] = stream_id
        stream_handles[7]['tg_handle'] = tg_handle
        stream_handles[7]['verify_enabled'] = True
        stream_handles[7]['topo_handles'] = topo_handles
        stream_handles[7]['spine_deviceGroupv6_handle_1'] = spine_deviceGroupv6_handle_1
        stream_handles[7]['deviceGroupv6_handle_2'] = deviceGroupv6_handle_2
        stream_handles[7]['port_handle'] = topo_handles['spine3'][spine_src_port]['port_handle']

        #create traffic item 8 for Spine to external router host"
        
        stream = tg_handle.tg_traffic_config(
                        mode='create',
                        bidirectional=1,
                        transmit_mode='single_burst',
                        pkts_per_burst=pkts_per_burst,
                        rate_percent =rate_percent,
                        circuit_endpoint_type='ipv6',
                        frame_size='500',
                        emulation_src_handle=spine_deviceGroupv6_handle_4,
                        emulation_dst_handle=deviceGroupv6_handle_3,
                        track_by = 'traffic_item',
                        )
        stream_id = stream["stream_id"]
        stream_handles[8] = {}
        stream_handles[8]['stream_id'] = stream_id
        stream_handles[8]['tg_handle'] = tg_handle
        stream_handles[8]['verify_enabled'] = True
        stream_handles[8]['topo_handles'] = topo_handles
        stream_handles[8]['spine_deviceGroupv6_handle_4'] = spine_deviceGroupv6_handle_4
        stream_handles[8]['deviceGroupv6_handle_3'] = deviceGroupv6_handle_3
        stream_handles[8]['port_handle'] = topo_handles['spine3'][spine_src_port]['port_handle']
    
    yield stream_handles
    #cleanup tgen
    tg_handle.tg_traffic_control(action='reset', port_handle=stream_handles[1]['port_handle'])
    topology_handles = [ext_topo_handles['external_router'][ext_tgen_intf['external_router'][0]]['topology_handle']]
    for topology in topology_handles:
        tg_handle.tg_topology_config(topology_handle =topology, mode = 'destroy')

@pytest.mark.usefixtures('tgen_health_check_class', 'configure_external_router', 'tgen_ext_conn_preconfig')
class TestVxlanExternalConnectivity():


    @pytest.fixture(autouse=True)
    def init_fixtures(self, request):
        self.handles = request.getfixturevalue('tgen_ext_conn_preconfig')
    
    def skip_spine_test(self):
        #global test_cfg
        if 'spine3' not in test_cfg['nodes']['l2l3vni']:
            return True

    def test_er_config(self):
        st.log("TEST : Verify external router configuration")
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")
        st.report_pass('test_case_passed')
    
    def test_interface_flap_between_bl_and_er(self):
        ext_dut_id = vars.dut_ids['external_router']
        leaf3_dut_id = vars.dut_ids['leaf3']
        for node,dut_id in vars.dut_ids.items():
            if dut_id == ext_dut_id or dut_id == leaf3_dut_id :
                for key,value in vars.items():
                    if ext_dut_id+leaf3_dut_id in key:
                        ext_dut_int = value
                        continue

                    if leaf3_dut_id+ext_dut_id in key:
                        leaf3_dut_int = value
                        continue
        #Triggers
        
        intf_obj.interface_shutdown('external_router', ext_dut_int)
        st.wait(5)
        intf_obj.interface_noshutdown('external_router', ext_dut_int)
        st.wait(5)

        intf_obj.interface_shutdown('leaf3', leaf3_dut_int)
        st.wait(5)
        intf_obj.interface_noshutdown('leaf3', leaf3_dut_int)
        st.wait(5)

        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")

    def test_ext_router_host_interface_flap(self):

        ext_dut_id = vars.dut_ids['external_router']
        for node,dut_id in vars.dut_ids.items():
            if dut_id == ext_dut_id :
                for key,value in vars.items():
                    if ext_dut_id+"T1P1" in key:
                        ext_tgen_int = value
        
        intf_obj.interface_shutdown('external_router',ext_tgen_int)
        st.wait(5)
        intf_obj.interface_noshutdown('external_router',ext_tgen_int)
        st.wait(5)
        
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")

    def test_spine_ext_host_connectivity(self):
        if self.skip_spine_test():
            pytest.skip("Spine config not present")

        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between spine and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between spine host and ext host failed")
            st.report_fail("test_case_failed")

    def test_config_reload(self):
        st.banner("TEST 50:Trigger: Verify traffic after config reload ")
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = 'leaf3'
        #config save sonic and frr
        reboot_obj.config_save(selected_dut)
        vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
        count = basic_obj.get_and_match_docker_count(selected_dut)
        status = reboot_obj.config_reload(selected_dut)
        if status:
            st.banner("config reload cmd success!")
        else:
            st.banner("config reload cmd failed!")
            st.report_fail("test_case_failed")
        #change hostname to sonic
        vxlan_obj.config_dut(selected_dut,"sonic", "sudo hostname sonic") 

        #check docker status
        result = True
        if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
            st.error("Post 'config reload', dockers are not auto recovered.")
            result = False
        if result:
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
                st.error("Post 'config reload', ALL dockers are not UP.")
                st.report_fail("test_case_failed")
        
        st.wait(180)
        st.log("Verifying base setup")
        base_res = pf.verify_base_setup(retry=test_cfg['global']['config_reload'])
        if base_res:
            st.banner("Base verification pass after config reload")
        else:
            vxlan_obj.get_cli_out(leaf_nodes)
            vxlan_obj.report_result(False, "test_config_reload", 'Base setup verification failed after config reload')
    
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            vxlan_obj.get_cli_out(leaf_nodes)
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")
            
    def test_reboot(self):
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = 'leaf3'
        vxlan_obj.config_dut(selected_dut,"bgp", "do write")
        count = basic_obj.get_and_match_docker_count(selected_dut)
        status = st.reboot(selected_dut, clear_skipped_file=True)
        #check docker status
        result = True
        if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
            st.error("Post 'config reload', dockers are not auto recovered.")
            result = False
        if result:
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
                st.error("Post 'config reload', ALL dockers are not UP.")
                st.report_fail("test_case_failed")
        st.log("Verifying base setup")
        base_res = pf.verify_base_setup(retry=10)
        if base_res:
            st.banner("Base verification pass after reboot")
        else:
            vxlan_obj.get_cli_out(leaf_nodes)
            vxlan_obj.report_result(False, "test_config_reload", 'Base setup verification failed after reboot')

        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            vxlan_obj.get_cli_out(leaf_nodes)
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")


@pytest.fixture(scope="class")
def setup_scaled_mac_vlans():
    '''
    config setup
    ixia stream setup

    Mac only --> first

    '''
    ### ADD DUT CONFIGS ###
   
    tc_id = 'test_mac_learn_and_withdraw'
    test_cfg['tc_id'] = tc_id
    tc_cfg = vxlan_obj.get_tc_params(tc_id) 
    result = True
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    
    int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
    dut_int_data = vxlan_obj.get_dut_interfaces(vars)
    vrf_id = "Vrf101"
    for node in leaf_nodes:
        #add l2vni
        leaf_data = test_cfg['testcases'][tc_id][node]
        config_out = vxlan_obj.generate_l2vni_config(leaf_data,int_config_dict[node]['l2vni_int'],dut_int_data[node])
        vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
        #bindvrf and  add svi
        for vlan, info in leaf_data['host_info'].items():
            ref_int = "Vlan"+str(vlan)
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =ref_int)
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=info['v4_svi'], subnet='16', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=info['v6_svi'], subnet='64', family="ipv6", config='add', skip_error=True)
            cmd = "sudo config vlan static-anycast-gateway enable {}\n".format(vlan)
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
    
    yield
    ###CLEANUP DUT CONFIGS###
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    int_config_dict = vxlan_obj.get_config_interfaces_list(vars) 
    dut_int_data = vxlan_obj.get_dut_interfaces(vars)
    #unbind vlan from vrf
    for node in leaf_nodes:
        leaf_data = test_cfg['testcases'][tc_id][node]
        for vlan, info in leaf_data['host_info'].items():
            cmd = "sudo config vlan static-anycast-gateway disable {}\n".format(vlan)
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            ref_int = "Vlan"+str(vlan)
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =ref_int,config = 'no')
        ##remove l2vni
        config_out = vxlan_obj.generate_l2vni_config(leaf_data,int_config_dict[node]['l2vni_int'],dut_int_data[node], mode='del')
        vxlan_obj.config_dut(node, 'sonic', config_out, add=True)

#@pytest.fixture(scope="class", params=[1000, 10000])
@pytest.fixture(scope="class")
def tgen_scaled_mac_preconfig(request):
    #mac_count = request.param
    mac_count = 1000
    
    global tgen_handles, dut_type, host_addr_1, host_mask_1, host_gateway_1
    
    #Src port selection
    tc_id = 'test_mac_learn_and_withdraw'
    test_cfg['tc_id'] = tc_id
    tc_cfg = vxlan_obj.get_tc_params(tc_id) 
    result = True
    selected_leaf_list = ['leaf0']
    topo_handles = tgen_handles['topo_handles']
    dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
    if dut_type == 'hw':
        pkts_per_burst=1000
        rate_percent = 1
    else:
        pkts_per_burst=200
        rate_percent = 0.01
    #intf = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')['leaf0']
    leaf0_tgen_intf = topo_handles['leaf0'].keys()
    for item in leaf0_tgen_intf:
        if "PortChannel" in item:
            src_port =item
    
    leaf2_tgen_intf = topo_handles['leaf2'].keys()
    for item in leaf2_tgen_intf:
        if "PortChannel" in item:
            dst_port =item  


    #Dst port selection
    tgen_ports = dict(vars.tgen_ports)
    tg_handle = topo_handles['leaf0'][src_port]['tg_handle']
    
    device_group_1 = tg_handle.tg_topology_config(
                    topology_handle=tgen_handles['topo_handles']['leaf0'][src_port]['topology_handle'], 
                    device_group_name= """1000 Mac learn  """,
                    device_group_multiplier = mac_count,
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_1 = device_group_1['device_group_handle']
    device_group_2 = tg_handle.tg_topology_config(
                    topology_handle=tgen_handles['topo_handles']['leaf2'][dst_port]['topology_handle'],
                    device_group_name= """1000 Mac learn dst group  """,
                    device_group_multiplier = 1,
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_2 = device_group_2['device_group_handle']


    l2_protocol_1 = tg_handle.tg_interface_config(
                    protocol_name= """Ethernet stack 2 """, 
                    protocol_handle = deviceGroup_handle_1, 
                    mtu= "1500", 
                    vlan=1, 
                    vlan_id = '510', 
                    #vlan_id_step =1, 
                    vlan_id_count=1, 
                    src_mac_addr= '00:51:00:00:10:30', 
                    src_mac_addr_step= "00.00.00.00.00.01")

    ethernet_handle_1 = l2_protocol_1['ethernet_handle']

    l2_protocol_2 = tg_handle.tg_interface_config(
                    protocol_name= """Ethernet stack 3 """, 
                    protocol_handle = deviceGroup_handle_2,
                    mtu= "1500",
                    vlan=1,
                    vlan_id = '510',
                    vlan_id_count=1,
                    src_mac_addr= '00:51:00:00:20:30',
                    src_mac_addr_step= "00.00.00.00.00.01")

    ethernet_handle_2  = l2_protocol_2['ethernet_handle']

    l3_protocol_1 = tg_handle.tg_interface_config(
                    protocol_name = """IPv4""", 
                    protocol_handle=ethernet_handle_1,
                    ipv4_resolve_gateway= "1",
                    gateway= '51.51.51.1', 
                    gateway_step= "0.0.0.0", 
                    netmask = "255.255.0.0",
                    intf_ip_addr = '51.51.51.2', 
                    intf_ip_addr_step= "0.0.0.1"
                    )
    l3_protocol_2 = tg_handle.tg_interface_config(
                    protocol_name = """IPv4""", 
                    protocol_handle=ethernet_handle_2,
                    ipv4_resolve_gateway= "1",
                    gateway= '51.51.51.1',
                    gateway_step= "0.0.0.0",
                    netmask = "255.255.0.0",
                    intf_ip_addr = '51.51.251.2',
                    intf_ip_addr_step= "0.0.0.1"
                    )
    
    ipv4_handle_1 = l3_protocol_1['ipv4_handle']
    ipv4_handle_2 = l3_protocol_2['ipv4_handle']

    vxlan_obj.start_stop_protocols(tg_handle,'stop')
    st.wait(30)
    vxlan_obj.start_stop_protocols(tg_handle,'start')
    st.wait(60)
    stream = tg_handle.tg_traffic_config(
                    #port_handle = topo_handles['leaf0'][intf['leaf0'][0]]['port_handle'],
                    #port_handle2 = ext_topo_handles['external_router'][ext_tgen_intf['external_router'][0]]['port_handle'],
                    mode='create', 
                    bidirectional=1,
                    transmit_mode='single_burst', 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type='ipv4', 
                    frame_size='500', 
                    emulation_src_handle=deviceGroup_handle_1, 
                    emulation_dst_handle=deviceGroup_handle_2,
                    track_by = 'traffic_item',
                    )
    stream_id = stream["stream_id"]
    stream_handles = {}
    stream_handles[1] = {}
    stream_handles[1]['stream_id'] = stream_id
    stream_handles[1]['tg_handle'] = tg_handle
    stream_handles[1]['verify_enabled'] = True
    stream_handles[1]['topo_handles'] = topo_handles
    stream_handles[1]['deviceGroup_handle_1'] = deviceGroup_handle_1
    stream_handles[1]['deviceGroup_handle_2'] = deviceGroup_handle_2
    stream_handles[1]['port_handle'] = topo_handles['leaf0'][src_port]['port_handle']

    
    #create traffic item 2 for different vrf 102
    yield stream_handles, mac_count
    #tg_handle.tg_traffic_control(action='reset', port_handle=topo_handles['leaf0'][src_port]['port_handle'])
    topology_handles = [tgen_handles['topo_handles']['leaf0'][src_port]['topology_handle']]
    for topology in topology_handles:
        tg_handle.tg_topology_config(topology_handle =topology, mode = 'destroy')

        
@pytest.mark.usefixtures('tgen_health_check_class', 'setup_scaled_mac_vlans', 'tgen_scaled_mac_preconfig')
class TestMacScaleLearnAndWithdraw():
    '''
    def verify_type_2_mac(self, dut, vlan, mac_search, type):
        cmd = vtysh -c "show bgp l2vpn evpn mac" | grep "VNI: 510" | grep "MAC: 00:51:00:00" | grep "Type: Dynamic"
    '''
    @pytest.fixture(autouse=True)
    def init_fixtures(self, request):

        self.handles, self.mac_count = request.getfixturevalue('tgen_scaled_mac_preconfig')

    def _tgen_lag_intf_op_mode(self, status):
        if status == 'down':
            op_mode_state = 'sim_disconnect'
        else:
            op_mode_state = 'normal'

        for int_id, handles in tgen_handles['topo_handles']['leaf0'].items():
            if 'PortChannel' in int_id:
                port_handles = []
                for vport, port_id in zip(handles['vport_handles'], handles['vport_port_ids']):
                        port_handles.append(tgapi.get_handle_byname(port_id)[1])
                        tg_handle = handles['tg_handle']
                        res = tg_handle.tg_interface_config(mode='modify', 
                                                    port_handle=port_handles, 
                                                    op_mode= op_mode_state)
                        if res['status'] != '1':
                            st.error("Failed to set interface {} to {}".format(int_id, status))
                            return False
        return True


    #@pytest.mark.parametrize("tgen_scaled_mac_preconfig", [1000, 10000], indirect=True)
    def test_mac_learn_and_withdraw_with_pc_member_shut(self):
        #mac_count = 1000
        mac_count = self.mac_count
        st.log("Running test with MAC count is {}".format(mac_count))
        mac_add_count = {}
        mac_address_list_leaf0_dynamic = mac_obj.get_mac_address_list('leaf0', vlan='510', type='Dynamic')
        mac_address_list_leaf1_dynamic = mac_obj.get_mac_address_list('leaf1', vlan='510', type='Dynamic')
        mac_address_list_leaf0_static = mac_obj.get_mac_address_list('leaf0', vlan='510', type='Static')
        mac_address_list_leaf1_static = mac_obj.get_mac_address_list('leaf1', vlan='510', type='Static')
        mac_not_sync_list = []

        if len(mac_address_list_leaf0_dynamic) != len(mac_address_list_leaf1_static)-1 or len(mac_address_list_leaf1_dynamic) != len(mac_address_list_leaf0_static)-1:
            if len(mac_address_list_leaf0_dynamic) > len(mac_address_list_leaf1_static):
                st.log("MAC count mismatch between leaf0 and leaf1. Leaf0 dynamic mac count is more than leaf1 static mac count")
                mac_not_sync_list = list(set(mac_address_list_leaf0_dynamic) - set(mac_address_list_leaf1_static))
                mac_local_node = 'leaf0'
            if len(mac_address_list_leaf1_dynamic) > len(mac_address_list_leaf0_static):
                st.log("MAC count mismatch between leaf0 and leaf1. Leaf1 dynamic mac count is more than leaf0 static mac count")
                mac_not_sync_list = list(set(mac_address_list_leaf1_dynamic) - set(mac_address_list_leaf0_static))
                mac_local_node = 'leaf1'
        
        type_2_mac_failed = {}
        if mac_not_sync_list:
            st.error("MAC count mismatch between leaf0 and leaf1 for MACs {}".format(mac_not_sync_list))
            result_dict = vxlan_obj.validate_mac_type2_route(mac_not_sync_list, host_local_node=[mac_local_node], is_mh_host = True)                 
            st.error("MAC verification failed for MACs {} and verification result {}".format(type_2_mac_failed, result_dict))
            st.report_fail("test_case_failed")

        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        
        for dut in leaf_nodes:
            mac_add_count[dut] = {'static': mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Static')}
            mac_add_count[dut]['dynamic'] = mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Dynamic')
            mac_add_count[dut]['total'] = mac_add_count[dut]['static'] + mac_add_count[dut]['dynamic']
            #comparing with mac_count+1, because it will have destination mac learnt on leaf2 and leaf3
            if mac_add_count[dut]['total'] == mac_count+1:
                st.banner("MAC learn count is {}".format(mac_count))
            else: 
                st.banner("MAC learn count is not {} is {}".format(mac_count, mac_add_count[dut]['total']))
                st.report_fail("test_case_failed")
        st.wait(30)
        #port channel member shut

        pc_member_intf = pc_obj.get_portchannel_members('leaf0', 'PortChannel1')
        intf_obj.interface_shutdown('leaf0', pc_member_intf[0])
        st.wait(30)
        #verify if macs are withdrawn
        mac_add_count_after_trigger = {}    
        verify_result = True
        for dut in leaf_nodes:
            mac_add_count_after_trigger[dut] = {'static': mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Static')}
            mac_add_count_after_trigger[dut]['dynamic'] = mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Dynamic')
            mac_add_count_after_trigger[dut]['total'] = mac_add_count_after_trigger[dut]['static'] + mac_add_count_after_trigger[dut]['dynamic']
            if dut == 'leaf0':
                if mac_add_count_after_trigger[dut]['dynamic'] == 0 and mac_add_count_after_trigger[dut]['static'] == mac_add_count[dut]['total']:
                    st.banner("MAC withdraw is as expected")
                else: 
                    st.banner("MAC withdraw is not as expected mac_count is {}".format(mac_add_count_after_trigger[dut]))
                    verify_result = False
            elif dut == 'leaf1' :
                if mac_add_count_after_trigger[dut]['dynamic'] == mac_add_count[dut]['total'] and mac_add_count_after_trigger[dut]['static'] == 0:
                    st.banner("MAC withdraw is as expected")
                else: 
                    st.banner("MAC withdraw is not as expected mac_count is {}".format(mac_add_count_after_trigger[dut]))
                    verify_result = False
            else:
                if mac_add_count_after_trigger[dut]['static'] == mac_add_count[dut]['static']:
                    st.banner("MAC withdraw is as expected")
                else: 
                    st.banner("MAC withdraw is not as expected mac_count is {}".format(mac_add_count_after_trigger[dut]))
                    verify_result = False
            
            st.wait(30)
            mac_verify_flag = True
            mac_address_failed = []
            #verify type 2 routes
            result_dict = vxlan_obj.validate_mac_type2_route(mac_address_list_leaf0_dynamic, host_local_node=['leaf1'], is_mh_host = True)
            for node, mac_addr in result_dict.items():
                for mac, result in mac_addr.items():
                    if not result:
                        st.error("MAC verification failed for MAC {} on node {}".format(mac, node))
                        mac_verify_flag = False

            if mac_verify_flag:
                st.banner("MAC verification passed")
            else:
                st.banner("MAC verification failed")
                verify_result = False
            st.wait(30)
                    
        #port channel member no shut
        intf_obj.interface_noshutdown('leaf0', pc_member_intf[0])   
        st.wait(120)    
    
        if verify_result:
            st.banner("MAC learn/withdraw after PortChannel member shut: Pass")
        else: 
            st.banner("MAC learn/withdraw after PortChannel member shut: Fail")
            st.report_fail("test_case_failed")

        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")
        st.report_pass('test_case_passed')

    #@pytest.mark.parametrize("tgen_scaled_mac_preconfig", [1000, 10000], indirect=True)
    def test_mac_learn_and_withdraw_with_pc_shut(self):
        #mac_count = 1000
        mac_count = self.mac_count
        st.log("Running test with MAC count is {}".format(mac_count))
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        mac_add_count = {}
        mac_address_list_leaf0_dynamic = mac_obj.get_mac_address_list('leaf0', vlan='510', type='Dynamic')
        mac_address_list_leaf1_dynamic = mac_obj.get_mac_address_list('leaf1', vlan='510', type='Dynamic')
        mac_address_list_leaf0_static = mac_obj.get_mac_address_list('leaf0', vlan='510', type='Static')
        mac_address_list_leaf1_static = mac_obj.get_mac_address_list('leaf1', vlan='510', type='Static')
        
        for dut in leaf_nodes:
            mac_add_count[dut] = {'static': mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Static')}
            mac_add_count[dut]['dynamic'] = mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Dynamic')
            mac_add_count[dut]['total'] = mac_add_count[dut]['static'] + mac_add_count[dut]['dynamic']
            if mac_add_count[dut]['total'] == mac_count:
                st.banner("MAC learn count is {}".format(mac_count))
            else: 
                st.banner("MAC learn count is not {} is {}".format(mac_count, mac_add_count[dut]['total']))
                st.report_fail("test_case_failed")
        st.wait(30)
        #port channel member shut

        pc_member_intf = pc_obj.get_portchannel_members('leaf0', 'PortChannel1')
        intf_obj.interface_shutdown('leaf0', 'PortChannel1')
        st.wait(30)
        #verify if macs are withdrawn
        mac_add_count_after_trigger = {}    
        for dut in leaf_nodes:
            mac_add_count_after_trigger[dut] = {'static': mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Static')}
            mac_add_count_after_trigger[dut]['dynamic'] = mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Dynamic')
            mac_add_count_after_trigger[dut]['total'] = mac_add_count_after_trigger[dut]['static'] + mac_add_count_after_trigger[dut]['dynamic']
            if dut == 'leaf0':
                if mac_add_count_after_trigger[dut]['dynamic'] == 0 and mac_add_count_after_trigger[dut]['static'] == mac_add_count[dut]['static']:
                    st.banner("MAC withdraw is as expected")
                else: 
                    st.banner("MAC withdraw is not as expected mac_count is {}".format(mac_add_count_after_trigger[dut]))
                    st.report_fail("test_case_failed")
            elif dut == 'leaf1' :
                if mac_add_count_after_trigger[dut]['dynamic'] == mac_add_count[dut]['dynamic'] and mac_add_count_after_trigger[dut]['static'] == 0:
                    st.banner("MAC withdraw is as expected")
                else: 
                    st.banner("MAC withdraw is not as expected mac_count is {}".format(mac_add_count_after_trigger[dut]))
                    st.report_fail("test_case_failed")
            else:
                if mac_add_count_after_trigger[dut]['static'] == mac_add_count[dut]['static'] - mac_add_count['leaf0']['dynamic']:
                    st.banner("MAC withdraw is as expected")
                else: 
                    st.banner("MAC withdraw is not as expected mac_count is {}".format(mac_add_count_after_trigger[dut]))
                    st.report_fail("test_case_failed")
            st.wait(30)
            mac_verify_flag = True
            mac_address_failed = []
            #verify type 2 routes
            result_dict_1 = vxlan_obj.validate_mac_type2_route(mac_address_list_leaf0_dynamic, host_local_node=['leaf0'], is_mh_host = True)
            result_dict_2 = vxlan_obj.validate_mac_type2_route(mac_address_list_leaf1_dynamic, host_local_node=['leaf1'], is_mh_host = True)

            for node, mac_addr in result_dict_1.items():
                for mac, result in mac_addr.items():
                    if result:
                        st.error("MAC verification failed for MAC {} on node {}".format(mac, node))
                        st.error("MAC is not withdrawn from node {}".format(node))
                        mac_address_failed.append(mac)
            
            if mac_address_failed:
                st.error("MAC verification failed for MACs {}".format(mac_address_failed))
                mac_verify_flag = False
            if mac_verify_flag:
                st.banner("MAC verification passed")
            else:
                st.banner("MAC verification failed")
                st.report_fail("test_case_failed")
            st.wait(30)
                    
        #port channel member no shut
        intf_obj.interface_noshutdown('leaf0', 'PortChannel1')       
    
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")
        st.report_pass('test_case_passed')

    def test_mac_learn_and_withdraw_with_lag_shut(self):

        mac_count = self.mac_count
        st.log("Running test with MAC count is {}".format(mac_count))
        leaf_nodes=[]
        dut_id = vars.dut_ids['leaf0']
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        mac_add_count = {}
        mac_address_list_leaf0_dynamic = mac_obj.get_mac_address_list('leaf0', vlan='510', type='Dynamic')
        mac_address_list_leaf1_dynamic = mac_obj.get_mac_address_list('leaf1', vlan='510', type='Dynamic')
        mac_address_list_leaf0_static = mac_obj.get_mac_address_list('leaf0', vlan='510', type='Static')
        mac_address_list_leaf1_static = mac_obj.get_mac_address_list('leaf1', vlan='510', type='Static')
        
        for dut in leaf_nodes:
            mac_add_count[dut] = {'static': mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Static')}
            mac_add_count[dut]['dynamic'] = mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Dynamic')
            mac_add_count[dut]['total'] = mac_add_count[dut]['static'] + mac_add_count[dut]['dynamic']
            if mac_add_count[dut]['total'] == mac_count:
                st.banner("MAC learn count is {}".format(mac_count))
            else: 
                st.banner("MAC learn count is not {} is {}".format(mac_count, mac_add_count[dut]['total']))
                st.report_fail("test_case_failed")
        st.wait(30)
        #port channel member shut

        pc_member_intf = pc_obj.get_portchannel_members('leaf0', 'PortChannel1')
        if not self._tgen_lag_intf_op_mode('down'):
            st.error("Failed to set interface to sim_disconnect")
            st.report_fail("test_case_failed")                
        st.wait(180)
        #verify if macs are withdrawn
        mac_add_count_after_trigger = {}    
        for dut in leaf_nodes:
            mac_add_count_after_trigger[dut] = {'static': mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Static')}
            mac_add_count_after_trigger[dut]['dynamic'] = mac_obj.get_mac_address_count(dut, vlan='510', mac_search = '00:51:00:00', type = 'Dynamic')
            mac_add_count_after_trigger[dut]['total'] = mac_add_count_after_trigger[dut]['static'] + mac_add_count_after_trigger[dut]['dynamic']
            if mac_add_count_after_trigger['dut']['total'] == 0:
                st.banner("MAC withdraw is as expected")
            else:
                st.banner("MAC withdraw is not as expected mac_count is {}".format(mac_add_count_after_trigger[dut]))
                st.report_fail("test_case_failed")
            
        # unshut the lag interface on Ixia
        if not self._tgen_lag_intf_op_mode('up'):
            st.error("Failed to set interface to normal")
            st.report_fail("test_case_failed")

        st.wait(180)
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")      
        st.report_pass('test_case_passed')     

@pytest.fixture(scope="class")
def tgen_local_bridged_config():
    '''
    config setup
    ixia stream setup

    Mac only --> first
    '''
   
    ### ADD DUT CONFIGS ###
    tc_id = 'test_local_bridged_traffic'
    test_cfg['tc_id'] = tc_id
    tc_cfg = vxlan_obj.get_tc_params(tc_id) 
    result = True
    
    selected_leaf_list = ['leaf0']
    topo_handles = tgen_handles['topo_handles']
    dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
    if dut_type == 'hw':
        pkts_per_burst=1000
        rate_percent = 1
    else:
        pkts_per_burst=200
        rate_percent = 0.01
    #intf = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')['leaf0']
    leaf0_tgen_intf = topo_handles['leaf0'].keys()

    for item in leaf0_tgen_intf:
        if "P1" in item:
            src_port =item
        if 'PortChannel' in item:
            dst_port = item
    
    tg_handle = topo_handles['leaf0'][src_port]['tg_handle']
    deviceGroup_handle_1 = tgen_handles['v4_device_handles'][src_port][tc_cfg['vlan_id']]
    deviceGroup_handle_2 = tgen_handles['v4_device_handles'][dst_port][tc_cfg['vlan_id']]

    deviceGroupv6_handle_1  = tgen_handles['v6_device_handles'][src_port][tc_cfg['vlan_id']]
    deviceGroupv6_handle_2  = tgen_handles['v6_device_handles'][dst_port][tc_cfg['vlan_id']]

    vxlan_obj.start_stop_protocols(tg_handle,'stop')
    st.wait(10)
    vxlan_obj.start_stop_protocols(tg_handle,'start')
    st.wait(10)

    #create traffic item for vrf 101
    stream = tg_handle.tg_traffic_config(
                    mode='create', 
                    bidirectional=1,
                    transmit_mode='single_burst', 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type='ipv4', 
                    frame_size='500', 
                    emulation_src_handle=deviceGroup_handle_1, 
                    emulation_dst_handle=deviceGroup_handle_2,
                    track_by = 'traffic_item',
                    )
    
    stream_id = stream["stream_id"] 
    stream_handles = {}
    stream_handles[1] = {}
    stream_handles[1]['stream_id'] = stream_id
    stream_handles[1]['tg_handle'] = tg_handle
    stream_handles[1]['verify_enabled'] = True
    stream_handles[1]['topo_handles'] = topo_handles
    stream_handles[1]['deviceGroup_handle_1'] = deviceGroup_handle_1
    stream_handles[1]['deviceGroup_handle_2'] = deviceGroup_handle_2
    stream_handles[1]['port_handle'] = topo_handles['leaf0'][src_port]['port_handle']

    #create traffic item 2 for v6
    stream = tg_handle.tg_traffic_config(
                    mode='create',
                    bidirectional=1,
                    transmit_mode='single_burst',
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent,
                    circuit_endpoint_type='ipv6',
                    frame_size='500',
                    emulation_src_handle=deviceGroupv6_handle_1,
                    emulation_dst_handle=deviceGroupv6_handle_2,
                    track_by = 'traffic_item',
                    )
    stream_id = stream["stream_id"]
    stream_handles[2] = {}
    stream_handles[2]['stream_id'] = stream_id
    stream_handles[2]['tg_handle'] = tg_handle
    stream_handles[2]['verify_enabled'] = True
    stream_handles[2]['topo_handles'] = topo_handles
    stream_handles[2]['deviceGroup_handle_1'] = deviceGroupv6_handle_1
    stream_handles[2]['deviceGroup_handle_2'] = deviceGroupv6_handle_2
    stream_handles[2]['port_handle'] = topo_handles['leaf0'][src_port]['port_handle']
    yield stream_handles
    #cleanup tgen
    tg_handle.tg_traffic_control(action='reset', port_handle=stream_handles[1]['port_handle'])
    topology_handles = [tgen_handles['topo_handles']['leaf0'][src_port]['topology_handle']]
    for topology in topology_handles:
        tg_handle.tg_topology_config(topology_handle =topology, mode = 'destroy')

@pytest.mark.usefixtures('tgen_health_check_class', 'tgen_local_bridged_config')
class TestLocalBridged():
    @pytest.fixture(autouse=True)
    def init_fixtures(self, request):
        self.handles = request.getfixturevalue('tgen_local_bridged_config')
    
    def get_interface_counters(self, dut, intf, counter_type):
        cli_output = st.show(dut, "show int counters", skip_tmpl=True)
        parsed_out = st.parse_show(dut, "show int counters",cli_output, "show_interfaces_counters.tmpl") 
        for output in parsed_out:
            if output['iface'] == intf:
                counter_uni = output[counter_type]
                counter = int(counter_uni.replace(',',''))
        return counter
                                               
    def test_local_bridged(self):
        max_retries = 5
        retry_delay = 2
        po_intf = pc_obj.get_portchannel_members('leaf0', 'PortChannel1')
         #Clear interface counters before doing the trigger 
        st.show('leaf0', "sonic-clear counters", skip_tmpl=True)
        #intf_obj.clear_interface_counters('leaf0')
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between single host and dual homed host passed")
        else:
            st.banner("traffic between single host and dual homed host failed")
            st.report_fail("test_case_failed")
        for attempt in range(max_retries):
            tx_interface_count = self.get_interface_counters('leaf0', po_intf[0] , 'tx_ok')
            if tx_interface_count >= 1000:
                st.banner("traffic received on PortChannel interface")
                break
            else:
                st.banner("No traffic received on PortChannel interface")
                st.wait(retry_delay)
        else:
            st.report_fail("test_case_failed")
        '''   
        tx_interface_count = self.get_interface_counters('leaf0', po_intf[0] , 'tx_ok')
        if tx_interface_count >= 1000:
            st.banner("traffic received on PortChannel interface")
        else:
            st.banner("No traffic received on PortChannel interface")
            st.report_fail("test_case_failed")
        '''
        po_intf_dual_home = pc_obj.get_portchannel_members('leaf1', 'PortChannel1')
        #Clear interface counters before doing the trigger
        st.show('leaf1', "sonic-clear counters", skip_tmpl=True)
        #intf_obj.clear_interface_counters('leaf1')    
        intf_obj.interface_shutdown('leaf0', po_intf[0])
        st.wait(60)
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between single host and dual homed host passed")
        else:
            st.banner("traffic between single host and dual homed host failed after link on Leaf0 is shutdown")
            st.report_fail("test_case_failed")  
        for attempt in range(max_retries):
            tx_interface_count_dual_home = self.get_interface_counters('leaf1', po_intf_dual_home[0] , 'tx_ok')
            if tx_interface_count_dual_home >= 1000:
                st.banner("traffic received on PortChannel interface")
                break
            else:
                st.banner("No traffic received on PortChannel interface")
                st.wait(retry_delay)
        else:
            st.report_fail("test_case_failed")
        '''
        tx_interface_count_dual_home = self.get_interface_counters('leaf1', po_intf_dual_home[0] , 'tx_ok')
        if tx_interface_count_dual_home >= 1000:
            st.banner("traffic received on PortChannel interface")
        else:
            st.banner("traffic not received on PortChannel interface of dual homed host")
            st.report_fail("test_case_failed")  
        '''   
        intf_obj.interface_noshutdown('leaf0', po_intf[0])
        st.wait(60)
        #clear counters on leaf0
        st.show('leaf0', "sonic-clear counters", skip_tmpl=True)
        #intf_obj.clear_interface_counters('leaf0')
        traffic_result = vxlan_obj.check_traffic(self.handles,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
        if traffic_result:
            st.banner("traffic between single host and dual homed host passed")
        else:
            st.banner("traffic between single host and dual homed host failed after link on Leaf0 is no shutdown")
            st.report_fail("test_case_failed")
        for attempt in range(max_retries):
            tx_interface_count = self.get_interface_counters('leaf0', po_intf[0] , 'tx_ok')
            if tx_interface_count >= 1000:
                st.banner("traffic received on PortChannel interface")
                break
            else:
                st.banner("No traffic received on PortChannel interface")
                st.wait(retry_delay)
        else:
            st.report_fail("test_case_failed")
        '''
        tx_interface_count = self.get_interface_counters('leaf0', po_intf[0] , 'tx_ok')
        if tx_interface_count >= 1000:
            st.banner("traffic received on PortChannel interface for local bridged traffic")
        else:
            st.banner("No traffic received on PortChannel interface of local bridged traffic on leaf0")
            st.report_fail("test_case_failed")
        '''

        st.report_pass('test_case_passed')


@pytest.mark.usefixtures('tgen_health_check_class')
class TestMoveExistingVlanToDiffVrf():
    def test_move_vlan_to_diff_vrf(self):
        """
        Testcase: Solution_test:MH:140 : Moving existing vlan to different vrf
        Description:
            Verify traffic going well after moving vlans to different vrf
        Steps:
            Verify move Vlan4 Vlan5 from Vrf102 to Vrf103
            Verify traffic going well
            Verify move Vlan4 Vlan5 back to Vrf102
            Verify traffic going well
        """
        tc_id = "test_move_vlan_to_diff_vrf"
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        duts = []
        result_str = ''

        st.banner("Testcase : Moving existing vlan to different Vrf")
        for d in test_cfg['nodes']['l2l3vni']:
            duts.append(d)

        st.log('Move vlan: {} from {} to {}'.format([v['id'] for v in tc_cfg['vlans']], tc_cfg['src_vrf'], tc_cfg['dst_vrf']))
        for dut in duts:
            cmd = ""
            for vlan in tc_cfg['vlans']:
                intf_obj.config_interface_vrf_binds(dut, {vlan['id']:{'vrf':""}}, 'no', cli_type='click')
                intf_obj.config_interface_vrf_binds(dut, {vlan['id']:{'vrf':tc_cfg['dst_vrf']}}, 'yes', cli_type='click')
                ip_obj.config_ip_addr_interface(dut, interface_name=vlan['id'], ip_address=vlan['ipv4'], subnet='24', family="ipv4", config='add', skip_error=True)
                ip_obj.config_ip_addr_interface(dut, interface_name=vlan['id'], ip_address=vlan['ipv6'], subnet='64', family="ipv6", config='add', skip_error=True)
                cmd += "sudo config vlan static-anycast-gateway enable {}\n".format(vlan["id"][-1])
            st.config(dut, cmd, skip_error_check=True)
        st.log('Verifying traffic after moving')
        if not pf.verify_traffic(tgen_handles):
            log = 'Verifying traffic after moving failed'
            st.banner(log)
            result_str += '{}\n'.format(log)

    
        st.log('Restore vlan: {} to vrf {}'.format([v['id'] for v in tc_cfg['vlans']], tc_cfg['src_vrf']))
        for dut in duts:
            cmd = ""
            for vlan in tc_cfg['vlans']:
                intf_obj.config_interface_vrf_binds(dut, {vlan['id']:{'vrf':""}}, 'no', cli_type='click')
                intf_obj.config_interface_vrf_binds(dut, {vlan['id']:{'vrf':tc_cfg['src_vrf']}}, 'yes', cli_type='click')
                ip_obj.config_ip_addr_interface(dut, interface_name=vlan['id'], ip_address=vlan['ipv4'], subnet='24', family="ipv4", config='add', skip_error=True)
                ip_obj.config_ip_addr_interface(dut, interface_name=vlan['id'], ip_address=vlan['ipv6'], subnet='64', family="ipv6", config='add', skip_error=True)
                cmd += "sudo config vlan static-anycast-gateway enable {}\n".format(vlan["id"][-1])
            st.config(dut, cmd, skip_error_check=True)
        st.log('Verifying traffic after restoring')
        if not pf.verify_traffic(tgen_handles):
            log = 'Verifying traffic after restoring failed'
            st.banner(log)
            result_str += '{}\n'.format(log)

        if not result_str:
            vxlan_obj.report_result(True, tc_id)
        else:
            vxlan_obj.report_result(False, tc_id, result_str)



###MISC TRIGGERS####
@pytest.mark.usefixtures("tgen_health_check_class")
class TestVxlanBasicAddDelTriggers():
    
    @staticmethod
    def enable_or_disable_existing_streams(mode='disable'):
        """
        Disable or enable existing streams.
        :param: mode <str> 'disable' or 'enable' options are acceptable.
        """
        if mode.lower() not in ('disable', 'enable'):
            raise ValueError("Unexpected mode: {}! Available ony 'disable' or 'enable' options!".format(mode))
        streams = []
        tg_handle = tgen_handles['topo_handles']['leaf0'][list(tgen_handles['topo_handles']['leaf0'].keys())[0]]['tg_handle']
        for traffic_type, item in tgen_handles.items():
            if traffic_type not in ['v6_device_handles', 'v4_device_handles', 'topo_handles', 'tg_handle']:
                for key, value in item.items():
                    streams.append(value['stream_id'])
        st.log("{} all existing streams...".format(mode.capitalize()))
        tg_handle.tg_traffic_config(mode=mode.lower(), stream_id=streams)
        tg_handle.tg_traffic_control(action='apply', stream_handle=streams)

    @staticmethod
    def get_triggers_inuse_interfaces(dut_list):
        """Get in use interfaces for triggers tests: PortChannel1 and <DUT_ID>T1P1"""
        inuse_ports = {dut: [] for dut in dut_list}
        for dut in dut_list:
            inuse_ports[dut].append(vars[vars["dut_ids"][dut]+"T1P1"])
            for port_channel in test_cfg[dut]['port_channels']:
                inuse_ports[dut].append('PortChannel{}'.format(port_channel["port_channel_num"]))
        return inuse_ports

    @staticmethod
    def get_triggers_out_of_use_interfaces(dut_list):
        """Get out of use interfaces for triggers tests - T1<DUT_ID>P3. E.g T1D5P3."""
        out_of_use_ports = {}
        for dut in dut_list:
            out_of_use_ports[dut] = "T1" + vars["dut_ids"][dut] + "P3"
        return out_of_use_ports

    def test_add_del_new_l2vni(self):
        st.banner("TEST Trigger add delete new L2VNI: Create and delete new l2vni and verify traffic.")
        selected_leaf_list = ['leaf0','leaf1']
        vlan_data = {'l2vni': {'vlan_start_range': 900,'count': 1}}
        l3vni_data = {
            'l2vni': {'vlan_start_range': 900,'count': 2},
            'l3vni': {'l3_dummy': {'start_vlan': 999, 'count': 1}}
        }
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        inuse_interfaces = self.get_triggers_inuse_interfaces(selected_leaf_list)
        out_of_use_interfaces = self.get_triggers_out_of_use_interfaces(selected_leaf_list)
        topo_handles = {device: {k: v for k, v in interfaces.items() if k != out_of_use_interfaces.get(device)}
                        for device, interfaces in tgen_handles["topo_handles"].items()}
        l2vni_intf_dict = deepcopy(test_cfg["l2vni_intf_dict"])
        for dut, interface in out_of_use_interfaces.items():
            l2vni_intf_dict[dut].remove(interface)

        ###ADD###
        for node in selected_leaf_list:
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data, inuse_interfaces[node])
            # Add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            # Add new vrf
            l3vni_config_out = vxlan_obj.generate_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_config_out, add=True)
            # Add sag ip
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111.111.111.1',
                subnet='24',
                family="ipv4",
                config='add',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111:111:111::1',
                subnet='64',
                family="ipv6",
                config='add',
                skip_error=True
            )
            # Enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            # bgp_l3vni_config
            config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data, bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)

        vxlan_obj.get_cli_out(selected_leaf_list)

        ###TRAFFIC###
        svi_dict_v4 = {'leaf0': {900: '111.111.111.1'},'leaf1': {900: '111.111.111.1'}}
        svi_dict_v6 = {'leaf0': {900: '111:111:111::1'},'leaf1': {900: '111:111:111::1'}}

        v4_host_info_dict = vxlan_obj.generate_sag_hosts(
            l2vni_intf_dict,
            svi_dict_v4,
            custom_mac_enable=True,
            custom_start_mac="00:00:00:00:98:10"
        )
        v6_host_info_dict = vxlan_obj.generate_sag_hosts(
            l2vni_intf_dict,
            svi_dict_v6,
            version="ipv6",
            custom_mac_enable=True,
            custom_start_mac="00:00:00:00:99:10"
        )

        # Create new device groups
        v4_node_device_handles = vxlan_obj.create_device_groups(topo_handles,v4_host_info_dict)[0]
        v6_node_device_handles = vxlan_obj.create_device_groups(topo_handles,v6_host_info_dict,version ="ipv6")[0]
        v4_device_handles = {}
        v6_device_handles = {}
        for node, interfaces in v4_node_device_handles.items():
            for interface,values in interfaces.items():
                v4_device_handles[interface] =values
        for node, interfaces in v6_node_device_handles.items():
            for interface,values in interfaces.items():
                v6_device_handles[interface] =values
        tg_handle = topo_handles[selected_leaf_list[0]][l2vni_intf_dict[selected_leaf_list[0]][0]]['tg_handle']

        ### Choose traffic endpoints###
        l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(v4_host_info_dict)

        # Disable old streams
        self.enable_or_disable_existing_streams(mode='disable')

        # Create new handles
        new_stream_handles = {}
        new_stream_handles['new_l2_v4'] = vxlan_obj.create_traffic_item(
            device_handles=v4_device_handles,
            endpoints=l2_traffic_endpoints,
            topo_handles=topo_handles
        )
        new_stream_handles['new_l2_v6'] = vxlan_obj.create_traffic_item(
            device_handles=v6_device_handles,
            endpoints=l2_traffic_endpoints,
            topo_handles=topo_handles,
            version="ipv6"
        )
        st.wait(5)
        flag = True
        for traffic_type, traffic_items in new_stream_handles.items():
            st.banner("Running {}".format(traffic_type))
            traffic_result = vxlan_obj.check_traffic(traffic_items, regenerate_traffic_items=True,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
            if traffic_result:
                st.banner("{} traffic passed".format(traffic_type))
            else:
                st.banner("{} traffic failed".format(traffic_type))
                flag = False

        ###DEL###
        for node in selected_leaf_list:
            # Disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            # Del sag ip
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111.111.111.1',
                subnet='24',
                family="ipv4",
                config='remove',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111:111:111::1',
                subnet='64',
                family="ipv6",
                config='remove',
                skip_error=True
            )
            # Del bgp l3vni
            config_out = vxlan_obj.delete_bgp_l3vni_config(l3vni_data, bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
            # Del sonic l3vni
            config_out = vxlan_obj.delete_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', config_out)
            # Del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out)
            # Del member
            for item in inuse_interfaces[node]:
                vlan_obj.delete_vlan_member(
                    node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk"
                )
            # Del vlan
            vlan_obj.delete_vlan(node,[900, 999])
        vxlan_obj.get_cli_out(selected_leaf_list)

        # Delete Tgen traffic items and device group
        # Traffic item del
        for traffic_type, traffic_items in new_stream_handles.items():
            for key, item in traffic_items.items():
                vxlan_obj.delete_traffic_item(item['tg_handle'],item['stream_id'])
        for port, values in v4_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        for port, values in v6_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        # Enable all streams
        self.enable_or_disable_existing_streams(mode='enable')
        if flag:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_add_del_new_l3vni(self):
        st.banner("TEST Trigger add delete new L3VNI: Create and delete new l3vni and verify traffic.")
        selected_leaf_list = ['leaf0','leaf1']
        vlan_data = {'l2vni': {'vlan_start_range': 900,'count': 2}}
        l3vni_data = {
            'l2vni': {'vlan_start_range': 900,'count': 2},
            'l3vni': {'l3_dummy': {'start_vlan': 999, 'count': 1}}
        }
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        inuse_interfaces = self.get_triggers_inuse_interfaces(selected_leaf_list)
        out_of_use_interfaces = self.get_triggers_out_of_use_interfaces(selected_leaf_list)
        topo_handles = {device: {k: v for k, v in interfaces.items() if k != out_of_use_interfaces.get(device)}
                        for device, interfaces in tgen_handles["topo_handles"].items()}
        l2vni_intf_dict = deepcopy(test_cfg["l2vni_intf_dict"])
        for dut, interface in out_of_use_interfaces.items():
            l2vni_intf_dict[dut].remove(interface)

        ###ADD###
        for node in selected_leaf_list:
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data, inuse_interfaces[node])
            # Add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            # Add new vrf
            l3vni_config_out = vxlan_obj.generate_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_config_out, add=True)
            # Add sag ip
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111.111.111.1',
                subnet='24',
                family="ipv4",
                config='add',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111:111:111::1',
                subnet='64',
                family="ipv6",
                config='add',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan901",
                ip_address='111.111.112.1',
                subnet='24',
                family="ipv4",
                config='add',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan901",
                ip_address='111:111:112::1',
                subnet='64',
                family="ipv6",
                config='add',
                skip_error=True
            )
            # enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            # bgp_l3vni_config
            config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data, bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        vxlan_obj.get_cli_out(selected_leaf_list)

        ###Traffic###
        # Generate host info
        svi_dict_v4 = {
            'leaf0': {900: '111.111.111.1', 901: '111.111.112.1'},
            'leaf1': {900: '111.111.111.1', 901: '111.111.112.1'}
        }
        svi_dict_v6 = {
            'leaf0': {900: '111:111:111::1', 901: '111:111:112::1'},
            'leaf1': {900: '111:111:111::1', 901: '111:111:112::1'}
        }
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(
            l2vni_intf_dict,
            svi_dict_v4,
            custom_mac_enable=True,
            custom_start_mac="00:00:00:00:91:10")
        v6_host_info_dict = vxlan_obj.generate_sag_hosts(
            l2vni_intf_dict,
            svi_dict_v6,
            version="ipv6",
            custom_mac_enable=True,
            custom_start_mac="00:00:00:00:92:10")

        # Create new device groups
        v4_node_device_handles = vxlan_obj.create_device_groups(topo_handles, v4_host_info_dict)[0]
        v6_node_device_handles = vxlan_obj.create_device_groups(topo_handles, v6_host_info_dict, version="ipv6")[0]
        v4_device_handles = {}
        v6_device_handles = {}
        for node, interfaces in v4_node_device_handles.items():
            for interface, values in interfaces.items():
                v4_device_handles[interface] = values
        for node, interfaces in v6_node_device_handles.items():
            for interface, values in interfaces.items():
                v6_device_handles[interface] = values

        ### Start all protocols ###
        tg_handle = topo_handles[selected_leaf_list[0]][l2vni_intf_dict[selected_leaf_list[0]][0]]['tg_handle']
        l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(v4_host_info_dict)
        l3_traffic_endpoints = vxlan_obj.find_l3_traffic_endpoints(v6_host_info_dict, vrf_vlan_dict={"1": [900, 901]})

        # Disable old streams
        self.enable_or_disable_existing_streams(mode='disable')

        # Create new handles
        new_stream_handles = {}
        new_stream_handles['new_l2_v4'] = vxlan_obj.create_traffic_item(
            device_handles=v4_device_handles, endpoints=l2_traffic_endpoints, topo_handles=topo_handles)
        st.wait(2)
        new_stream_handles['new_l2_v6'] = vxlan_obj.create_traffic_item(
            device_handles=v6_device_handles, endpoints=l2_traffic_endpoints, topo_handles=topo_handles, version="ipv6")
        st.wait(2)
        new_stream_handles['new_l3_v4'] = vxlan_obj.create_traffic_item(
            device_handles=v4_device_handles, endpoints=l3_traffic_endpoints, topo_handles=topo_handles)
        st.wait(2)
        new_stream_handles['new_l3_v6'] = vxlan_obj.create_traffic_item(
            device_handles=v6_device_handles, endpoints=l3_traffic_endpoints, topo_handles=topo_handles, version="ipv6")
        st.wait(10)
        ### Run traffic ###
        flag = True
        for traffic_type, traffic_items in new_stream_handles.items():
            st.banner("Running {}".format(traffic_type))
            traffic_result = vxlan_obj.check_traffic(traffic_items, regenerate_traffic_items=True,
                                   stop_proto_wait = test_cfg['global']['traffic_stop_protocol_sleep'],
                                   start_proto_wait = test_cfg['global']['traffic_start_protocol_sleep'])
            if traffic_result:
                st.banner("{} traffic passed".format(traffic_type))
            else:
                st.banner("{} traffic failed".format(traffic_type))
                flag = False

        ###DEL###
        # Config cleanup
        for node in selected_leaf_list:
            # Disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd)
            # Del sag ip
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111.111.111.1',
                subnet='24',
                family="ipv4",
                config='remove',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan900",
                ip_address='111:111:111::1',
                subnet='64',
                family="ipv6",
                config='remove',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan901",
                ip_address='111.111.112.1',
                subnet='24',
                family="ipv4",
                config='remove',
                skip_error=True
            )
            ip_obj.config_ip_addr_interface(
                node,
                interface_name="Vlan901",
                ip_address='111:111:112::1',
                subnet='64',
                family="ipv6",
                config='remove',
                skip_error=True
            )
            # Del bgp l3vni
            config_out = vxlan_obj.delete_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
            # Del sonic l3vni
            config_out = vxlan_obj.delete_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', config_out)
            # Del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out)
            # Del member
            for item in inuse_interfaces[node]:
                vlan_obj.delete_vlan_member(
                    node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk"
                )
                vlan_obj.delete_vlan_member(
                    node, 901 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk"
                )
            # Del vlan
            vlan_obj.delete_vlan(node,[900, 901, 999])
        vxlan_obj.get_cli_out(selected_leaf_list)
        # Tgen cleanup
        for traffic_type, traffic_items in new_stream_handles.items():
            for key, item in traffic_items.items():
                vxlan_obj.delete_traffic_item(item['tg_handle'],item['stream_id'])
        for port, values in v4_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        for port, values in v6_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        # Enable old streams
        self.enable_or_disable_existing_streams(mode='enable')
        if flag:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

