import pytest
from spytest import st
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import vxlan_helper as vxlan_obj
import profile 
import apis.system.interface as interface_obj
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj
from spytest.utils import poll_wait
from utilities.utils import get_intf_short_name

"""
Test cases for VXLAN with external router connectivity (northbound peering) testing.
Topology: 4 leaf and 4 spine with 1 external router connected to leaf3 
"""

@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    global vars, nodes, pf, test_cfg    
    global CONFIGS_FILE
    CONFIGS_FILE = 'vxlan_ext_conn_input.yaml'

    test_cfg = {
        'ext_sub_int_vlan_id': 201,
        'ref_vrf': 0,
        'ext_addr': '21.1.1.2',
        'ext_v6addr': '2100:1:1::2',
        'lb_dut': 'leaf3',
        'l0_dut': 'leaf0',
        'lb_addr': '21.1.1.1',
        'lb_v6addr': '2100:1:1::1',
        'ext_asn_no': "65204",
        'vrf_num': 'Vrf101',
        'org_bgp_cfg_ext': '',
        'host_addr_1': '90.0.0.1',
        'host_mask_1': '24',
        'host_gateway_1': '80.2.0.10'
    }
    vars = st.get_testbed_vars()
    for req_dev in ['external_router', test_cfg['lb_dut'], test_cfg['l0_dut']]:
        if req_dev not in st.get_dut_names():
            st.report_fail("test_case_failed", "Required device {} not found in the topology".format(req_dev))
    nodes = st.get_dut_names()
    leaf_nodes = [dut for dut in st.get_dut_names() if "leaf" in dut]
    spine_nodes = [dut for dut in st.get_dut_names() if "spine" in dut]
    pf = profile.VxlanProfile(input_file=CONFIGS_FILE, vars=vars, topo_type=st.getenv("topo", "4s4l"), 
                                          leaf_nodes=leaf_nodes, spine_nodes=spine_nodes)
    
@pytest.fixture(scope="module", autouse=True)
def copy_default_config_db():
    cmd = "sudo cp /etc/sonic/config_db.json config_db.json.orig"
    for dut in st.get_dut_names():
        st.config(dut, cmd, skip_error_check=True) 

@pytest.fixture(scope="module", autouse=True)
def vxlan_config():

    st.log("Configuring VXLAN profile")
    pf.configure_sonic()
    st.wait(60)
    yield
    st.log("Un-Configuring VXLAN profile")
    pf.configure_sonic(config=False)

@pytest.fixture(scope="class", autouse=True)
def configure_external_router(request):
    global test_cfg
    selected_dut = ""
    for dut in st.get_dut_names():
        if "external" in dut:
            selected_dut = dut
    cli_output = st.show(test_cfg['lb_dut'], "show vrf", skip_tmpl=True)
    parsed_output = st.parse_show(test_cfg['lb_dut'], "show vrf",cli_output, "show_vrf.tmpl")
    test_cfg['ref_vrf'] = parsed_output[0]['vrfname']
    
    #config loopback
    ip_obj.config_ip_addr_interface(selected_dut, interface_name="Loopback0", ip_address='30.100.100.100', subnet='32', family="ipv4", config='add', skip_error=True)
    #Config Vrf
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = test_cfg['ref_vrf'], config = 'yes')
    # find the port connected to leaf
    ext_dut_id = vars.dut_ids['external_router']
    leaf_dut_id = vars.dut_ids[test_cfg['lb_dut']]
    for node,dut_id in vars.dut_ids.items():
        if dut_id == ext_dut_id or dut_id == leaf_dut_id :
            for key,value in vars.items():
                if ext_dut_id+leaf_dut_id in key:
                    ext_dut_int = get_intf_short_name(value + '.' + str(test_cfg['ext_sub_int_vlan_id']))
                if leaf_dut_id+ext_dut_id in key:
                    leaf_int = get_intf_short_name(value + '.' + str(test_cfg['ext_sub_int_vlan_id']))
                if ext_dut_id+"T1P1" in key:
                    ext_tgen_int = value
    #find the port connected to VM host
    #Config ip address on interfaces
    ip_obj.config_sub_interface(dut = test_cfg['lb_dut'], intf = leaf_int, vlan = test_cfg['ext_sub_int_vlan_id'])
    vrf_obj.bind_vrf_interface(dut = test_cfg['lb_dut'], vrf_name = test_cfg['ref_vrf'], intf_name =leaf_int)
    ip_obj.config_ip_addr_interface(test_cfg['lb_dut'], interface_name=leaf_int, ip_address=test_cfg['lb_addr'], subnet='24', family="ipv4", config='add', skip_error=True)
    ip_obj.config_ip_addr_interface(test_cfg['lb_dut'], interface_name=leaf_int, ip_address=test_cfg['lb_v6addr'], subnet='64', family="ipv6", config='add', skip_error=True)
    ip_obj.config_sub_interface(dut = selected_dut, intf = ext_dut_int, vlan = test_cfg['ext_sub_int_vlan_id'])
    vrf_obj.bind_vrf_interface(dut = selected_dut, vrf_name = test_cfg['ref_vrf'], intf_name =ext_dut_int)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name=ext_dut_int, ip_address=test_cfg['ext_addr'], subnet='24', family="ipv4", config='add', skip_error=True)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name=ext_dut_int, ip_address=test_cfg['ext_v6addr'], subnet='64', family="ipv6", config='add', skip_error=True)
    #config external host int
    vrf_obj.bind_vrf_interface(dut = selected_dut, vrf_name = test_cfg['ref_vrf'], intf_name =ext_tgen_int)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name=ext_tgen_int, ip_address='42.1.1.1', subnet='24', family="ipv4", config='add', skip_error=True)

    #configure bgp on lb leaf
    leaf_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
    cmd = "router bgp {} vrf {}\nbgp router-id 50.50.50.2\n".format(leaf_asn_no, test_cfg['ref_vrf'])
    cmd += "no bgp ebgp-requires-policy\nno bgp network import-check\n"
    cmd += "neighbor {} remote-as {}\nend\nexit\n".format(test_cfg['ext_addr'], test_cfg['ext_asn_no'])
    st.banner(cmd)
    vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd)
    #configure bgp on external router
    test_cfg['org_bgp_cfg_ext'] = "router bgp {} vrf {}\nbgp router-id 50.50.50.1\nno bgp ebgp-requires-policy\nno bgp network import-check\n".format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
    test_cfg['org_bgp_cfg_ext'] += "neighbor {} remote-as {}\n".format(test_cfg['lb_addr'], leaf_asn_no)
    test_cfg['org_bgp_cfg_ext'] += "address-family ipv4 unicast\nnetwork 42.1.1.0/24\nexit-address-family\nend\nexit"
    vxlan_obj.config_dut(selected_dut, 'bgp', test_cfg['org_bgp_cfg_ext'])
    st.wait(10)
    cmd = "show bgp vrf {} summary".format(test_cfg['ref_vrf'])
    st.show(test_cfg['lb_dut'], cmd, type='vtysh', skip_tmpl=True)
    st.show(selected_dut, cmd, type='vtysh', skip_tmpl=True)
    yield
    ###unconfig on lb leaf
    #bgp
    leaf_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
    cmd = "no router bgp {} vrf {}".format(leaf_asn_no, test_cfg['ref_vrf'])
    ###unconfig external router
    #bgp
    cmd = "no router bgp {} vrf {}\nend\nexit".format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
    vxlan_obj.config_dut(selected_dut, 'bgp', cmd)
    #interface
    ip_obj.config_sub_interface(dut = test_cfg['lb_dut'], intf = leaf_int, vlan = test_cfg['ext_sub_int_vlan_id'], config = 'no')
    ip_obj.config_sub_interface(dut = selected_dut, intf = ext_dut_int, vlan = test_cfg['ext_sub_int_vlan_id'], config = 'no')
    #sonic
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = test_cfg['ref_vrf'], config = 'no')

@pytest.fixture(scope="class", autouse=True)
def tgen_preconfig_1():
    #Src port selection
    selected_leaf_list = ['leaf0']
    dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
    if dut_type == 'hw':
        pkts_per_burst=1000
        rate_percent = 10
    else:
        pkts_per_burst=200
        rate_percent = 0.01
    intf = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')['leaf0']
    for item in intf:
        if "P1" in item:
            src_port =item
    #Dst port selection
    tgen_ports = dict(vars.tgen_ports)
    ext_dut_id = vars.dut_ids['external_router']
    for key in tgen_ports:
        if ext_dut_id in key and "P1" in key:
            dst_port = key
    intf = {'leaf0':[src_port],'external_router':[dst_port]}
    
    topo_handles = vxlan_obj.create_topology_handles(intf)
    tg_handle = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['tg_handle'] 
    #Create device groups
    device_group_1 = tg_handle.tg_topology_config(
                    topology_handle= topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['topology_handle'],
                    device_group_name= """leaf0 src device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_1 = device_group_1['device_group_handle']
    device_group_2 = tg_handle.tg_topology_config(
                    topology_handle= topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['topology_handle'],
                    device_group_name= """external dst device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_2 = device_group_2['device_group_handle']
    
    #create eth stack
    #get vlan variable
    l2_protocol_1 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack 1 """,
            protocol_handle= deviceGroup_handle_1,mtu= "1500",
            src_mac_addr= '00:10:00:00:10:20',
            src_mac_addr_step= "00.00.00.00.00.01",
            vlan=1,
            vlan_id=2, 
            vlan_id_step=1,
            vlan_id_count=1
        )
    ethernet_handle_1 = l2_protocol_1['ethernet_handle']
    l2_protocol_2 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack 2 """,
            protocol_handle= deviceGroup_handle_2,mtu= "1500",
            src_mac_addr= '00:10:00:00:10:30',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
    ethernet_handle_2 = l2_protocol_2['ethernet_handle']
    
    #create v4 stack
    #get ip variable
    l3_protocol_1 = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle_1,
            ipv4_resolve_gateway= "1",
            gateway= '80.2.0.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '80.2.0.10',
            intf_ip_addr_step= "0.0.0.1"
            )
    ipv4_handle_1 = l3_protocol_1['ipv4_handle']
    
    l3_protocol_2 = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle_2,
            ipv4_resolve_gateway= "1",
            gateway= '42.1.1.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '42.1.1.2',
            intf_ip_addr_step= "0.0.0.1"
            )
    ipv4_handle_2 = l3_protocol_2['ipv4_handle']
    
    vxlan_obj.start_stop_protocols(tg_handle,'start')
    st.wait(10)

    #create traffic item
    stream = tg_handle.tg_traffic_config(
                    port_handle = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['port_handle'],
                    port_handle2 = topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['port_handle'],
                    mode='create', 
                    bidirectional=1,
                    transmit_mode='single_burst', 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type='ipv4', 
                    frame_size='500', 
                    emulation_src_handle=deviceGroup_handle_1, 
                    emulation_dst_handle=deviceGroup_handle_2
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
    stream_handles[1]['port_handle'] = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['port_handle']


    #create traffic item for static / network route
    ext_dut = 'external_router'
    tgn_id = vars.tgen_list[0]
    ext_dut_tgn_p1 =  vars.get(ext_dut_id+tgn_id+'P1')
    mac_dest = basic_obj.get_ifconfig_ether(ext_dut, ext_dut_tgn_p1)
    stream = tg_handle.tg_traffic_config(
                        port_handle = topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['port_handle'],
                        port_handle2 = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['port_handle'],
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src='00:0a:01:00:00:01',
                        mac_dst=mac_dest,
                        ip_dst_addr = test_cfg['host_addr_1'],
                        ip_src_addr = "42.1.1.2"
                        )
    stream_id = stream["stream_id"]
    stream_handles[2] = {}
    stream_handles[2]['stream_id'] = stream_id
    stream_handles[2]['tg_handle'] = tg_handle
    stream_handles[2]['verify_enabled'] = False
    stream_handles[2]['port_handle'] = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['port_handle']

    test_cfg['handles'] = stream_handles
    yield stream_handles
    #cleanup tgen
    tg_handle.tg_traffic_control(action='reset', port_handle=stream_handles[1]['port_handle'])
    topology_handles = [topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['topology_handle'], topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['topology_handle']]
    for topology in topology_handles:
        tg_handle.tg_topology_config(topology_handle =topology, mode = 'destroy')


@pytest.mark.usefixtures('configure_external_router', 'tgen_preconfig_1')
class TestSingleTenant():
    '''
    ebgp via routed interface

    '''
        
    def test_basic_traffic_check(self):
        st.banner("Base Traffic check")
        traffic_result = vxlan_obj.check_traffic(test_cfg['handles'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")

    def test_bgp_authentication(self):
        """
        Configure authentication between border leaf and external router
        * configure bgp neighbor password on leaf and check neighbor goes down
        * cofnigure bgp neighbor password on ext peer and verify neighbor comes up
        * verify traffic
        * unconfigure password and verify neighbor is up
        * verify traffic
        """
        st.banner("Configure authentication between border leaf and external router")
        result = True
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')
        password = 'abcd!@#$1234'
        lb_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure bgp neighbor password on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'neighbor {} password {}\nend\nexit'.format(test_cfg['ext_addr'], password)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify if bgp neighbor is down on leaf and external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="down",
                                              vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="down")
            st.log('Bgp neighbor down verifcation: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor down verifcation: Fail ({})'.format(str(err)))
            result = False

        if result:
            st.log('Configure bgp neighbor password on external dut {}'.format(ext_dut))
            cmd = 'router bgp {} vrf {}\n'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
            cmd += 'neighbor {} password {}\nend\nexit'.format(test_cfg['lb_addr'], password)
            st.banner(cmd)
            vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

            st.log('Verify if bgp neighbor is up on leaf and external router')
            try: 
                vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="up",
                                                  vl_retries=2, vl_interval=5)
                vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up")
                st.log('Bgp neighbor up verifcation: Pass')
            except vxlan_obj.VerifyBgpIpv4Summary as err:
                st.error('Bgp neighbor up verifcation: Fail ({})'.format(str(err)))
                result = False

            if result:
                st.log('Verify traffic with bgp neighbor authentication on leaf and external router')
                if vxlan_obj.check_traffic(test_cfg['handles']):
                    st.log("Traffic between vxlan host and ext host with bgp authentication passed")
                else:
                    st.error("Traffic between vxlan host and ext host with bgp authentication failed")
                    result = False

            st.log('Un-Configure bgp neighbor password on external dut {}'.format(ext_dut))
            cmd = 'router bgp {} vrf {}\n'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
            cmd += 'no neighbor {} password {}\nend\nexit'.format(test_cfg['lb_addr'], password)
            st.banner(cmd)
            vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 
        
        st.log('Un-Configure bgp neighbor password on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'no neighbor {} password {}\nend\nexit'.format(test_cfg['ext_addr'], password)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify if bgp neighbor is up on leaf and external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="up",
                                              vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up")
            st.log('Bgp neighbor up verifcation after unconfig: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor up verifcation after unconfig: Fail ({})'.format(str(err)))
            result = False

        st.log('Verify traffic after remove bgp neighbor authentication on leaf and external router')
        if vxlan_obj.check_traffic(test_cfg['handles']):
            st.log("Traffic between vxlan host and ext host after removing bgp authentication passed")
        else:
            st.error("Traffic between vxlan host and ext host after removing bgp authentication failed")
            result = False

        if result:
            st.banner("BGP authentication verification between leaf and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP authentication verification between leaf and ext host failed")
            st.report_fail("test_case_failed")

    def test_bgp_prepend_replace_as(self):
        """
        Configure prepend and replace AS between border leaf and external router at border leaf
        * configure bgp neighbor local-as and no-prepend
        * verify bgp neighbor goes down
        * configure bgp neighbor remote-as on ext peer
        * verify bgp neighbor state/AS, bgp route AS path and traffic 
        * configure bgp neighbor remove-private-as on leaf router
        * verify bgp bgp route AS path and traffic 
        * unconfigure bgp neighbor remove-private-as on leaf router
        * configure bgp neighbor replace-as 
        * verify bgp neighbor state/AS, bgp route AS path and traffic 
        * unconfigure all AS path congigurations
        * verify bgp neighbor state/AS, and traffic 
        """
        st.banner("Configure prepend and replace AS between border leaf and external router at border leaf")
        result = True
        new_local_as = '200'
        lb_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure local AS on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'neighbor {} local-as {} no-prepend\nend\nexit'.format(test_cfg['ext_addr'], new_local_as)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify if bgp neighbor down state on external router')

        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="down",
                                              vl_retries=6)
            st.log('Bgp neighbor down and AS number verifcation : Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor and AS number verifcation : Fail ({})'.format(err))
            result = False

        if result:
            st.log('Configure remote AS on external dut {}'.format(ext_dut))
            cmd = 'router bgp {} vrf {}\n'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
            cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['lb_addr'], new_local_as)
            st.banner(cmd)
            vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

            st.log('Verify if bgp neighbor up state and AS number on external router')
            try: 
                vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], 
                                              state="up", as_num=new_local_as, vl_retries=6)
                st.log('Bgp neighbor up and AS number verifcation : Pass')
            except vxlan_obj.VerifyBgpIpv4Summary as err:
                st.error('Bgp neighbor and AS number verifcation : Fail ({})'.format(str(err)))
                result = False

            st.log('Verify bgp AS path on external router for route with local-as')
            try:
                expect_path = '{} {}'.format(new_local_as, lb_asn_no)
                vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['lb_addr'],
                                                  vrf=test_cfg['vrf_num'], as_path=expect_path, vl_retries=5)
                st.log('Bgp route AS path with local-as verifcation : Pass')
            except vxlan_obj.VerifyBgpIpv4Unicast as err:
                st.error('Bgp route AS path with local-as verifcation : Fail')
                result = False

            if result:
                st.log('Verify traffic with bgp local-as path for route')
                if vxlan_obj.check_traffic(test_cfg['handles']):
                    st.log("Traffic between vxlan host and ext host with bgp local-as passed")
                else:
                    st.error("Traffic between vxlan host and ext host with bgp local-as failed")
                    result = False

            st.log('Configure remove-private-as on leaf {}'.format(test_cfg['lb_dut']))
            cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
            cmd += 'address-family ipv4 unicast\n'
            cmd += 'neighbor {} remove-private-AS all\n'.format(test_cfg['ext_addr'])
            cmd += 'exit-address-family\nend\nexit'
            st.banner(cmd)
            vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

            st.log('Verify bgp AS path on ext router for route with remove-private-as')
            try:
                expect_path = '{}'.format(new_local_as)
                vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['lb_addr'],
                                                  vrf=test_cfg['vrf_num'], as_path=expect_path, vl_retries=5)
                st.log('Bgp route AS path with local-as verifcation : Pass')
            except vxlan_obj.VerifyBgpIpv4Unicast as err:
                st.error('Bgp route AS path with local-as verifcation : Fail')
                result = False

            if result:
                st.log('Verify traffic with bgp remove-privae-as path for route')
                if vxlan_obj.check_traffic(test_cfg['handles']):
                    st.log("Traffic between vxlan host and ext host with bgp local-as passed")
                else:
                    st.error("Traffic between vxlan host and ext host with bgp local-as failed")
                    result = False

            st.log('Un-Configure remove-private-as on leaf {}'.format(test_cfg['lb_dut']))
            cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
            cmd += 'address-family ipv4 unicast\n'
            cmd += 'no neighbor {} remove-private-AS all\n'.format(test_cfg['ext_addr'])
            cmd += 'exit-address-family\nend\nexit'
            st.banner(cmd)
            vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

            st.log('Verify bgp AS path on ext router for route with unconfig remove-private-as')
            try:
                expect_path = '{} {}'.format(new_local_as, lb_asn_no)
                vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['lb_addr'],
                                                  vrf=test_cfg['vrf_num'], as_path=expect_path, vl_retries=5)
                st.log('Bgp route AS path with local-as verifcation : Pass')
            except vxlan_obj.VerifyBgpIpv4Unicast as err:
                st.error('Bgp route AS path with local-as verifcation : Fail')
                result = False

            st.log('Configure replace AS on leaf {}'.format(test_cfg['lb_dut']))
            cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
            cmd += 'neighbor {} local-as {} no-prepend replace-as\nend\nexit'.format(test_cfg['ext_addr'], new_local_as)
            st.banner(cmd)
            vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd)

            try: 
                vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], 
                                              state="up", as_num=new_local_as, vl_retries=6)
                st.log('Bgp neighbor up and AS number verifcation : Pass')
            except vxlan_obj.VerifyBgpIpv4Summary as err:
                st.error('Bgp neighbor and AS number verifcation : Fail {}'.format(str(err)))
                result = False

            st.log('Verify bgp AS path on external router for route with local-as + replace-as')
            try:
                expect_path = '{}'.format(new_local_as)
                vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['lb_addr'],
                                                  vrf=test_cfg['vrf_num'], as_path=expect_path, vl_retries=5)
                st.log('Bgp route AS path with local-as + replace-as verifcation : Pass')
            except vxlan_obj.VerifyBgpIpv4Unicast as err:
                st.error('Bgp route AS path with local-as + replace-as verificstion : Fail {}'.format(str(err)))
                result = False

            if result:
                st.log('Verify traffic with bgp local-as+replace-as path for route')
                if vxlan_obj.check_traffic(test_cfg['handles']):
                    st.log("Traffic between vxlan host and ext host with bgp local-as+replace-as passed")
                else:
                    st.error("Traffic between vxlan host and ext host with bgp local-as+replace-as failed")
                    result = False
            
            st.log('Restore BGP remote AS on external dut {}'.format(ext_dut))
            cmd = 'router bgp {} vrf {}\n'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
            cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['lb_addr'], lb_asn_no)
            st.banner(cmd)
            vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Restore BGP AS path on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'no neighbor {} local-as {} no-prepend replace-as\nend\nexit'.format(test_cfg['ext_addr'], new_local_as)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify if bgp neighbor is up on external router after restoring BGP AS path configs')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up", 
                                              as_num=lb_asn_no, vl_retries=6)
            st.log('Bgp neighbor up verifcation after config restore: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary:
            st.error('Bgp neighbor up verifcation after config restore: Fail ({})'.format(str(err)))
            result = False

        st.log('Verify traffic after BGP AS path configs restore')
        if vxlan_obj.check_traffic(test_cfg['handles']):
            st.log("Traffic between vxlan host and ext host after BGP AS path configs restore passed")
        else:
            st.error("Traffic between vxlan host and ext host after BGP AS path configs restore failed")
            result = False

        if result:
            st.banner("BGP Local-AS verification passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP Local-AS verification failed")
            st.report_fail("test_case_failed")

    def test_bgp_network_aggregation(self):
        """
        Configure summary-only on border leaf and verify route distribution
        * configure bgp neighbor summary-only
        * verify bgp summary route present and specific route
        *   not present on external router and traffic 
        * unconfigure bgp neighbor summary-only
        * verify bgp summary route not present and specific route
        *   present on external router and traffic 
        """
        st.banner("Configure summary-only on border leaf and verify route distribution")
        result = True
        summary_route = '80.0.0.0'
        summary_mask = '8'
        advt_route = '80.2.0.0'
        advt_mask = '24'
        lb_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure summary-only on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'address-family ipv4 unicast\n'
        cmd += 'aggregate-address {}/{} summary-only \n'.format(summary_route, summary_mask)
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify bgp summary route on external router')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=advt_route, 
                                                     vrf=test_cfg['vrf_num'], prefix_ip=summary_route,
                                                     prefix_mask=summary_mask, vl_retries=5)
            st.log('Bgp route prefix ip with aggregation verifcation : Pass')
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.error('Bgp route prefix ip with aggregation verifcation : Fail')
            result = False

        if result:
            st.log('Verify traffic with bgp route aggreatioin')
            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host with route aggreatioin passed")
            else:
                st.error("Traffic between vxlan host and ext host with route aggreatioin failed")
                result = False
        st.log('Un-Configure summary-only on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'address-family ipv4 unicast\n'
        cmd += 'no aggregate-address {}/{} summary-only \n'.format(summary_route, summary_mask)
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify bgp no summary route on external router. Route restored.')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=advt_route, 
                                                     vrf=test_cfg['vrf_num'], prefix_ip=advt_route,
                                                     prefix_mask=advt_mask, vl_retries=5)
            st.log('Bgp route prefix ip with no aggregation verifcation. Route restore : Pass')
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.error('Bgp route prefix ip with no aggregation verifcation. Route restore : Fail')
            result = False
        
        st.log('Verify bgp no summary route on external router. Summary route removed')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=summary_route, 
                                                     vrf=test_cfg['vrf_num'], vl_retries=5)
            st.error('Bgp route prefix ip with no aggregation verifcation.'
                     'Summary route removed : Fail')
            result = False
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.log('Bgp route prefix ip with no aggregation verifcationa.'
                    'Summary route removed : Pass')

        st.log('Verify traffic with bgp no route aggreatioin')
        if vxlan_obj.check_traffic(test_cfg['handles']):
            st.log("Traffic between vxlan host and ext host with no route aggreatioin passed")
        else:
            st.error("Traffic between vxlan host and ext host with no route aggreatioin failed")
            result = False
        if result:
            st.banner("BGP network aggregation verification passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP network aggregation verification failed")
            st.report_fail("test_case_failed")


    def test_bgp_rpl_set_community(self):
        """
        Configure BGP route-map RPL and set community for route
        * configure prefix-list , rpl and bgp neighbor route-map out
        * verify bgp route on external router with community attribute set. verify traffic
        * unconfigure all new configs
        * verify bgp route on external router with community attribute unset. verify traffic
        """
        st.banner("Configure BGP route-map RPL and set community for route")
        result = True
        advt_route_1 = '80.2.0.0'
        advt_route_2 = '80.3.0.0'
        host_mask = '24'
        rpl_name =  'set_community'
        prefix_list = 'match_host'
        community = '987:654'
        lb_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure prefix-list, rpl and bgp neighbor route-map on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'ip prefix-list {} seq 5 permit {}/{}\n'.format(prefix_list, advt_route_1, host_mask)
        cmd += 'ip prefix-list {} seq 10 permit {}/{}\n'.format(prefix_list, advt_route_2, host_mask)
        cmd += 'route-map {} permit 10\n match ip address prefix-list {}\n'.format(rpl_name, prefix_list)
        cmd += 'set community {}\n exit\n'.format(community)
        cmd += 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += ' neighbor {} route-map {} out\nend\nexit'.format(test_cfg['ext_addr'], rpl_name)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify bgp route on external router has community set')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=advt_route_1, 
                                                     vrf=test_cfg['vrf_num'], community=community, vl_retries=5)
            st.log('Bgp route community verifcation : Pass')
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.error('Bgp route community verifcation : Fail')
            result = False

        if result:
            st.log('Verify traffic with bgp route community')
            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host with route community passed")
            else:
                st.error("Traffic between vxlan host and ext host with route community failed")
                result = False

        st.log('Un-Configure prefix-list, rpl and bgp neighbor route-map on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += ' no neighbor {} route-map {} out\n'.format(test_cfg['ext_addr'], rpl_name)
        cmd += 'no route-map {} permit 10\n'.format(rpl_name)
        cmd += 'no ip prefix-list {}\nend\nexit'.format(prefix_list)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify bgp route on external router has no community set')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=advt_route_1, 
                                                     vrf=test_cfg['vrf_num'], community=community, vl_retries=5)
            st.error('Bgp route community verifcation : Fail')
            result = False
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.log('Bgp route community verifcation : Pass')

        st.log('Verify traffic with no bgp route community')
        if vxlan_obj.check_traffic(test_cfg['handles']):
            st.log("Traffic between vxlan host and ext host with no route community passed")
        else:
            st.error("Traffic between vxlan host and ext host with no route community failed")
            result = False
        if result:
            st.banner("BGP RPL set community passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP RPL set community failed")
            st.report_fail("test_case_failed")


    def test_bgp_4byte_AS(self):
        """
        Configure BGP 4 Byte AS on external router and verify bgp peering
        * configure 4 Byte BGP AS on external router . Update neighbor config on leaf
        * verify neighbor comes up and traffic flowing
        * restore 2 Byte BGP AS on external router and leaf
        * verify neighbor comes up
        """
        st.banner("Configure BGP 4 Byte AS on external router and verify bgp peering")
        result = True
        as_4byte = '4294967295'
        lb_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure bgp neighbor on leaf dut {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['ext_addr'], as_4byte)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('UnConfigure bgp neighbor on external dut {}'.format(ext_dut))
        cmd = 'no router bgp {} vrf {}\nend\nexit'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Configure bgp 4 Byte AS on external dut {}'.format(ext_dut))
        cmd = test_cfg['org_bgp_cfg_ext'].replace(test_cfg['ext_asn_no'], as_4byte)
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Verify if bgp neighbor is up with 4 byte AS on leaf and external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="up",
                                              as_num=as_4byte, vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up",
                                              as_num=lb_asn_no)
            st.log('Bgp neighbor up verifcation: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor up verifcation: Fail ({})'.format(str(err)))
            result = False

        if result:
            st.log('Verify traffic with bgp 4 Byte AS')
            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host with bgp 4 byte AS passed")
            else:
                st.error("Traffic between vxlan host and ext host with bgp 4 byte AS failed")
                result = False

        st.log('Un-Configure bgp 4 Byte AS on external dut {}'.format(ext_dut))
        cmd = 'no router bgp {} vrf {}\nend\nexit'.format(as_4byte, test_cfg['ref_vrf'])
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Restore bgp neighbor configs on external dut {}'.format(ext_dut))
        st.banner(test_cfg['org_bgp_cfg_ext'])
        vxlan_obj.config_dut(ext_dut, 'bgp', test_cfg['org_bgp_cfg_ext']) 
        
        st.log('Restore bgp neighbor configs on leaf {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['ext_addr'], test_cfg['ext_asn_no'])
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Verify if bgp neighbor is up on leaf and external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="up",
                                              as_num=test_cfg['ext_asn_no'], vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up",
                                              as_num=lb_asn_no)
            st.log('Bgp neighbor up verifcation: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor up verifcation: Fail ({})'.format(str(err)))
            result = False

        if result:
            st.banner("BGP peering with 4 Byte AS verification passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP peering with 4 Byte AS verification failed")
            st.report_fail("test_case_failed")

    def test_bgp_ipv6_peering(self):
        """
        Configure BGP ipv6 peer address and verify bgp peering
        * configure ipv6 peer address on leaf and external router . 
        * verify neighbor comes up and traffic flowing
        * restore ipv4 peer address on leaf and external router 
        * verify neighbor comes up
        """
        st.banner("Configure BGP ipv6 peer address and verify bgp peering")
        result = True
        lb_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure bgp ipv6 neighbor on leaf dut {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'no neighbor {} remote-as {}\n'.format(test_cfg['ext_addr'], test_cfg['ext_asn_no'])
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['ext_v6addr'], test_cfg['ext_asn_no'])
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Configure bgp ipv6 neighbor on external dut {}'.format(ext_dut))
        cmd = 'router bgp {} vrf {}\n'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
        cmd += 'no neighbor {} remote-as {}\n'.format(test_cfg['lb_addr'], lb_asn_no)
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['lb_v6addr'], lb_asn_no)
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Verify if bgp ipv6 neighbor is external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_v6addr'], state="up",
                                              vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_v6addr'], state="up")
            st.log('Bgp neighbor up verifcation: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor up verifcation: Fail ({})'.format(str(err)))
            result = False

        if result:
            st.log('Verify traffic with bgp ipv6 peering')
            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host with bgp ipv6 peering passed")
            else:
                st.error("Traffic between vxlan host and ext host with bgp ipv6 peering failed")
                result = False

        st.log('Restore bgp ipv4 neighbor configs on external dut {}'.format(ext_dut))

        st.log('Configure bgp ipv6 neighbor on leaf dut {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'no neighbor {} remote-as {}\n'.format(test_cfg['ext_v6addr'], test_cfg['ext_asn_no'])
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['ext_addr'], test_cfg['ext_asn_no'])
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('Configure bgp ipv6 neighbor on external dut {}'.format(ext_dut))
        cmd = 'router bgp {} vrf {}\n'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
        cmd += 'no neighbor {} remote-as {}\n'.format(test_cfg['lb_v6addr'], lb_asn_no)
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['lb_addr'], lb_asn_no)
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Verify if bgp ipv4 neighbor is up on leaf and external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="up",
                                              vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up")
            st.log('Bgp neighbor up verifcation: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor up verifcation: Fail ({})'.format(str(err)))
            result = False

        if result:
            st.banner("BGP peering using ipv6 address family passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP peering using ipv6 address family failed")
            st.report_fail("test_case_failed")

    def test_ibgp_external_peering(self):
        """
        Configure iBGP between external router and border leaf and verify bgp peering
        * configure iBGP peering on external router and border leaf router
        * verify neighbor comes up and traffic flowing
        * restore eBGP peering external router and leaf
        * verify neighbor comes up
        """
        st.banner("Configure iBGP between external router and border leaf and verify bgp peering")
        result = True
        lb_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['lb_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure bgp neighbor on leaf dut {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['ext_addr'], lb_asn_no)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('UnConfigure bgp neighbor on external dut {}'.format(ext_dut))
        cmd = 'no router bgp {} vrf {}\nend\nexit'.format(test_cfg['ext_asn_no'], test_cfg['ref_vrf'])
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Configure ibgp peering with border leaf on external dut {}'.format(ext_dut))
        cmd = test_cfg['org_bgp_cfg_ext'].replace(test_cfg['ext_asn_no'], lb_asn_no)
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Verify if bgp neighbor is up with ibgp peering on leaf and external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="up",
                                              as_num=lb_asn_no, vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up",
                                              as_num=lb_asn_no)
            st.log('Bgp neighbor up verifcation: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor up verifcation: Fail ({})'.format(str(err)))
            result = False

        if result:
            st.log('Verify traffic with ibgp peering')
            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host with ibgp peering passed")
            else:
                st.error("Traffic between vxlan host and ext host with ibgp peering failed")
                result = False

        st.log('UnConfigure bgp neighbor on leaf dut {}'.format(test_cfg['lb_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(lb_asn_no, test_cfg['ref_vrf'])
        cmd += 'neighbor {} remote-as {}\nend\nexit'.format(test_cfg['ext_addr'], test_cfg['ext_asn_no'])
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['lb_dut'], 'bgp', cmd) 

        st.log('UnConfigure ibgp neighbor on external dut {}'.format(ext_dut))
        cmd = 'no router bgp {} vrf {}\nend\nexit'.format(lb_asn_no, test_cfg['ref_vrf'])
        st.banner(cmd)
        vxlan_obj.config_dut(ext_dut, 'bgp', cmd) 

        st.log('Configure ebgp peering with border leaf on external dut {}'.format(ext_dut))
        st.banner(test_cfg['org_bgp_cfg_ext'])
        vxlan_obj.config_dut(ext_dut, 'bgp', test_cfg['org_bgp_cfg_ext']) 

        st.log('Verify if bgp neighbor is up on leaf and external router')
        try: 
            vxlan_obj.verify_bgp_ipv4_summary(dut=test_cfg['lb_dut'], vrf=test_cfg['ref_vrf'], neighbor=test_cfg['ext_addr'], state="up",
                                              as_num=test_cfg['ext_asn_no'], vl_retries=2, vl_interval=5)
            vxlan_obj.verify_bgp_ipv4_summary(dut=ext_dut, vrf=test_cfg['ref_vrf'], neighbor=test_cfg['lb_addr'], state="up",
                                              as_num=lb_asn_no)
            st.log('Bgp neighbor up verifcation: Pass')
        except vxlan_obj.VerifyBgpIpv4Summary as err:
            st.error('Bgp neighbor up verifcation: Fail ({})'.format(str(err)))
            result = False

        if result:
            st.banner("BGP ipv6 peering verification passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP ipv6 peering verification failed")
            st.report_fail("test_case_failed")

    def test_bgp_network_cfg(self):
        """
        Configure bgp network config on border leaf and verify route distribution
        * configure bgp network configs
        * verify bgp route present external router and verify traffic flow
        * unconfigure bgp network configs
        """
        st.banner("Configure summary-only on border leaf and verify route distribution")
        result = True
        vni = '5101'
        l0_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['l0_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure static route on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'vrf {} \n vni {} \n ip route {}/{} {}\nend\nexit'.format(test_cfg['ref_vrf'], vni, test_cfg['host_addr_1'],
                                                               test_cfg['host_mask_1'], test_cfg['host_gateway_1'])
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Configure bgp network config on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(l0_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += '  network {}/{}\n'.format(test_cfg['host_addr_1'], test_cfg['host_mask_1'])
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Verify bgp network route on external router')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['host_addr_1'], 
                                                     vrf=test_cfg['vrf_num'], vl_retries=5)
            st.log('Bgp network route verifcation : Pass')
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.error('Bgp network route verifcation : Fail')
            result = False

        if result:
            test_cfg['handles'][2]['verify_enabled'] = True

            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host with route community passed")
            else:
                st.error("Traffic between vxlan host and ext host with route community failed")
                result = False

            test_cfg['handles'][2]['verify_enabled'] = False

        st.log('Un-Configure static route on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'vrf {} \n vni {} \n no ip route {}/{} {}\nend\nexit'.format(test_cfg['ref_vrf'], vni, test_cfg['host_addr_1'],
                                                               test_cfg['host_mask_1'], test_cfg['host_gateway_1'])
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Un-Configure bgp network config on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(l0_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += '  no network {}/{}\n'.format(test_cfg['host_addr_1'], test_cfg['host_mask_1'])
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Verify no bgp network route on external router.')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['host_addr_1'], 
                                                     vrf=test_cfg['vrf_num'], vl_retries=5)
            st.error('Bgp route prefix with no network route verifcation.'
                     'Static route removed : Fail')
            result = False
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.log('Bgp route prefix with no network route verifcation.'
                     'Static route removed : Pass')

        if result:
            st.banner("BGP network configs verification passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP network configs verification failed")
            st.report_fail("test_case_failed")

    def test_bgp_rpl_static_route_set_community(self):
        """
        Configure BGP route-map RPL to match static route and set community 
        * configure static route in vrf 
        * configure rpls to match static route, rpl to set community
        * redistribute static in bgp with rpl match
        * verify bgp route on external router with community attribute set. verify traffic
        * unconfigure all new configs
        """
        st.banner("Configure BGP route-map RPL to match static route and set community ")
        result = True
        vni = '5101'
        rpl_name =  'set_community'
        community = '987:654'
        l0_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['l0_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure static route, rpl on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'vrf {} \n vni {} \n ip route {}/{} {}\n'.format(test_cfg['ref_vrf'], vni, test_cfg['host_addr_1'],
                                                               test_cfg['host_mask_1'], test_cfg['host_gateway_1'])
        cmd += 'route-map {} permit 20\n set community {}\nend\nexit'.format(rpl_name, community)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Configure redistribute static with rpl match on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(l0_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += ' redistribute static route-map {}\n'.format(rpl_name)
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Verify bgp route on external router has community set')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['host_addr_1'], 
                                                     vrf=test_cfg['vrf_num'], community=community, vl_retries=5)
            st.log('Bgp route community verifcation : Pass')
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.error('Bgp route community verifcation : Fail')
            result = False

        if result:
            st.log('Verify traffic with bgp route community')
            test_cfg['handles'][2]['verify_enabled'] = True

            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host with route community passed")
            else:
                st.error("Traffic between vxlan host and ext host with route community failed")
                result = False
            test_cfg['handles'][2]['verify_enabled'] = False

        st.log('Un-Configure prefix-list, rpl on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'vrf {} \n vni {} \n no ip route {}/{} {}\n'.format(test_cfg['ref_vrf'], vni, test_cfg['host_addr_1'],
                                                               test_cfg['host_mask_1'], test_cfg['host_gateway_1'])
        cmd += 'no route-map {}\nend\nexit'.format(rpl_name, community)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Un-Configure redistribute static with rpl match on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(l0_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += ' no redistribute static route-map {}\n'.format(rpl_name)
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Verify no bgp static route on external router.')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['host_addr_1'], 
                                                     vrf=test_cfg['vrf_num'], vl_retries=5)
            st.error('Bgp route prefix with no static route verifcation.'
                     'Static route removed : Fail')
            result = False
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.log('Bgp route prefix with no static route verifcation.'
                     'Static route removed : Pass')

        if result:
            st.banner("BGP RPL static route set community passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP RPL static route set community failed")
            st.report_fail("test_case_failed")

    def test_bgp_rpl_static_route_with_tag(self):
        """
        Configure BGP route-map RPL to match static routes with tag and set community 
        * configure static route with tag in vrf 
        * configure rpl match static tag
        * redistribute static in bgp with rpl match
        * verify bgp route on external router . verify traffic
        * unconfigure all new configs
        """
        st.banner("Configure BGP route-map RPL to match static route with tag and set community ")
        result = True
        vni = '5101'
        rpl_name =  'set_community'
        community = '987:654'
        tag = '123'
        l0_asn_no = str(vxlan_obj.generate_bgp_underlay_info()[test_cfg['l0_dut']]['as_num'])
        ext_dut = next((dut for dut in st.get_dut_names() if 'external' in dut), '')

        st.log('Configure static route, rpl on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'vrf {} \n vni {} \n ip route {}/{} {} tag {}\n'.format(test_cfg['ref_vrf'], vni, test_cfg['host_addr_1'],
                                                               test_cfg['host_mask_1'], test_cfg['host_gateway_1'], tag)
        cmd += 'route-map {} permit 20\n'.format(rpl_name)
        cmd += 'match tag {}\n set community {}\nend\nexit'.format(tag, community)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Configure redistribute static with rpl matching tag on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(l0_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += ' redistribute static route-map {}\n'.format(rpl_name)
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Verify bgp route on external router ')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['host_addr_1'], 
                                                     vrf=test_cfg['vrf_num'], community=community, vl_retries=5)
            st.log('Bgp route community verifcation : Pass')
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.error('Bgp route community verifcation : Fail')
            result = False

        if result:
            st.log('Verify traffic with bgp route redistribute')
            test_cfg['handles'][2]['verify_enabled'] = True

            if vxlan_obj.check_traffic(test_cfg['handles']):
                st.log("Traffic between vxlan host and ext host passed")
            else:
                st.error("Traffic between vxlan host and ext host failed")
                result = False
            test_cfg['handles'][2]['verify_enabled'] = False

        st.log('Un-Configure prefix-list, rpl on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'vrf {} \n vni {} \n no ip route {}/{} {} tag {}\n'.format(test_cfg['ref_vrf'], vni, test_cfg['host_addr_1'],
                                                               test_cfg['host_mask_1'], test_cfg['host_gateway_1'], tag)
        cmd += 'no route-map {}\nend\nexit'.format(rpl_name)
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Un-Configure redistribute static with rpl matching tag on leaf {}'.format(test_cfg['l0_dut']))
        cmd = 'router bgp {} vrf {}\n'.format(l0_asn_no, test_cfg['ref_vrf'])
        cmd += ' address-family ipv4 unicast\n'
        cmd += ' no redistribute static route-map {}\n'.format(rpl_name)
        cmd += ' exit-address-family\nend\nexit'
        st.banner(cmd)
        vxlan_obj.config_dut(test_cfg['l0_dut'], 'bgp', cmd) 

        st.log('Verify no bgp static route on external router.')
        try:
            vxlan_obj.verify_bgp_ipv4_unicast_prefix(dut=ext_dut, prefix=test_cfg['host_addr_1'], 
                                                     vrf=test_cfg['vrf_num'], vl_retries=5)
            st.error('Bgp route prefix with no static route verifcation.'
                     'Static route removed : Fail')
            result = False
        except vxlan_obj.VerifyBgpIpv4Unicast as err:
            st.log('Bgp route prefix with no static route verifcation.'
                     'Static route removed : Pass')

        if result:
            st.banner("BGP redistribute static route with RPL tag match passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BGP redistribute static route with RPL tag match failed")
            st.report_fail("test_case_failed")


    def test_external_bgp_interface_flap(self):
        st.banner("Flap the interface between border leaf and external router at border leaf")
        ext_dut_id = vars.dut_ids['external_router']
        leaf_dut_id = vars.dut_ids[test_cfg['lb_dut']]
        for node,dut_id in vars.dut_ids.items():
            if dut_id == ext_dut_id or dut_id == leaf_dut_id :
                for key,value in vars.items():
                    if leaf_dut_id+ext_dut_id in key:
                        leaf_int = get_intf_short_name(value + '.' + str(test_cfg['ext_sub_int_vlan_id']))
        interface_obj.interface_shutdown(test_cfg['lb_dut'],leaf_int)
        st.wait(2)
        interface_obj.interface_noshutdown(test_cfg['lb_dut'],leaf_int)
        st.wait(2)
        traffic_result = vxlan_obj.check_traffic(test_cfg['handles'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")

    def test_external_router_host_interface_flap(self):
        st.banner("Flap the external host interface")
        ext_dut_id = vars.dut_ids['external_router']
        for node,dut_id in vars.dut_ids.items():
            if dut_id == ext_dut_id :
                for key,value in vars.items():
                    if ext_dut_id+"T1P1" in key:
                        ext_tgen_int = value
        interface_obj.interface_shutdown('external_router',ext_tgen_int)
        st.wait(2)
        interface_obj.interface_noshutdown('external_router',ext_tgen_int)
        st.wait(2)
        traffic_result = vxlan_obj.check_traffic(test_cfg['handles'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")
    

    def test_config_reload(self):
        st.banner("reload BL")
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = test_cfg['lb_dut']
        #config save sonic and frr
        reboot_obj.config_save(selected_dut)
        vxlan_obj.config_dut(selected_dut,"bgp", "do write\nend\nexit") 
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
        st.wait(180)
        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail("test_case_failed")

        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = vxlan_obj.check_traffic(test_cfg['handles'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed after BL reload")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed after BL reload")
            st.report_fail("test_case_failed")

    def test_reboot(self):
        st.banner("reboot BL ")
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = test_cfg['lb_dut']
        vxlan_obj.config_dut(selected_dut,"bgp", "do write\nend\nexit") 
        count = basic_obj.get_and_match_docker_count(selected_dut)
        status = reboot_obj.config_save_reboot(selected_dut)
        #check docker status
        result = True
        if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
            st.error("Post 'config reload', dockers are not auto recovered.")
            result = False
        if result:
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
                st.error("Post 'config reload', ALL dockers are not UP.")
                st.report_fail("test_case_failed")
        st.wait(300)
        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail("test_case_failed")
        traffic_result = vxlan_obj.check_traffic(test_cfg['handles'])
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed after BL reboot")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed after BL reboot")
            st.report_fail("test_case_failed")
