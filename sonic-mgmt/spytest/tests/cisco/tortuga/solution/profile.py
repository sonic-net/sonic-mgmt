import os
import yaml
import threading
from spytest import st, tgapi
import vxlan_helper as vxlan_obj
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import random

class Profile:
    def __init__(self, input_file, vars, leaf_nodes, spine_nodes=[]):
        """Initialize the Profile instance."""
        self.input_file = input_file
        self.vars = vars
        self.handles = {} 
        self.leaf_nodes = leaf_nodes
        self.spine_nodes = spine_nodes
        self.nodes = leaf_nodes + spine_nodes

        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + self.input_file) as f:
            self.test_cfg = yaml.load(f, Loader=yaml.FullLoader)
        pass
    
    def config(self):
        """Configure the profile settings."""
        pass

    def unconfig(self):
        """Configure the profile settings."""
    
    def verify(self):
        """Verify the profile configuration."""
        pass

class VxlanProfile(Profile):
    """
    VXLAN Profile:
    Description: This class implements VXLAN profile configuration, unconfiguration and verification methods.
    Supported Topologies: 4S4L, 2L, 2S2L
    Topology Details:
        4S4L - 4 Spine and 4 Leaf nodes
        2L   - 2 Leaf nodes only
        2S2L - 2 Spine and 2 Leaf nodes
        2 Tgen ports are connected to each leaf node for traffic generation and verification.
    """
    def __init__(self, input_file, vars, leaf_nodes, spine_nodes=[], topo_type="4s4l"):
        """Initialize the VxlanProfile instance."""
        super().__init__(input_file=input_file, vars=vars, leaf_nodes=leaf_nodes, spine_nodes=spine_nodes)

        if topo_type == "4s4l":
            exp_no_leaf_nodes = exp_no_spine_nodes = 4
        elif topo_type == "2l":
            exp_no_leaf_nodes = 2
            exp_no_spine_nodes = 0
        elif topo_type == "2s2l":
            exp_no_leaf_nodes = exp_no_spine_nodes = 2
        else:
            raise Exception('invalid_topology', "Invalid topology type provided: {}".format(topo_type))

        if len(leaf_nodes) != exp_no_leaf_nodes or len(spine_nodes) != exp_no_spine_nodes:
            st.warn("Topology not matching, required leaf {}, spine {} dut, " \
            "having leaf {}, spine {}".format(exp_no_leaf_nodes, exp_no_spine_nodes, len(leaf_nodes), len(spine_nodes)))
    
    def config(self):
        """Configure the vxlan profile settings."""
        self.configure_sonic()
        self.configure_tgen()

    def unconfig(self):
        """Unconfigure the vxlan profile settings."""   
        self.configure_sonic(config=False)
    
    def verify(self):
        """Verify the vxlan profile configuration."""
        ret_val = True
        if self.verify_base_setup():
            st.log("SONiC verification passed")
        else:
            st.log("SONiC verification failed")
            ret_val = False

        if self.verify_traffic(bum=True):
            st.log("Traffic verification passed")
        else:
            st.log("Traffic verification failed")
            ret_val = False

        return ret_val

    def configure_sonic(self, config=True):
        """Configure SONiC specific settings for the profile."""
        self.configure_underlay(config=config)
        self.configure_overlay(config=config)
        self.configure_l2l3vni(config=config)
        # Enable QoS on all nodes
        for node in self.nodes:
            vxlan_obj.config_dut(node, 'sonic', "sudo config qos reload")
        pass

    def configure_tgen(self, **kwargs):
        """Configure traffic generator settings for the profile."""
        svi_dict_v4 = {}
        svi_dict_v6 ={}
        l2vni_intf_dict = vxlan_obj.get_interfaces(self.vars, self.leaf_nodes,'l2vni')
        ###Get topology Handles###
        topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)

        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + self.input_file) as f:
            config_dict = yaml.load(f, Loader=yaml.FullLoader)
            for node, config in config_dict.items():
                if 'leaf' in node:
                    if kwargs.get('custom_svi_ip'):
                        svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4', ip_start = "10.2.0.1")
                        svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6', ip_start = "1000:2::1")
                    else:
                        svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4')
                        svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6')
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4)
        v6_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v6,version="ipv6")
        
        tg_handle = topo_handles[self.leaf_nodes[0]][l2vni_intf_dict[self.leaf_nodes[0]][0]]['tg_handle']
        ###CREATE DEVICE GROUPS###
        #ipv4
        out_v4 = vxlan_obj.create_device_groups(topo_handles,v4_host_info_dict)
        v4_node_device_handles = out_v4[0]
        #ipv6
        out_v6 = vxlan_obj.create_device_groups(topo_handles,v6_host_info_dict,version ="ipv6")
        v6_node_device_handles = out_v6[0]
        v4_device_handles = {}
        v6_device_handles = {}
        for node, interfaces in v4_node_device_handles.items():
            for interface,values in interfaces.items():
                v4_device_handles[interface] =values
        for node, interfaces in v6_node_device_handles.items():
            for interface,values in interfaces.items():
                v6_device_handles[interface] =values
        ### start all protocols ###
        start_protocol = vxlan_obj.start_stop_protocols(tg_handle,action='start')
        if start_protocol == 1:
            st.log("protocols started successfully")
        else:
            st.report_tgen_fail('start protocols failed!')
            pass
        st.wait(5)
        ### choose traffic item endpoints###
        l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(v4_host_info_dict)
        l3_traffic_endpoints = vxlan_obj.find_l3_traffic_endpoints(v4_host_info_dict)
        ### create traffic item endpoints###
        self.handles['l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,
                                                              endpoints=l2_traffic_endpoints,
                                                              rate_percent=2,
                                                              topo_handles=topo_handles)
        self.handles['l3_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,
                                                              endpoints=l3_traffic_endpoints,
                                                              rate_percent=2,
                                                              topo_handles=topo_handles)
        self.handles['l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,
                                                              endpoints=l2_traffic_endpoints,
                                                              rate_percent=2,
                                                              topo_handles=topo_handles,
                                                              version = "ipv6")
        self.handles['l3_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,
                                                              endpoints=l3_traffic_endpoints,
                                                              rate_percent=2,
                                                              topo_handles=topo_handles,
                                                              version = "ipv6")
        #BUM
        bum_info ={}
        bum_info['tg_handle'] = topo_handles[self.leaf_nodes[0]][l2vni_intf_dict[self.leaf_nodes[0]][0]]['tg_handle']
        bum_info['topology_handle'] = topo_handles[self.leaf_nodes[0]][l2vni_intf_dict[self.leaf_nodes[0]][0]]['topology_handle']
        bum_info['port_handle'] = topo_handles[self.leaf_nodes[0]][l2vni_intf_dict[self.leaf_nodes[0]][0]]['port_handle']
        bum_info['dst_port_handles'] = []
        for node, interfaces in topo_handles.items():
            for interface, values in interfaces.items():
                if values['port_handle'] != bum_info['port_handle']:
                    bum_info['dst_port_handles'].append(values['port_handle'])
        svi_info = v4_host_info_dict[self.leaf_nodes[0]][l2vni_intf_dict[self.leaf_nodes[0]][0]]
        self.handles['bum'] = vxlan_obj.generate_bum_handles(bum_info,svi_info)
        self.handles["topo_handles"] = topo_handles

        streams = []
        for traffic_type, item in self.handles.items():
            if traffic_type in ['l2_v4','l3_v4','l2_v6','l3_v6']:
                for key, value in item.items():
                    streams.append(value['stream_id'])
        tg_handle.tg_traffic_config(mode = 'disable', stream_id = streams)

        return self.handles

    def configure_underlay(self, config=True): 
        if config:
            vxlan_obj.config_feature(self.nodes,'loopback')
            vxlan_obj.config_feature(self.nodes,'unnumbered')
            vxlan_obj.config_feature(self.nodes,'bgp_underlay')
        else:
            vxlan_obj.config_feature(self.nodes,'delete_loopback')
            vxlan_obj.config_feature(self.nodes,'delete_bgp_config')

    def configure_overlay(self,config=True): 
        if config:
            vxlan_obj.config_feature(self.leaf_nodes,'bgp_overlay')
        else:
            vxlan_obj.config_feature(self.leaf_nodes,'delete_bgp_config')

    def configure_l2l3vni(self,config=True): 
        if config:
            vxlan_obj.config_feature(self.leaf_nodes,'nvo')
            vxlan_obj.config_feature(self.leaf_nodes,'enable_tunnel_counters')
            vxlan_obj.config_feature(self.leaf_nodes,'l2vni')
            vxlan_obj.config_feature(self.leaf_nodes,'l3vni')
            vxlan_obj.config_feature(self.leaf_nodes,'add_sag_mac')
            vxlan_obj.config_feature(self.leaf_nodes,'sag_v4')
            vxlan_obj.config_feature(self.leaf_nodes,'sag_v6')
            vxlan_obj.config_feature(self.leaf_nodes,'bgp_l3vni_config')
        else:
            vxlan_obj.config_feature(self.leaf_nodes,'delete_sag_v6')
            vxlan_obj.config_feature(self.leaf_nodes,'delete_sag_v4')
            vxlan_obj.config_feature(self.leaf_nodes,'del_sag_mac')
            vxlan_obj.config_feature(self.leaf_nodes,'delete_bgp_l3vni_config')
            vxlan_obj.config_feature(self.leaf_nodes,'delete_l3vni')
            vxlan_obj.config_feature(self.leaf_nodes,'delete_l2vni')
            vxlan_obj.config_feature(self.leaf_nodes,'disable_tunnel_counters')
            vxlan_obj.config_feature(self.leaf_nodes,'delete_vxlan')
            vrf_obj.clear_vrf_configuration(st.get_dut_names())
            ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True, skip_error_check = True)
            vlan_obj.clear_vlan_configuration(st.get_dut_names())
    
    def verify_base_setup(self, retry=1):

        dut_result = {}
        for dut in self.leaf_nodes:
            st.log('Verifing base setup on DUT: {}'.format(dut))
            dut_result[dut] = {}

            try:
                dut_result[dut]['Vxlan remote vtep'] = True
                exp_data = vxlan_obj.get_expected_vxlan_remotevtep(dut)
                vxlan_obj.verify_vxlan_remotevtep(dut, exp_data, vl_retries=retry)
                st.log('Verify Vxlan remote vtep on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify Vxlan remote vtep on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['Vxlan remote vtep'] = False

            try:
                dut_result[dut]['BGP summary'] = True
                exp_data = vxlan_obj.get_expected_bgp_summary(dut)
                vxlan_obj.verify_bgp_summary(dut, exp_data, vl_retries=retry)
                st.log('Verify BGP summary on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify BGP summary on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['BGP summary'] = False
            
            dut_result[dut]['result'] = True
            for v_name , res in dut_result[dut].items():
                if res:
                    st.log('Verify {} on {}: Pass'.format(v_name, dut))
                else:
                    st.error('Verify {} on {}: Fail'.format(v_name, dut))
                    dut_result[dut]['result'] = False

        ret_val = True
        for dut in self.leaf_nodes:
            if dut_result[dut]['result']:
                st.banner('Base verification on {}: Pass'.format(dut))
            else:
                st.banner('Base verification on {}: Fail'.format(dut))
                ret_val = False

        return ret_val

    def verify_traffic(self, bum=False):
        traffic_result = {}
        for traffic_type, traffic_items in self.handles.items():
            if traffic_type != 'bum' and traffic_type != "topo_handles": 
                #Enable traffic items
                tg_handle = self.handles[traffic_type][1]['tg_handle']
                stream_list = []
                for key, value in traffic_items.items():
                    stream_list.append(value['stream_id'])
                tg_handle.tg_traffic_config(mode = 'enable', stream_id = stream_list)

                #check traffic
                st.banner("Running {}".format(traffic_type))
                traffic_result[traffic_type] = vxlan_obj.check_traffic(traffic_items, regenerate_traffic_items = True)

                #Disable traffic items
                tg_handle.tg_traffic_config(mode = 'disable', stream_id = stream_list)
            if traffic_type == 'bum' and bum == True:
                st.banner("Running BUM traffic : {}".format(traffic_type))
                traffic_result[traffic_type] = vxlan_obj.check_bum_traffic(self.handles['bum'])

        ret_val = True
        for traffic_type , result in traffic_result.items():
            if result == True :
                st.banner("{} traffic passed".format(traffic_type))
            else:
                st.banner("{} traffic failed".format(traffic_type))
                ret_val = False

        return ret_val


class VxlanMultiHomingProfile(Profile):
    """
    VXLAN Multi-Homing Profile:
    Description: This class implements VXLAN multihoming profile configuration, unconfiguration and verification methods.
    Topology Details:
        4 Spine and 4 Leaf nodes
        + 1 External router for external connectivity testcases (optional)
        3 Tgen ports are connected to each leaf node for traffic generation and verification.
        +1 Tgen port to spine3 for host on spine testcases (optional)
    """
    def __init__(self, input_file, vars, leaf_nodes, spine_nodes=[], l2l3vni_nodes=[], test_cfg={}):
        """Initialize the VxlanProfile instance."""
        super().__init__(input_file=input_file, vars=vars, leaf_nodes=leaf_nodes, spine_nodes=spine_nodes)
        self.l2l3vni_nodes = l2l3vni_nodes if l2l3vni_nodes else self.leaf_nodes
        if test_cfg: self.test_cfg = test_cfg

    def config(self):
        """Configure the vxlan profile settings."""
        self.configure_sonic()
        self.configure_tgen()

    def unconfig(self):
        """Unconfigure the vxlan profile settings."""   
        self.configure_sonic(config=False)
    
    def verify(self):
        """Verify the vxlan profile configuration."""
        ret_val = True
        if self.verify_base_setup():
            st.log("SONiC verification passed")
        else:
            st.log("SONiC verification failed")
            ret_val = False

        if self.verify_traffic(bum=True):
            st.log("Traffic verification passed")
        else:
            st.log("Traffic verification failed")
            ret_val = False

        return ret_val

    def configure_sonic(self, config=True, dut=None):
        """Configure SONiC specific settings for the profile."""
        if config:
            vxlan_obj.enable_debugs()
            self.configure_underlay()
            self.configure_overlay()
            self.configure_l2l3vni()
            # Enable QoS on all nodes
            for node in self.nodes:
                vxlan_obj.config_dut(node, 'sonic', "sudo config qos reload")

            # Save the configuration for the relevant nodes
            for node in self.l2l3vni_nodes:
                vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")
                vxlan_obj.config_dut(node, "bgp", "do write")
        else:
            self.unconfigure_underlay()
            self.unconfigure_l2l3vni()
        pass

    def configure_tgen(self, **kwargs):
        """
        configuring tgen for vxlan multihoming profile
        """
        leaf_nodes = self.l2l3vni_nodes
        svi_dict_v4 = {}
        svi_dict_v6 ={}

        if st.getenv('skip_tgen', 'false') == 'true':
            return self.handles        
        l2vni_intf_dict = vxlan_obj.get_interfaces(self.vars, leaf_nodes, 'l2vni')

        #port channel interfaces 
        # getting list of port_channels in config file
        port_channel = dict()
        for node, config in self.test_cfg.items():
            if not config: continue
            if node not in self.nodes: continue
            for pc_channel in self.test_cfg[node].get('port_channels', []):
                pc_num = pc_channel['port_channel_num']
                if pc_num not in port_channel:
                    port_channel[pc_num] = dict()
                port_channel[pc_num][node] = pc_channel['member_ids']

        def get_port_channel_match(tgn_port, port_channel):
            """check if tgn port is part of  any of the port channels and create port channel info"""
            pc_match = False
            for pc_num , pc_info in port_channel.items():
                port_list = list()
                node_list = list()
                for node, member_ids in pc_info.items():
                    for member_id in member_ids:
                        peer_port_id = vxlan_obj.get_peer_port_id(member_id, self.vars, node)
                        node_list.append(vxlan_obj.get_device_id(node, self.vars))
                        port_list.append(peer_port_id)
                        if tgn_port == peer_port_id:
                            pc_match = True 
                if pc_match:
                    return {'num': pc_num, 'nodes': node_list, 'ports': port_list}
            else:
                return pc_match

        # search for port channel ports in l2vi_int_dict and replace with portchannel info dict
        pc_list = list()
        new_l2vni_intf_dict = dict()
        for node in sorted(l2vni_intf_dict.keys()):
            new_l2vni_intf_dict[node] = list()
            for tgn_port in l2vni_intf_dict[node]:
                port_channel_match = get_port_channel_match(tgn_port, port_channel)
                if port_channel_match:
                    if port_channel_match['num'] not in pc_list:

                        pc_list.append(port_channel_match['num'])
                        port_channel_name =  'PortChannel{}_{}'.format(port_channel_match['num'], 
                                                                        ''.join(port_channel_match['nodes']))
                        tgn_port =  {'name': port_channel_name, 
                                    'ports': port_channel_match['ports'], 
                                    'port_channel_num': port_channel_match['num']}
                        new_l2vni_intf_dict[node].append(tgn_port)
                else:
                    new_l2vni_intf_dict[node].append(tgn_port)
        
        l2vni_intf_dict = new_l2vni_intf_dict
        self.test_cfg["l2vni_intf_dict"] = l2vni_intf_dict

        # generate vlans on each port
        port_vlan_dict = {}
        for node , ports in l2vni_intf_dict.items():
            node_id = vxlan_obj.get_device_id(node, self.vars)
            for port in ports:
                if type(port) == dict:
                    # port channel type
                    peer_port_id = 'PortChannel{}'.format(port['port_channel_num'])
                    port = port['name']
                else:
                    peer_port_id = vxlan_obj.get_peer_port_id(port, self.vars)

                port_vlan_dict[port] = list()
                for item in self.test_cfg[node]['l2vni']:
                    for member in item['members']:
                        if node_id+member == peer_port_id or member == peer_port_id:
                            port_vlan_dict[port].append(item['vlan_id'])
        ###Get topology Handles###
        topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)
        
        for node, config in self.test_cfg.items():
            if node in self.l2l3vni_nodes:

                if kwargs.get('custom_svi_ip'):
                    svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4', ip_start = "10.2.0.1")
                    svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6', ip_start = "1000:2::1")
                else:
                    svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4')
                    svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6')
        self.v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4, port_vlan_dict=port_vlan_dict, 
                                                        skip_nodes=[])
        self.v6_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v6, port_vlan_dict = port_vlan_dict, 
                                                        version="ipv6", skip_nodes=[])

        ###CREATE DEVICE GROUPS###
        
        #ipv4
        out_v4 = vxlan_obj.create_device_groups(topo_handles,self.v4_host_info_dict)
        v4_node_device_handles = out_v4[0]
        #ipv6
        out_v6 = vxlan_obj.create_device_groups(topo_handles,self.v6_host_info_dict,version ="ipv6")
        v6_node_device_handles = out_v6[0]
        
        v4_device_handles = {}
        v6_device_handles = {}
        
        for node, interfaces in v4_node_device_handles.items():
            for interface,values in interfaces.items():
                v4_device_handles[interface] =values
        for node, interfaces in v6_node_device_handles.items():
            for interface,values in interfaces.items():
                v6_device_handles[interface] =values
        ### start all protocols ###
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']

        start_protocol = vxlan_obj.start_stop_protocols(tg_handle,action='start')
        # fail only if it is not 0, Otherwise say started successfully
        if start_protocol == 0:
            st.report_tgen_fail('start protocols failed!')
        else:
            st.log("protocols started successfully")
            
        ### choose traffic item endpoints###
        l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(self.v4_host_info_dict)
        # get vrf - vlan mapping from configs
        vrf_vlan_dict = dict()
        for item in self.test_cfg['leaf0']['l3vni']:
            vrf_vlan_dict[item['vrf_id']] = item['vlan_bindings']

        l3_traffic_endpoints = vxlan_obj.find_l3_traffic_endpoints(self.v4_host_info_dict, vrf_vlan_dict = vrf_vlan_dict)
        ### create traffic item endpoints###
        self.handles['l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,
                                                                endpoints=l2_traffic_endpoints,
                                                                topo_handles=topo_handles, 
                                                                multi_dst = 'vlan', name_prfx='L2',
                                                                rate_percent=self.test_cfg['global']['l2l3']['rate_percent'],
                                                                pkts_per_burst=self.test_cfg['global']['l2l3']['pkts_per_burst'])
        self.handles['l3_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,
                                                                endpoints=l3_traffic_endpoints,
                                                                topo_handles=topo_handles,
                                                                multi_dst = 'vrf', name_prfx='L3',
                                                                rate_percent=self.test_cfg['global']['l2l3']['rate_percent'],
                                                                pkts_per_burst=self.test_cfg['global']['l2l3']['pkts_per_burst'])
        self.handles['l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,
                                                                endpoints=l2_traffic_endpoints,
                                                                topo_handles=topo_handles,
                                                                version = "ipv6", multi_dst = 'vlan', name_prfx='L2',
                                                                rate_percent=self.test_cfg['global']['l2l3']['rate_percent'],
                                                                pkts_per_burst=self.test_cfg['global']['l2l3']['pkts_per_burst'])
        self.handles['l3_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,
                                                                endpoints=l3_traffic_endpoints,
                                                                topo_handles=topo_handles,
                                                                version = "ipv6", multi_dst = 'vrf', name_prfx='L3',
                                                                rate_percent=self.test_cfg['global']['l2l3']['rate_percent'],
                                                                pkts_per_burst=self.test_cfg['global']['l2l3']['pkts_per_burst'])
        #BUM
        cntr = 1
        for node, config in self.test_cfg.items():
            if not node in self.l2l3vni_nodes:
                continue
            for l2_info in self.test_cfg[node].get('l2vni', []):
                if l2_info.get('bum_traffic', False):
                    for port in l2_info['members']:

                        bum_l2_endpoints = self.find_traffic_enpoints(topo_handles, self.v4_host_info_dict, node, port, 
                                                                l2_info['vlan_id'], l2_info['vlan_id'],  traffic_type='raw')
                        for dest_type, dst_mac in \
                            [('unknown', '00:99:00:00:00:99'), ('broadcast', 'ff:ff:ff:ff:ff:ff'), ('multicast', '01:00:5e:44:44:44')]:

                            for name,value in bum_l2_endpoints.items():
                                value['dst_mac'] = dst_mac

                            bum_type = 'bum_MH' if 'PortChannel' in port else 'bum_SH'
                            stream_prfx = '{}_{}'.format(bum_type, dest_type)
                            stream_info = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,
                                                                    endpoints=bum_l2_endpoints,
                                                                    topo_handles=topo_handles,
                                                                    multi_dst = 'vlan', name_prfx=stream_prfx, 
                                                                    circuit_type='raw', rx_all_ports=True,
                                                                    rate_percent=self.test_cfg['global']['bum']['rate_percent'], 
                                                                    pkts_per_burst=self.test_cfg['global']['bum']['pkts_per_burst'])
                            if not self.handles.get(bum_type):
                                self.handles[bum_type] = dict()    
                            self.handles[bum_type][cntr] =  stream_info[1]
                            cntr += 1
        
        ###Disable all streams###
        streams = []
        for traffic_type, item in self.handles.items():
            if traffic_type in ['l2_v4','l3_v4','l2_v6','l3_v6','bum_MH','bum_SH']:
                for key, value in item.items():
                    streams.append(value['stream_id'])
        tg_handle.tg_traffic_config(mode = 'disable', stream_id = streams)

        self.handles["tg_handle"] = tg_handle
        self.handles["topo_handles"] = topo_handles
        self.handles["v4_device_handles"] = v4_device_handles
        self.handles["v6_device_handles"] = v6_device_handles

        return self.handles

    def configure_l2l3vni(self):
        """
        Configures L2/L3 VNI on the specified nodes.
        If `dut` is provided, only configure the specified node.
        """

        # Perform the configuration
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'nvo')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'enable_tunnel_counters')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'port_channels')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'l2vni')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'l3vni')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'add_sag_mac')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'sag_v4')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'sag_v6')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'bgp_l3vni_config')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'evpn_mh')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'evpn_esi')
        vxlan_obj.enable_uplink_tracking_configs(self.l2l3vni_nodes)

        # configs changed after image issues 24806, 27192
        for dut in self.l2l3vni_nodes:
            cmd = 'evpn mh startup-delay 10\n'
            cmd += 'no ip nht resolve-via-default\n'
            cmd += 'no ipv6 nht resolve-via-default\n'
            vxlan_obj.config_dut(dut, 'bgp', cmd)
        for dut in self.spine_nodes:            
            cmd = 'no ip nht resolve-via-default\n'
            cmd += 'no ipv6 nht resolve-via-default\n'
            vxlan_obj.config_dut(dut, 'bgp', cmd)



    def unconfigure_l2l3vni(self, ):
        # Log the operation
        st.log("Unconfiguring L2/L3 VNI on nodes: {}".format(self.l2l3vni_nodes))

        # Perform the unconfiguration
        vxlan_obj.enable_uplink_tracking_configs(self.l2l3vni_nodes, add=False)
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_evpn_esi')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_evpn_mh')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_sag_v6')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_sag_v4')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'del_sag_mac')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_bgp_l3vni_config')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_l3vni')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_l2vni')
        vxlan_obj.config_feature_parallel(self.nodes, 'delete_bgp_config')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_port_channels')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'disable_tunnel_counters')
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes, 'delete_vxlan')

        # configs changed after image issues 24806, 27192
        for dut in self.l2l3vni_nodes:
            cmd = 'no evpn mh startup-delay 10\n'
            cmd += 'ip nht resolve-via-default\n'
            cmd += 'ipv6 nht resolve-via-default\n'
            vxlan_obj.config_dut(dut, 'bgp', cmd)
        for dut in self.spine_nodes:
            cmd = 'ip nht resolve-via-default\n'
            cmd += 'ipv6 nht resolve-via-default\n'
            vxlan_obj.config_dut(dut, 'bgp', cmd)

        vrf_obj.clear_vrf_configuration(self.nodes)
        ip_obj.clear_ip_configuration(self.nodes, family='all', thread=True, skip_error_check = True)
        vlan_obj.clear_vlan_configuration(self.nodes)

    def configure_underlay(self): 
        """
        configures underlay on all nodes.
        """
        vxlan_obj.config_feature_parallel(self.nodes,'loopback')
        vxlan_obj.config_feature_parallel(self.nodes,'unnumbered')
        vxlan_obj.config_feature_parallel(self.nodes,'bgp_underlay')
        if self.test_cfg['global']['bfd_enable']:
            vxlan_obj.config_feature_parallel(self.nodes,'bgp_bfd_underlay')
    
    def unconfigure_underlay(self):
        """
        unconfiguring underlay on all nodes.
        """
        vxlan_obj.config_feature_parallel(self.nodes,'delete_loopback')

    def configure_overlay(self): 
        vxlan_obj.config_feature_parallel(self.l2l3vni_nodes,'bgp_overlay')
        if self.test_cfg['global']['bfd_enable']:
            vxlan_obj.config_feature_parallel(self.l2l3vni_nodes,'bgp_bfd_overlay')
    
    def find_traffic_enpoints(self, topo_handles, v4_host_info_dict, src_int_dut, src_int, src_vlan_id, dst_vlan_id, 
                            traffic_type='default'):
        cntr = 1
        endpoints = dict()

        if src_int.startswith('PortChannel'):
            for port_id in topo_handles[src_int_dut].keys():
                if src_int in port_id:
                    src_port_id = port_id
                    break
            else:
                raise Exception('Port channel {} not found in toplogy'.format(src_int))
        else:
            src_port_id = vxlan_obj.get_peer_port_id(src_int, self.vars, src_int_dut)

        for lnode in self.test_cfg.keys():
            if not lnode in self.l2l3vni_nodes:
                continue
            for l2vni_item in self.test_cfg[lnode]['l2vni']:
                if l2vni_item['vlan_id'] == dst_vlan_id:
                    for l3vni_item in self.test_cfg[lnode]['l3vni']:
                        if dst_vlan_id in l3vni_item['vlan_bindings']:
                            vrf = l3vni_item['vrf_id']
                            break
                    else:
                        vrf = ''
                    for member in l2vni_item['members']:
                        if member.startswith('PortChannel'):
                            # look for portchannel name in topo_handles
                            for port_id in topo_handles[lnode].keys():
                                if member in port_id:
                                    dst_port_id = port_id
                                    break
                            else:
                                continue
                        else:
                            # orphan port
                            dst_port_id = vxlan_obj.get_peer_port_id(member, self.vars, lnode)

                        if dst_port_id == src_port_id: 
                            continue
                        # find mac addresses
                        endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)] = {
                                            'dst_int': dst_port_id,
                                            'dst_node': lnode,
                                            'dst_vlan': dst_vlan_id,
                                            'dst_vrf': vrf,
                                            'src_int': src_port_id,
                                            'src_node': src_int_dut,
                                            'src_vrf': vrf,
                                            'src_vlan': src_vlan_id}
                        if traffic_type == 'raw':
                            endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)]['dst_mac'] = \
                                    v4_host_info_dict[lnode][dst_port_id][dst_vlan_id]['src_mac']
                            endpoints['traffic_item_{}_{}'.format(src_port_id,cntr)]['src_mac'] = \
                                    v4_host_info_dict[src_int_dut][src_port_id][src_vlan_id]['src_mac']
                        cntr += 1
        return endpoints
    
    def verify_base_setup(self, retry=1):
        leaf_nodes = self.l2l3vni_nodes
        st.log('Verifying base setup')
        dut_result = {}
        for dut in leaf_nodes:
            dut_result[dut] = {}
            st.banner('Verify vlan/vrf/vxlan/evpn on leaf node: {}'.format(dut))
            try:
                dut_result[dut]['EVPN ES'] = True
                exp_data = vxlan_obj.get_expected_evpn_es(dut)
                vxlan_obj.verify_evpn_es(dut, exp_data, vl_retries=retry)
                st.log('Verify EVPN ES on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify EVPN ES on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['EVPN ES'] = False

            try:
                dut_result[dut]['EVPN ES-EVI'] = True
                exp_data = vxlan_obj.get_expected_evpn_es_evi(dut)
                vxlan_obj.verify_evpn_es_evi(dut, exp_data, vl_retries=retry)
                st.log('Verify EVPN ES-EVI on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify EVPN ES-EVI on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['EVPN ES-EVI'] = False

            try:
                dut_result[dut]['Vxlan-VlanVni map'] = True
                exp_data = vxlan_obj.get_expected_vxlan_vlanvnimap(dut)
                vxlan_obj.verify_vxlan_vlanvnimap(dut, exp_data, vl_retries=retry)
                st.log('Verify Vxlan-VlanVni map on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify Vxlan-VlanVni map on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['Vxlan-VlanVni map'] = False

            try:
                dut_result[dut]['Vxlan-VrfVni map'] = True
                exp_data = vxlan_obj.get_expected_vxlan_vrfvnimap(dut)
                vxlan_obj.verify_vxlan_vrfvnimap(dut, exp_data, vl_retries=retry)
                st.log('Verify Vxlan-VrfVni map on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify Vxlan-VrfVni map on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['Vxlan-VrfVni map'] = False

            try:
                dut_result[dut]['Vxlan remote vtep'] = True
                exp_data = vxlan_obj.get_expected_vxlan_remotevtep(dut)
                vxlan_obj.verify_vxlan_remotevtep(dut, exp_data, vl_retries=retry)
                st.log('Verify Vxlan remote vtep on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify Vxlan remote vtep on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['Vxlan remote vtep'] = False
            
            try:
                dut_result[dut]['BGP summary'] = True
                exp_data = vxlan_obj.get_expected_bgp_summary(dut)
                vxlan_obj.verify_bgp_summary(dut, exp_data, vl_retries=retry)
                st.log('Verify BGP summary on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify BGP summary on {}: Fail\n{}'.format(dut, err))
                # TODO ; FIX dut_result[dut]['BGP summary'] = False
            """
            try:
                dut_result[dut]['BFD summary'] = True
                exp_data = vxlan_obj.get_expected_bfd_summary(dut)
                vxlan_obj.verify_bfd_summary(dut, exp_data, vl_retries=retry)
                st.log('Verify BFD summary on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify BFD summary on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['BFD summary'] = False
            """

            try:
                dut_result[dut]['Vxlan neighbor group'] = True
                self.verify_vxlan_neigh_groups(dut, retry=retry)
                st.log('Verify Vxlan neighbor group on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify Vxlan neighbor group on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['Vxlan neighbor group'] = False

            try:
                dut_result[dut]['EVPN Type 1 Routes'] = True
                exp_data = vxlan_obj.get_expected_evpn_type1_routes(dut)
                vxlan_obj.verify_evpn_type1_routes(dut, exp_data, vl_retries=retry)
                st.log('Verify EVPN Type 1 Routes on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify EVPN Type 1 Routes on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['EVPN Type 1 Routes'] = False

            try:
                dut_result[dut]['EVPN Type 4 Routes'] = True
                exp_data = vxlan_obj.get_expected_evpn_type4_routes(dut)
                vxlan_obj.verify_evpn_type4_routes(dut, exp_data)
                st.log('Verify EVPN Type 4 Routes on {}: Pass'.format(dut))
            except Exception as err:
                st.log('Verify EVPN Type 4 Routes on {}: Fail\n{}'.format(dut, err))
                dut_result[dut]['EVPN Type 4 Routes'] = False

            dut_result[dut]['result'] = True
            for v_name , res in dut_result[dut].items():
                if res:
                    st.log('Verify {} on {}: Pass'.format(v_name, dut))
                else:
                    st.error('Verify {} on {}: Fail'.format(v_name, dut))
                    dut_result[dut]['result'] = False

        result = True
        for dut in leaf_nodes:
            if dut_result[dut]['result']:
                st.banner('Base verification on {}: Pass'.format(dut))
            else:
                st.banner('Base verification on {}: Fail'.format(dut))
                result = False
        return result

    def verify_vxlan_neigh_groups(self, dut, retry=1):

        # find esi for dut:
        if self.test_cfg[dut] and self.test_cfg[dut].get('port_channels'):
            # todo. assuming only one esi per node
            dut_esi = self.test_cfg[dut]['port_channels'][0]['evpn_esi']
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
                        node_esi = self.test_cfg[node]['port_channels'][0]['evpn_esi']
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

    def verify_traffic(self, traffic_handles, regenerate=False, traffic_types=[], traffic_names=[], 
                    bum=True, stop_start_protocols=True):

        traffic_result = {}
        for traffic_type, traffic_items in traffic_handles.items():
            if '_handle' in traffic_type: continue
            mode = 'traffic_item'
            if bum:
                if 'bum' in traffic_type: 
                    mode = 'flow'
            else:
                if 'bum' in traffic_type: 
                    continue

            if traffic_types:
                for ttype in traffic_types:
                    if ttype in traffic_type:
                        break
                else:
                    continue

            if traffic_names:
                sel_traffic_items = {}
                for tname in traffic_names:
                    for idx , traffic_info in traffic_items.items():
                        if tname in traffic_info['stream_id']:
                            sel_traffic_items[idx] = traffic_info
                traffic_items = sel_traffic_items

            st.banner("Verifying {} traffic".format(traffic_type))
            try:
                traffic_result[traffic_type] = vxlan_obj.check_traffic(traffic_items,
                                                regenerate_traffic_items = regenerate,
                                                stop_start_protocols=stop_start_protocols, mode=mode,
                                                stop_proto_wait = self.test_cfg['global']['traffic_stop_protocol_sleep'],
                                                start_proto_wait = self.test_cfg['global']['traffic_start_protocol_sleep'])
                stop_start_protocols=False
                st.log("Traffic type {} verify result: {}".format(traffic_type, traffic_result[traffic_type]))
                if not traffic_result[traffic_type]:
                    pass
            except Exception as err:
                st.error('Exception when checking traffic: {}'.format(str(err)))
                traffic_result[traffic_type] = False
        ret = True
        for traffic_type , result in traffic_result.items():
            if result == True :
                st.banner("{} traffic passed".format(traffic_type))
            else:
                st.banner("{} traffic failed".format(traffic_type))
                ret = False
        return ret

    def change_underlay_dpb(self, dpb_type, dpb_intf_idx="random"):
        """
        Change the DPB configuration on all DUTs in network
            1. remove underlay interfaces in bgp
            2. disable qos on underlay interfaces
            3. remove link local on underlay interfaces
            4. configure dbp
            unshut interface
            5. add link local on new underlay interfaces
            6. enable qos on new underlay interfaces
            7. add new underlay interfaces in bgp
        """
        num_intfs, speed = dpb_type.split('x')
        node_intfs = vxlan_obj.get_dut_interfaces(self.vars)
        st.log("Configuring new DPB setting (type: {}) and reconfiguring bgp, link-local and Qos".format(dpb_type))
        if not self.test_cfg['global'].get('current_dpb_type'):
            dut = 'leaf0'
            st.log("Getting current DPB type from {}".format(dut))
            intfs_status = vxlan_obj.get_interfaces_status(dut)
            for underlay_intf in node_intfs[dut]['underlay_dict'].values():
                for status in intfs_status:
                    if status['interface'] == underlay_intf and speed in status['speed']:
                        st.log("Underlay interface {} on {} present and speed ({}) match".format(underlay_intf, dut, speed))
                        break
                else:
                    st.log("Underlay interface {} on {} not present or speed ({}) mismatch".format(underlay_intf, dut, speed))
                    break
            else:
                st.log("Underlay interfaces on {} present and speed matches {} dpb type {}. " \
                    "Skipping reconfiguration".format(dut, speed, dpb_type))
                raise Exception("DPB type {} already configured".format(dpb_type))
            
        if self.test_cfg['global'].get('current_dpb_type') == dpb_type:
            st.log("DPB type {} is already configured. Skipping reconfiguration.".format(dpb_type))
            raise Exception("DPB type {} already configured".format(dpb_type))

        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        new_underlay_intfs = dict()
        if dpb_intf_idx == "random":
            dpb_intf_idx = random.randint(0, int(num_intfs) -1)
        else:
            dpb_intf_idx = int(dpb_intf_idx)    

        def config_intfs_underlay(node, bgp_info, intfs, add=True):

            frr_cfg = 'router bgp {}\n'.format(bgp_info['as_num'])
            qos_cfg = ''
            ll_cfg = ''
            for intf in intfs:
                oper = '' if add else 'no '
                frr_cfg += ' {}neighbor {} interface peer-group TRANSIT\n'.format(oper, intf)
                oper = 'reload' if add else 'clear'
                qos_cfg += 'sudo config qos {} --ports {}\n'.format(oper, intf)
                oper = 'enable' if add else 'disable'
                ll_cfg += 'sudo config interface ipv6 {} use-link-local-only {}\n'.format(oper, intf)
            frr_cfg += 'end\n'
            frr_cfg += 'exit\n'

            if add:
                st.log("Config link-local on underlay interfaces on node {}".format(node))
                st.config(node, ll_cfg, skip_error_check=True, conf=True)
                if self.test_cfg['global']['qos_enable']:
                    st.log("Config qos on underlay interfaces on node {}".format(node))
                    st.config(node, qos_cfg, skip_error_check=True, conf=True)
                st.log("Config bgp underlay configs on node {}".format(node))
                st.config(node, frr_cfg, type='vtysh', skip_error_check=True, conf=True)
            else:
                st.log("Remove bgp underlay configs on node {}".format(node))
                st.config(node, frr_cfg, type='vtysh', skip_error_check=True, conf=True)
                if self.test_cfg['global']['qos_enable']:
                    st.log("Remove qos on underlay interfaces on node {}".format(node))
                    st.config(node, qos_cfg, skip_error_check=True, conf=True)
                st.log("Remove link-local on underlay interfaces on node {}".format(node))
                st.config(node, ll_cfg, skip_error_check=True, conf=True)

        def remove_add_dpb(node, dpb_type, dpb_intf_idx):
            st.log("Removing Underlay Config on node {}".format(node))
            config_intfs_underlay(node, bgp_info[node], node_intfs[node]['underlay_dict'].values(), add=False)
            st.log("Configuring DPB on node {}".format(node))
            new_intfs = vxlan_obj.config_dpb(node, dpb_type, node_intfs[node]['underlay_dict'].values())
            new_underlay_intfs[node] = list()
            for port_id, old_int in node_intfs[node]['underlay_dict'].items():
                main_intf = vxlan_obj.parse_main_interface_name(node, old_int)

                new_underlay_intfs[node].append(new_intfs[main_intf][dpb_intf_idx])
                # update vars with the new underlay inteface
                self.vars[port_id] = new_intfs[main_intf][dpb_intf_idx]

            st.log("Configuring new Underlay Config on node {}".format(node))
            config_intfs_underlay(node, bgp_info[node], new_underlay_intfs[node])


        threads = []
        for node in node_intfs.keys():
            thread = threading.Thread(target=remove_add_dpb, args=(node, dpb_type, dpb_intf_idx), 
                                    name='thread_{}'.format(node,))
            st.log('Starting Thread {} to remove add new dpb type on node {} undelay'.format(thread.name, node))
            thread.start()
            threads.append(thread)
        for thread in threads:
            st.log('Waiting for thread to complete: {}'.format(thread.name))
            thread.join()
            st.log('Thread complete: {}'.format(thread.name))

        self.test_cfg['global']['current_dpb_type'] = dpb_type
        st.log("DPB configuration complete.")

class VxlanPFCProfile(VxlanMultiHomingProfile):
    """
    VXLAN PFC (Priority Flow Control) Profile:
    Uses same topology and SONiC config as Multi-Homing, but TGEN is configured
    with only L2-V4 traffic (no L3-V4, L2-V6, L3-V6, BUM) for PFC congestion tests.
    """
    def configure_tgen(self, **kwargs):
        """Configure TGEN for PFC: only l2_v4 traffic items (skip l3_v4, l2_v6, l3_v6, BUM)."""
        return super().configure_tgen(skip_l2l3_bum_traffic=True, **kwargs)