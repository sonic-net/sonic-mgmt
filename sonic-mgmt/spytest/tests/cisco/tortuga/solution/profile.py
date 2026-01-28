import os
import yaml
from spytest import st, tgapi
import vxlan_helper as vxlan_obj

class Profile:
    def __init__(self, input_file, vars, leaf_nodes, spine_nodes=[]):
        """Initialize the Profile instance."""
        self.input_file = input_file
        self.vars = vars
        self.handles = {} 
        self.leaf_nodes = leaf_nodes
        self.spine_nodes = spine_nodes
        self.nodes = leaf_nodes + spine_nodes

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
            raise Exception("Topology not matching, required leaf {}, spine {} dut, " \
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
        if self.verify_sonic():
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
    
    def verify_sonic(self):

        dut_result = {}
        retry = 5
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