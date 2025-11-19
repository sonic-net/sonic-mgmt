import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import common_utils
import apis.system.basic as basic_obj

ACL_JSON_FILE = "ars_acl.json"
ACL_JSON_FILE_PATH = os.path.dirname(os.path.realpath(__file__)) + '/' + ACL_JSON_FILE

# Tgen config
data_tgen_l2vni = SpyTestDict()
data_tgen_l2vni.my_dut_list = None
data_tgen_l2vni.vlan = "2"

data_tgen_l2vni.t1d1_ip_addr = "100.100.100.1"
data_tgen_l2vni.t1d1_ipv6_addr = "100:100:100::1"
data_tgen_l2vni.t1d1_mac_addr = "00:0A:03:00:11:01"

data_tgen_l2vni.t1d2_ip_addr = "100.100.100.2"
data_tgen_l2vni.t1d2_ipv6_addr = "100:100:100::2"
data_tgen_l2vni.t1d2_mac_addr = "00:0A:04:00:12:01"

data_tgen_l2vni.t1d1_ip_gateway = data_tgen_l2vni.t1d2_ip_addr
data_tgen_l2vni.t1d1_ipv6_gateway = data_tgen_l2vni.t1d2_ipv6_addr
data_tgen_l2vni.t1d2_ip_gateway = data_tgen_l2vni.t1d1_ip_addr
data_tgen_l2vni.t1d2_ipv6_gateway = data_tgen_l2vni.t1d1_ipv6_addr

data_tgen_l2vni.t1d1_dest_mac_addr = data_tgen_l2vni.t1d2_mac_addr
data_tgen_l2vni.t1d2_dest_mac_addr = data_tgen_l2vni.t1d1_mac_addr

data_tgen_l3vni = SpyTestDict()
data_tgen_l3vni.my_dut_list = None
data_tgen_l3vni.vlan = "2"

data_tgen_l3vni.t1d1_ip_addr = "100.100.100.1"
data_tgen_l3vni.t1d1_ipv6_addr = "100:100:100::1"
data_tgen_l3vni.t1d1_mac_addr = "00:0A:03:00:11:01"

data_tgen_l3vni.t1d2_ip_addr = "100.100.101.2"
data_tgen_l3vni.t1d2_ipv6_addr = "100:100:101::2"
data_tgen_l3vni.t1d2_mac_addr = "00:0A:04:00:12:01"

data_tgen_l3vni.t1d1_ip_gateway = "100.100.100.254"
data_tgen_l3vni.t1d1_ipv6_gateway = "100:100:100::254"
data_tgen_l3vni.t1d2_ip_gateway = "100.100.101.254"
data_tgen_l3vni.t1d2_ipv6_gateway = "100:100:101::254"
# Tgen config

def initialize_globals(vni_type):
    global vars, data_glob, tg1, tg2, tg_handle_1, tg_handle_2, updated_path, updated_acl_file_path
    vars = st.get_testbed_vars()
    tg1, tg2, tg_handle_1, tg_handle_2 = common_utils.get_handles()
    data_glob = SpyTestDict()
    data_glob.nodes = [vars.D1, vars.D2, vars.D3, vars.D4]
    data_glob.spine0 = data_glob.nodes[0]
    data_glob.spine1 = data_glob.nodes[1]
    data_glob.leaf0 = data_glob.nodes[2]
    data_glob.leaf1 = data_glob.nodes[3]
    data_glob.interfaces = [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2]
    dir_path = os.path.dirname(os.path.realpath(__file__))
    if vni_type == 'l2vni':
        CONFIGS_FILE = 'ars_l2vni_cfg.yaml'
        updated_path = common_utils.modify_config_file(dir_path + '/' + CONFIGS_FILE, vars)
        
    else:
        CONFIGS_FILE = 'ars_l3vni_cfg.yaml'
        updated_path = common_utils.modify_config_file(dir_path + '/' + CONFIGS_FILE, vars)
        data_tgen_l3vni.t1d1_dest_mac_addr = basic_obj.get_ifconfig_ether(data_glob.leaf0, 'Vlan2')
        data_tgen_l3vni.t1d2_dest_mac_addr = basic_obj.get_ifconfig_ether(data_glob.leaf1, 'Vlan3')
    updated_acl_file_path = common_utils.modify_json_file(ACL_JSON_FILE_PATH, vars)

# Parametrized setup/teardown for vni_type
@pytest.fixture(scope='module', autouse=False)
def setup_vni(request):
    vni_type = request.param
    initialize_globals(vni_type)
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, configs in config.items():
                common_utils.config_static(node, domain, True, updated_path)
    st.wait(100)
    yield
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, configs in config.items():
                common_utils.config_static(node, domain, False, updated_path)
    common_utils.remove_temp_config(updated_path)

def tg_cleanup(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface):
    tg1.tg_traffic_config(mode = 'disable', stream_id =trBurst['stream_id']) 
    tg1.tg_traffic_config(mode = 'disable', stream_id =trContinuous['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trDSCP1['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trDSCP2['stream_id'])
    common_utils.tg_interface_cleanup(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface)

@pytest.fixture(scope = 'function')
def fixture_BUM(request):
    test_instance = request.instance
    if getattr(test_instance, 'vni_type', 'l2vni') != 'l2vni':
        yield
        return
    global trBUM, tg1_interface, tg2_interface
    common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    tg1_interface, tg2_interface = common_utils.configure_tg_interfaces_v4(tg1, tg2, tg_handle_1, tg_handle_2, data_tgen_l2vni, data_tgen_l2vni)
    common_utils.verify_ping_helper(tg1, tg_handle_1, tg1_interface['handle'], data_tgen_l2vni.t1d2_ip_addr)
    common_utils.verify_ping_helper(tg2, tg_handle_2, tg2_interface['handle'], data_tgen_l2vni.t1d1_ip_addr)
    trBUM = common_utils.configure_traffic_streams_BUM(tg1, tg2, tg_handle_1, tg_handle_2, data_tgen_l2vni, data_tgen_l2vni)
    yield
    for traffic_type in ['unicast', 'multicast', 'broadcast']:
        tg1.tg_traffic_config(mode='disable', stream_id=trBUM[traffic_type]['stream_id'])
    common_utils.tg_interface_cleanup(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface)

@pytest.fixture(scope = 'function')
def fixture_v4(request):
    st.banner("Fixture for IPv4")
    global tg1_interface, tg2_interface, trBurst, trContinuous, trDSCP1, trDSCP2
    common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    test_instance = request.instance
    vni_type = getattr(test_instance, 'vni_type', 'l2vni')
    data_tgen = data_tgen_l2vni if vni_type == 'l2vni' else data_tgen_l3vni
    tg1_interface, tg2_interface = common_utils.configure_tg_interfaces_v4(tg1, tg2, tg_handle_1, tg_handle_2, data_tgen, data_tgen)
    common_utils.verify_ping_helper(tg1, tg_handle_1, tg1_interface['handle'], data_tgen.t1d2_ip_addr)
    common_utils.verify_ping_helper(tg2, tg_handle_2, tg2_interface['handle'], data_tgen.t1d1_ip_addr)
    trBurst, trContinuous, trDSCP1, trDSCP2 = common_utils.configure_traffic_streams(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface, 'ipv4')
    yield
    tg_cleanup(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface)

# =============================================================================
# ARS VXLAN L2VNI Testbed Topology
#
#         +--------+         +--------+
#         | Spine0 |         | Spine1 |
#         |  D1    |         |  D2    |
#         +--------+         +--------+
#           |    \             |    /
#           |     \            |   /
#           |      \           |  /
#           |       \          | /
#           |        \         |/
#         +-------------------------+
#         |                         |
#     +--------+               +--------+
#     | Leaf0  |               | Leaf1  |
#     |  D3    |               |  D4    |
#     +--------+               +--------+
#         |                        |
#      [TG1]                    [TG2]
#
# Connections:
#   - Spine0 (D1) <-> Leaf0 (D3): D1D3P1, D1D3P2
#   - Spine0 (D1) <-> Leaf1 (D4): D1D4P1, D1D4P2
#   - Spine1 (D2) <-> Leaf0 (D3): D2D3P1, D2D3P2
#   - Spine1 (D2) <-> Leaf1 (D4): D2D4P1, D2D4P2
#   - Leaf0 (D3) <-> TG1: D3T1P1 (Vlan 2)
#   - Leaf1 (D4) <-> TG2: D4T1P1 (Vlan 2)
#
# Key Configurations:
#   - VLANs 2, 3, 100 used for L2VNI and bridging
#   - All traffic is Intra-Vlan (Vlan 2)
#   - BGP EVPN overlay/underlay with appropriate ASNs
#   - VXLAN tunnels and mappings configured per leaf
#   - IPv4 and IPv6 addressing on VLAN interfaces
#   - All interfaces between spines and leaves are started and enabled for IPv6 link-local
#
# Refer to ars_l2vni_cfg.yaml for full configuration details.
# =============================================================================

# =============================================================================
# ARS VXLAN L3VNI Testbed Topology
#
#         +--------+         +--------+
#         | Spine0 |         | Spine1 |
#         |  D1    |         |  D2    |
#         +--------+         +--------+
#           |    \             |    /
#           |     \            |   /
#           |      \           |  /
#           |       \          | /
#           |        \         |/
#         +-------------------------+
#         |                         |
#     +--------+               +--------+
#     | Leaf0  |               | Leaf1  |
#     |  D3    |               |  D4    |
#     +--------+               +--------+
#         |                        |
#      [TG1]                    [TG2]
#
# Connections:
#   - Spine0 (D1) <-> Leaf0 (D3): D1D3P1, D1D3P2
#   - Spine0 (D1) <-> Leaf1 (D4): D1D4P1, D1D4P2
#   - Spine1 (D2) <-> Leaf0 (D3): D2D3P1, D2D3P2
#   - Spine1 (D2) <-> Leaf1 (D4): D2D4P1, D2D4P2
#   - Leaf0 (D3) <-> TG1: D3T1P1 (Vlan 2)
#   - Leaf1 (D4) <-> TG2: D4T1P1 (Vlan 3)
#
# Key Configurations:
#   - Loopback27 on leaves used for VTEP IPs (e.g., 2001:db8:1::3 on D3, 2001:db8:1::1 on D4)
#   - VLANs 2, 3, 100 used for L3VNI and VRF mapping
#   - All traffic is Inter-Vlan (TG1 in Vlan 2, TG2 in Vlan 3)
#   - BGP EVPN overlay/underlay with VRF Vrf01 and VNI 1000
#   - VXLAN tunnels and mappings configured per leaf
#   - IPv4 and IPv6 addressing on VLAN interfaces
#
# Refer to ars_l3vni_cfg.yaml for full configuration details.
# =============================================================================

@pytest.fixture(scope = 'function')
def fixture_v6(request):
    st.banner("Fixture for IPv6")
    global tg1_interface, tg2_interface, trBurst, trContinuous, trDSCP1, trDSCP2
    common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    test_instance = request.instance
    vni_type = getattr(test_instance, 'vni_type', 'l2vni')
    data_tgen = data_tgen_l2vni if vni_type == 'l2vni' else data_tgen_l3vni
    tg1_interface, tg2_interface = common_utils.configure_tg_interfaces_v6(tg1, tg2, tg_handle_1, tg_handle_2, data_tgen, data_tgen)
    common_utils.verify_ping_helper(tg1, tg_handle_1, tg1_interface['handle'], data_tgen.t1d2_ipv6_addr)
    common_utils.verify_ping_helper(tg2, tg_handle_2, tg2_interface['handle'], data_tgen.t1d1_ipv6_addr)
    trBurst, trContinuous, trDSCP1, trDSCP2 = common_utils.configure_traffic_streams(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface, 'ipv6')
    yield
    tg_cleanup(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface)

class ARS_VXLAN:
    '''
    For L2VNI, verify ARS functionality with BUM traffic
    ARS Config Mode - Flowlet Quality with idle time 1000 micro seconds
    Traffic Type - Unicast, Multicast, Broadcast (V4)(Burst)
    '''
    def ars_BUM(self):
        st.banner("Verify BUM traffic distribution for ARS Flowlet Quality with idle time 1000 micro seconds")
        common_utils.add_ars(data_glob.leaf0, global_mode="true", mode="flowlet-quality", idle_time="1000")
        for traffic_type in ['unicast', 'multicast', 'broadcast']:
            st.banner("Traffic Type: {}".format(traffic_type))
            stream = trBUM[traffic_type]['stream_id']
            common_utils.run_traffic(data_glob.leaf0, tg1, tg_handle_1, stream)
            counter1 = st.show(data_glob.leaf0, "sudo -s show interface counters")
            st.banner("Traffic is expected to be load balanced after NHG is created, Ars oid should be getting attached to it.")
            assert common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces), "Traffic load is not Distributed for BUM traffic of type {}".format(traffic_type)
        common_utils.del_ars(data_glob.leaf0)
        st.banner("Test Passed: Traffic Load Distributed Evenly")

    '''
    For L2VNI and L3VNI, verify ARS functionality with Unicast traffic
    ARS Config Mode - Flowlet Quality with idle time 1000 micro seconds
    Traffic Type - V4/V6 Burst Unicast 
    '''
    def ars_flowlet(self):
        st.banner("Verify traffic distribution for ARS Flowlet Quality with idle time 1000 micro seconds")
        common_utils.add_ars(data_glob.leaf0, global_mode="true", mode="flowlet-quality", idle_time="1000")
        stream = trBurst['stream_id']
        common_utils.run_traffic(data_glob.leaf0, tg1, tg_handle_1, stream)
        common_utils.del_ars(data_glob.leaf0)
        counter1 = st.show(data_glob.leaf0, "sudo -s show interface counters")
        st.banner("Traffic is expected to be load balanced after NHG is created, Ars oid should be getting attached to it.")
        assert common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces), "Traffic load is not Distributed"
        st.banner("Test Passed: Traffic Load Distributed Evenly")

    '''
    For L2VNI and L3VNI, verify ARS functionality with Unicast traffic
    ARS Config Mode - Per Packet Quality
    Traffic Type - V4/V6 Burst Unicast 
    Note : Per Packet Quality with Continuous traffic is validated in ars_portlist test case
    '''
    def ars_perpacket(self):
        st.banner("Verify traffic distribution for ARS Per Packet Quality")
        common_utils.add_ars(data_glob.leaf0, global_mode="true", mode="per-packet-quality")
        stream = trBurst['stream_id']
        common_utils.run_traffic(data_glob.leaf0, tg1, tg_handle_1, stream)
        common_utils.del_ars(data_glob.leaf0)
        counter1 = st.show(data_glob.leaf0, "sudo -s show interface counters")
        st.banner("Traffic is expected to be load balanced after NHG is created, Ars oid should be getting attached to it.")
        assert common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces), "Traffic load is not Distributed (perpacket)"
        st.banner("Test Passed: Traffic Load Distributed Evenly")

    '''
    Negative Test Case
    For L2VNI and L3VNI, verify ARS should not load balance continuous traffic when configured in flowlet quality mode
    ARS Config Mode - Flowlet Quality with idle time 1000 micro seconds
    Traffic Type - V4/V6 Continuous Unicast
    '''
    def continuous_traffic_ars(self):
        st.banner("Testing Single Continuous Flow with ARS Flowlet Quality with idle time 1000 micro seconds")
        stream = trContinuous['stream_id']
        common_utils.add_ars(data_glob.leaf0, global_mode="true", mode="flowlet-quality", idle_time="1000")
        common_utils.run_traffic(data_glob.leaf0, tg1, tg_handle_1, stream)
        common_utils.del_ars(data_glob.leaf0)
        counter1 = st.show(data_glob.leaf0, "sudo -s show interface counters")
        st.banner("Traffic Expected to flow thorugh single interface for Continuous Traffic")
        assert common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces), "Traffic does not flow thorugh single interface for Continuous Traffic"
        st.banner("Passed: Traffic passes through Single Interface")

    '''
    For L2VNI and L3VNI, verify Conditional DLB functionality
    ARS Config Mode - Flowlet Quality with idle time 1000 micro seconds
    ACL Config - ACL rule to match DSCP value 57
    Traffic Type - V4/V6 DSCP Traffic with ACL rule and without ACL rule
    '''
    def ars_acl(self):
        pytest.skip("Skipping : ARS ACL over VXLAN not supported yet")
        st.banner("Verify traffic distribution for ARS Flowlet Quality with DSCP")
        common_utils.add_ars(data_glob.leaf0, global_mode="false", mode="flowlet-quality", idle_time="1000")
        common_utils.create_acl_table_and_rule(data_glob.leaf0, updated_acl_file_path)
        st.config(data_glob.leaf0, "counterpoll acl enable")
        st.banner("ACL Table")
        st.config(data_glob.leaf0, "show acl table")
        st.banner("ACL Rule")
        st.config(data_glob.leaf0, "show acl rule")
        stream = trDSCP1['stream_id']
        common_utils.run_traffic(data_glob.leaf0, tg1, tg_handle_1, stream)
        counter1 = st.show(data_glob.leaf0, "sudo -s show interface counters")
        st.banner("Traffic is expected to be load balanced for DSCP Traffic with ACL rule.")
        assert common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces), "Traffic load is not Distributed for DSCP Traffic with ACL rule"
        st.banner("Test Passed: Traffic Load Distributed Evenly for DSCP Traffic with ACL rule")
        stream = trDSCP2['stream_id']
        common_utils.run_traffic(data_glob.leaf0, tg1, tg_handle_1, stream)
        st.config(data_glob.leaf0, "acl-loader delete ARS_IPV4")
        common_utils.delete_acl_table(data_glob.leaf0)
        common_utils.del_ars(data_glob.leaf0)
        counter1 = st.show(data_glob.leaf0, "sudo -s show interface counters")
        st.banner("Traffic Expected to flow thorugh single interface for DSCP Traffic without ACL rule")
        assert common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces), "Traffic does not flow thorugh single interface for DSCP Traffic without ACL rule"
        st.banner("Test Passed: Traffic passes through Single Interface for DSCP Traffic without ACL rule")

    ''' 
    For L2VNI and L3VNI, verify ARS Portlist functionality with Unicast traffic  
    ARS Config Mode - Per Packet Quality (per-packet-quality)
    Traffic Type - V4/V6 Continuous Unicast
    '''
    def ars_portlist(self):
        st.banner("Testing ARS Portlist (per-packet) with Continuous Traffic")
        stream = trContinuous['stream_id']
        common_utils.add_ars(data_glob.leaf0, global_mode="false", mode="per-packet-quality")
        st.config(data_glob.leaf0,"sudo -s config ars-portlist add ars_pl --ars-profile-name arsp")
        for intf in data_glob.interfaces:
            st.config(data_glob.leaf0, "sudo -s config ars-portlist-member add {} --ars-portlist ars_pl".format(intf))
        common_utils.run_traffic(data_glob.leaf0, tg1, tg_handle_1, stream)
        counter1 = st.show(data_glob.leaf0, "sudo -s show interface counters")
        for intf in data_glob.interfaces:
            st.config(data_glob.leaf0, "sudo -s config ars-portlist-member del {}".format(intf))
        st.config(data_glob.leaf0,"sudo -s config ars-portlist del ars_pl")
        common_utils.del_ars(data_glob.leaf0)
        st.banner("Traffic Expected to be load balanced for ARS Portlist (per-packet) with Continuous Traffic")
        assert common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces), "Traffic load is not Distributed for ARS Portlist (per-packet) with Continuous Traffic"
        st.banner("Passed: Traffic Load Distributed Evenly for ARS Portlist (per-packet) with Continuous Traffic")


# Run all L2VNI TCs, then all L3VNI TCs, with correct config/unconfig order
@pytest.mark.parametrize('setup_vni', ['l2vni', 'l3vni'], indirect=True)
class TestARS_VXLAN_ALL(ARS_VXLAN):
    @pytest.fixture(autouse=True)
    def _setup_vni(self, setup_vni):
        # This fixture ensures setup_vni is used for each vni_type group
        pass

    @pytest.fixture(autouse=True)
    def _set_vni_type(self, request):
        # Set vni_type attribute for test logic and fixtures
        self.vni_type = request.node.callspec.params['setup_vni']

    # L2VNI-only test
    @pytest.mark.usefixtures('fixture_BUM')
    def test_ars_BUM(self):
        if self.vni_type != 'l2vni':
            st.report_pass("test_case_passed", "Skipping BUM test case for L3VNI")
            return
        try:
            super().ars_BUM()
            st.report_pass("test_case_passed", "ars_BUM test case passed")
        except AssertionError as e:
            common_utils.del_ars(data_glob.leaf0)
            st.report_fail("test_case_failed_msg", f"ars_BUM assertion failed: {e}")

    # IPv6
    @pytest.mark.usefixtures('fixture_v6')
    def test_v6_traffic(self):
        failures = []
        skipped = []
        for fn in [
            ('ars_flowlet', super().ars_flowlet),
            ('ars_perpacket', super().ars_perpacket),
            ('continuous_traffic_ars', super().continuous_traffic_ars),
            ('ars_acl', super().ars_acl),
            ('ars_portlist', super().ars_portlist),
        ]:
            try:
                fn[1]()
            except pytest.skip.Exception as e:
                skipped.append(f"{fn[0]}: {str(e)}")
                continue
            except Exception as e:
                failures.append(f"{fn[0]}: {str(e)}")
                try:
                    common_utils.del_ars(data_glob.leaf0)
                except:
                    pass
                continue
        
        # Report final results
        if skipped:
            st.log(f"Skipped IPv6 sub-tests: {skipped}")
        if failures:
            st.report_fail("test_case_failed_msg", f"IPv6 sub-tests failed: {failures}")
        else:
            st.report_pass("test_case_passed", "All IPv6 sub-tests passed")

    # IPv4
    @pytest.mark.usefixtures('fixture_v4')
    def test_v4_traffic(self):
        failures = []
        skipped = []
        for fn in [
            ('ars_flowlet', super().ars_flowlet),
            ('ars_perpacket', super().ars_perpacket),
            ('continuous_traffic_ars', super().continuous_traffic_ars),
            ('ars_acl', super().ars_acl),
            ('ars_portlist', super().ars_portlist),
        ]:
            try:
                fn[1]()
            except pytest.skip.Exception as e:
                skipped.append(f"{fn[0]}: {str(e)}")
                continue
            except Exception as e:
                failures.append(f"{fn[0]}: {str(e)}")
                try:
                    common_utils.del_ars(data_glob.leaf0)
                except:
                    pass
                continue
        
        # Report final results
        if skipped:
            st.log(f"Skipped IPv4 sub-tests: {skipped}")
        if failures:
            st.report_fail("test_case_failed_msg", f"IPv4 sub-tests failed: {failures}")
        else:
            st.report_pass("test_case_passed", "All IPv4 sub-tests passed")
