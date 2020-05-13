import os
import time
import pytest
from ptf_runner import ptf_runner
from abc import abstractmethod
import ipaddr as ipaddress

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
FILES_DIR = os.path.join(BASE_DIR, 'files')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')

EVERFLOW_TABLE_RULE_CREATE_TEMPLATE = 'acl_rule_persistent.json.j2'
EVERFLOW_TABLE_RULE_CREATE_FILE = 'acl_rule_persistent.json'
EVERFLOW_TABLE_RULE_DELETE_FILE = 'acl_rule_persistent-del.json'
DUT_RUN_DIR = '/home/admin/everflow_tests'

@pytest.fixture(scope="module", autouse=True)
def copy_acstests_directory(ptfhost):
    """ Fixture which copies the ptftests directory to the PTF host. This fixture
        is scoped to the module, as it only needs to be performed once before
        the first test is run. It does not need to be run before each test.
        We also set autouse=True to ensure this fixture gets instantiated before
        the first test runs, even if we don't explicitly pass it to them, and since
        there is no return value, there is no point in passing it into the functions.
    """
    ptfhost.copy(src="acstests", dest="/root")

@pytest.fixture(scope='module')
def setup_info(duthost, testbed):
    """
    setup fixture gathers all test required information from DUT facts and testbed
    :param duthost: DUT host object
    :param testbed: Testbed object
    :return: dictionary with all test required information
    """
    if testbed['topo']['name'] not in ('t1', 't1-lag', 't1-64-lag', 't1-64-lag-clet'):
        pytest.skip('Unsupported topology')

    tor_ports = []
    spine_ports = []
    port_channels = []

    # gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    #gather switch capability facts
    switch_capability_facts = duthost.switch_capabilities_facts()['ansible_facts']
    #gather host facts
    host_facts = duthost.setup()['ansible_facts']

    # get the list of TOR/SPINE ports
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        if 'T0' in neigh['name']:
            #for T1 Toplogy if dest port is TOR add T0 neighbors
            tor_ports.append(dut_port)
        elif 'T2' in neigh['name']:
            #for T1 topology if dest port is Spine add T2 neighbors
            spine_ports.append(dut_port)

    # get the list of port channels
    port_channels = mg_facts['minigraph_portchannels']

    test_mirror_v4 = switch_capability_facts['switch_capabilities']['switch']['MIRROR'] == 'true'
    test_mirror_v6 = switch_capability_facts['switch_capabilities']['switch']['MIRRORV6'] == 'true'
    test_ingress_mirror_on_ingress_acl = 'MIRROR_INGRESS_ACTION' in switch_capability_facts['switch_capabilities']['switch']['ACL_ACTIONS|INGRESS']
    test_ingress_mirror_on_egress_acl = 'MIRROR_INGRESS_ACTION' in switch_capability_facts['switch_capabilities']['switch']['ACL_ACTIONS|EGRESS']
    test_egress_mirror_on_egress_acl = 'MIRROR_EGRESS_ACTION' in switch_capability_facts['switch_capabilities']['switch']['ACL_ACTIONS|EGRESS']
    test_egress_mirror_on_ingress_acl = 'MIRROR_EGRESS_ACTION' in switch_capability_facts['switch_capabilities']['switch']['ACL_ACTIONS|INGRESS']


    def get_port_info(in_port_list, out_port_list, out_port_ptf_id_list, out_port_lag_name): 
        ptf_port_id = ''
        out_port_exclude_list = []
        for port in in_port_list:
            if port not in out_port_list and port not in out_port_exclude_list and len(out_port_list) < 4:
                ptf_port_id += (str(mg_facts['minigraph_port_indices'][port]))
                out_port_list.append(port)
                out_port_lag_name.append("Not Applicable")
                for portchannelinfo in mg_facts['minigraph_portchannels'].items():
                    if port in portchannelinfo[1]['members']:
                        out_port_lag_name[-1] = portchannelinfo[0]
                        for lag_memeber in portchannelinfo[1]['members']:
                            if port == lag_memeber:
                                continue
                            ptf_port_id += "," +  (str(mg_facts['minigraph_port_indices'][lag_memeber]))
                            out_port_exclude_list.append(lag_memeber)
                out_port_ptf_id_list.append(ptf_port_id)
                ptf_port_id = ''

    tor_dest_ports = []
    tor_dest_ports_ptf_id = []
    tor_dest_lag_name = []
    get_port_info(tor_ports, tor_dest_ports, tor_dest_ports_ptf_id, tor_dest_lag_name)

    spine_dest_ports = []
    spine_dest_ports_ptf_id = []
    spine_dest_lag_name = []
    get_port_info(spine_ports, spine_dest_ports, spine_dest_ports_ptf_id, spine_dest_lag_name)

    setup_information = {
        'router_mac': host_facts['ansible_Ethernet0']['macaddress'],
        'tor_ports': tor_ports,
        'spine_ports': spine_ports,
        'port_channels': port_channels,
        'test_mirror_v4' : test_mirror_v4,
        'test_mirror_v6' : test_mirror_v6,
        'ingress' : {'ingress': test_ingress_mirror_on_ingress_acl, 'egress' : test_egress_mirror_on_ingress_acl},
        'egress' : {'ingress': test_ingress_mirror_on_egress_acl, 'egress' : test_egress_mirror_on_egress_acl},
        'tor' : {'src_port' : spine_ports[0], 'src_port_ptf_id' : str(mg_facts['minigraph_port_indices'][spine_ports[0]]), 'dest_port' : tor_dest_ports, 'dest_port_ptf_id':tor_dest_ports_ptf_id,
                 'dest_port_lag_name': tor_dest_lag_name},
        'spine' : {'src_port' : tor_ports[0], 'src_port_ptf_id' : str(mg_facts['minigraph_port_indices'][tor_ports[0]]), 'dest_port' : spine_dest_ports, 'dest_port_ptf_id':spine_dest_ports_ptf_id,
                   'dest_port_lag_name': spine_dest_lag_name}
    }


    # This is important to add since for Policer test case regular packet
    # and mirror packet can go to same interface which cause tail drop of 
    # police packet and test case cir/cbs calculation gets impacted
    # We are making Regular Traffic has dedicated route and don't use
    # default route.

    peer_ip, peer_mac = get_neighbor_info(duthost, spine_dest_ports[3])
    
    add_route(duthost, "30.0.0.1/24", peer_ip)

    yield setup_information
    
    remove_route(duthost, "30.0.0.1/24", peer_ip)



#partial_ptf_runner is a pytest fixture that takes all the necessary arguments to run
#each everflow ptf test cases and calling the main function ptf_runner which will then 
#combine all the arguments and form ptf command to run via ptfhost.shell(). 
#some of the arguments are fix for each everflow test cases and are define here and 
#arguments specific to each everflow testcases are passed in each test via partial_ptf_runner
#Argumnents are passed in dictionary format via kwargs within each test case.

@pytest.fixture
def partial_ptf_runner(request, duthost, ptfhost):
    def _partial_ptf_runner(setup_info, session_info, acl_stage, mirror_type,  expect_receive = True, test_name = None, **kwargs):
        params = {
                  'hwsku' :  duthost.facts['hwsku'],
                  'asic_type' :  duthost.facts['asic_type'],
                  'router_mac': setup_info['router_mac'],
                  'session_src_ip' : session_info['session_src_ip'],
                  'session_dst_ip' : session_info['session_dst_ip'],
                  'session_ttl' : session_info['session_ttl'],
                  'session_dscp' : session_info['session_dscp'],
                  'acl_stage' : acl_stage,
                  'mirror_stage' : mirror_type,
                  'expect_received' : expect_receive }
        params.update(kwargs)
        ptf_runner(host=ptfhost,
                   testdir="acstests",
                   platform_dir="ptftests",
                   testname="everflow_tb_test.EverflowTest" if not test_name else test_name,
                   params=params,
                   socket_recv_size=16384,
                   log_file="/tmp/{}.{}.log".format(request.cls.__name__, request.function.__name__))

    return _partial_ptf_runner

def add_route(duthost, prefix, nexthop):
    """
    utility to add route
    duthost: fixture that have duthost information
    prefix:  Ip prefix 
    nexthop: nexthop
    """
    duthost.shell("vtysh -c 'configure terminal' -c 'ip route {} {}'".format(prefix, nexthop))

def remove_route(duthost, prefix, nexthop):
    """
    utility to remove route
    duthost: fixture that have duthost information
    prefix:  Ip prefix 
    nexthop: nexthop
    """
    duthost.shell("vtysh -c 'configure terminal' -c 'no ip route {} {}'".format(prefix, nexthop))

def get_neighbor_info(duthost, dest_port, resolved = True):

    if resolved == False:
        return '20.20.20.100', None

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    for bgp_peer in mg_facts['minigraph_bgp']:
        if bgp_peer['name'] == mg_facts['minigraph_neighbors'][dest_port]['name'] and ipaddress.IPAddress(bgp_peer['addr']).version == 4:
            peer_ip = bgp_peer['addr']
            break

    return peer_ip, duthost.shell("ip neigh show {} | awk -F' ' '{{print $5}}'".format(peer_ip))['stdout']


class BaseEverflowTest(object):

    @pytest.fixture(params=['tor', 'spine'])
    def dest_port_type(self, request):
        """
        used to parametrized test cases on dest port type
        :param request: pytest request object
        :return: destination port type
        """
        return request.param

    @pytest.fixture(scope='class')
    def setup_mirror_session(self, duthost):
        """Setup the Everflow Session"""

        session_name =  "test_session_1"
        session_src_ip =  "1.1.1.1"
        session_dst_ip = "2.2.2.2"
        session_ttl = "1"
        session_dscp = "8"

        session_prefixlens = ["24", "32"]
        session_prefixes = []
        for prefixlen in session_prefixlens:
            session_prefixes.append(str(ipaddress.IPNetwork(session_dst_ip + "/" + prefixlen).network) + "/" + prefixlen)

        if "mellanox" == duthost.facts["asic_type"]:
            duthost.command('config mirror_session add {} {} {} {} {} 0x8949'.format(session_name, session_src_ip, session_dst_ip, session_dscp, session_ttl))
        else:
            duthost.command('config mirror_session add {} {} {} {} {}'.format(session_name, session_src_ip, session_dst_ip, session_dscp, session_ttl))

        yield {'session_name' : session_name,
               'session_src_ip' : session_src_ip,
               'session_dst_ip' : session_dst_ip,
               'session_ttl' : session_ttl,
               'session_dscp' : session_dscp,
               'session_prefixes': session_prefixes
               }

        duthost.command('config mirror_session remove {}'.format(session_name))


    @abstractmethod
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        """
        setup the acl table
        return:pass
        """
        pass


    @abstractmethod
    def mirror_type(self):
        """
        used to parametrized test cases on mirror type
        :param request: pytest request object
        :return: mirror type
        """
        pass

    @abstractmethod
    def acl_stage(self):
        """
        get the acl stage
        return:pass
        """
        pass


    def test_everflow_case1(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """  Test on Resolved route, unresolved route, best prefix match route creation and removal flows """

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        
        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        # call the function return by pytest fixture and pass arguments needed for 
        # ptf test case like src port, dest port, acl_stage, mirror_type.
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port, False)
        
        add_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        remove_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)
        
        tx_port = setup_info[dest_port_type]['dest_port'][1]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][1]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        
        add_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)
        time.sleep(3)
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        remove_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)
        time.sleep(3)
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)


        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)
    
    def test_everflow_case2(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """Test case 2 - Change neighbor MAC address.
        Verify that session destination MAC address is changed after neighbor MAC address update."""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        
        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)


        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        if setup_info[dest_port_type]['dest_port_lag_name'][0] != 'Not Applicable':
            tx_port = setup_info[dest_port_type]['dest_port_lag_name'][0]


        duthost.shell("ip neigh replace {} lladdr 00:11:22:33:44:55 nud permanent dev {}".format(peer_ip, tx_port))
        
        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id,
                           expected_dst_mac = '00:11:22:33:44:55')

        
        duthost.shell("ip neigh del {} dev {}".format(peer_ip, tx_port))
        
        duthost.shell("ping {} -c3".format(peer_ip))


        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)
    
    def test_everflow_case3(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """Test case 3 -  ECMP route change (remove next hop not used by session).
        Verify that after removal of next hop that was used by session from ECMP route session state is active."""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        peer_ip0 = peer_ip
        
        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        tx_port = setup_info[dest_port_type]['dest_port'][1]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][1]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        peer_ip1 = peer_ip

        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)
        
        time.sleep(3)
       
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][0])

        tx_port = setup_info[dest_port_type]['dest_port'][2]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][2]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        
        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)
        
        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)
        
        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)
        
        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = setup_info[dest_port_type]['dest_port_ptf_id'][0] + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][1])

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)
 
        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip0)
        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip1)


    def test_everflow_case4(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """Test case 4 - ECMP route change (remove next hop used by session).
        Verify that removal of next hop that is not used by session doesn't cause DST port and MAC change."""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        peer_ip0 = peer_ip
        
        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)
        
        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)
 
        tx_port = setup_info[dest_port_type]['dest_port'][1]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        peer_ip1 = peer_ip

        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        tx_port = setup_info[dest_port_type]['dest_port'][2]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        peer_ip2 = peer_ip

        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)
        
        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = setup_info[dest_port_type]['dest_port_ptf_id'][0])
 
       
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports =  setup_info[dest_port_type]['dest_port_ptf_id'][1] + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][2])

        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip0)
        
        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports = setup_info[dest_port_type]['dest_port_ptf_id'][0])
 
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports =  setup_info[dest_port_type]['dest_port_ptf_id'][1] + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][2])

        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip1)
        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip2)

    def test_everflow_case5(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):

        """Test case 5 - Policer enforced DSCP value/mask test"""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        # Create Policer.
        duthost.shell("redis-cli -n 4 hmset 'POLICER|TEST_POLICER' meter_type packets mode sr_tcm\
                        cir 100 cbs 100 red_packet_action drop")

        # Add Mirror Session with Policer aqttached to it.
        if "mellanox" == duthost.facts["asic_type"]:
            duthost.command('config mirror_session add TEST_POLICER_SESSION {} {} {} {} 0x8949 --policer TEST_POLICER'.format(
                            setup_mirror_session['session_src_ip'], setup_mirror_session['session_dst_ip'],
                            setup_mirror_session['session_dscp'], setup_mirror_session['session_ttl']))
        else:
            duthost.command('config mirror_session add TEST_POLICER_SESSION {} {} {} {} --policer TEST_POLICER'.format(
                            setup_mirror_session['session_src_ip'], setup_mirror_session['session_dst_ip'],
                            setup_mirror_session['session_dscp'], setup_mirror_session['session_ttl']))

       # Add ACL rule to match on DSCP and action as mirror
        mirror_action = "MIRROR_INGRESS_ACTION" if self.mirror_type() == 'ingress' else "MIRROR_EGRESS_ACTION" 
        duthost.shell("redis-cli -n 4 hmset 'ACL_RULE|EVERFLOW_DSCP|RULE_1' PRIORITY 9999  {} TEST_POLICER_SESSION DSCP 8/56".format(mirror_action))

        time.sleep(3)

        # Send Traiffic with expected cir/cbs and tolerlance %
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           expect_receive = True, test_name = 'everflow_policer_test.EverflowPolicerTest',
                           src_port = rx_port_ptf_id, dst_mirror_ports = tx_port_ptf_id,
                           dst_ports = tx_port_ptf_id, meter_type = "packets", cir = "100", cbs = "100",
                           tolerance = "10")

        # Cleanup
        duthost.command('config mirror_session remove TEST_POLICER_SESSION')
        duthost.shell("redis-cli -n 4 del 'POLICER|TEST_POLICER_SESSION'")
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|EVERFLOW_DSCP|RULE_1'")
        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

    def test_everflow_case6(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):

        """ Test Case 6 - ARP/ND packet mirroring"""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        

        mirror_action = "MIRROR_INGRESS_ACTION" if self.mirror_type() == 'ingress' else "MIRROR_EGRESS_ACTION"

        # Add ACL Rule to match on ARP and DSCP packets.
        duthost.shell("redis-cli -n 4 hmset 'ACL_RULE|EVERFLOW|RULE_ARP' PRIORITY 8888 {} {} ETHER_TYPE 2054".format(mirror_action, setup_mirror_session['session_name']))
        duthost.shell("redis-cli -n 4 hmset 'ACL_RULE|EVERFLOWV6|RULE_ND' PRIORITY 8888 {} {} ICMPV6_TYPE 135".format(mirror_action,setup_mirror_session['session_name']))

        peer_ip, peer_mac = get_neighbor_info(duthost, tx_port)
        add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           expect_receive = True, test_name = 'everflow_neighbor_test.EverflowNeighborTest',
                           src_port = rx_port_ptf_id, dst_mirror_ports = tx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        #Remove ACL rule for Everflow and ARP Packets.
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|EVERFLOW|RULE_ARP'")
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|EVERFLOWV6|RULE_ND'")
        remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

class TestEverflowIngressAclIngressMirror(BaseEverflowTest):

    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
            pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))
        duthost.command('acl-loader update full {} --session_name={}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_TEST --stage=ingress")

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return 'ingress'

    def  mirror_type(self):
        return 'ingress'

class TestEverflowIngressAclEgressMirror(BaseEverflowTest):

    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
            pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))
        duthost.command('acl-loader update full {} --session_name={}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_TEST --stage=ingress")

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return 'ingress'

    def  mirror_type(self):
        return 'egress'

class TestEverflowEgressAclIngressMirror(BaseEverflowTest):

    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
           pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW_EGRESS"}) 

        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))
        
        
        duthost.command("config acl add table EVERFLOW_EGRESS MIRROR --description EVERFLOW_EGRESS --stage=egress")
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_EGRESS_TEST --stage=egress")
        duthost.command('acl-loader update full {} --session_name={} --mirror_stage=egress'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))

        yield
        
        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_EGRESS")
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return 'egress'

    def  mirror_type(self):
        return 'ingress'

class TestEverflowEgressAclEgressMirror(BaseEverflowTest):

    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
           pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))
        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW_EGRESS"}) 


        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))
        
        
        duthost.command("config acl add table EVERFLOW_EGRESS MIRROR --description EVERFLOW_EGRESS --stage=egress")
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_EGRESS_TEST --stage=egress")
        duthost.command('acl-loader update full {} --session_name={} --mirror_stage=egress'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_EGRESS")
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return 'egress'

    def  mirror_type(self):
        return 'egress'
