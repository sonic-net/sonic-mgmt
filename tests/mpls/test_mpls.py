import os
import time
import random
import logging
import pprint
import json

from abc import ABCMeta, abstractmethod

import pytest

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common import reboot, port_toggle
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db_module
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
#    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('t1'),
#    pytest.mark.sanity_check(skip_sanity=True)
]
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR='/tmp'
ADD_DIR = os.path.join(BASE_DIR, 'configs')

LABEL_POP_ROUTES='label_pop_routes'
LABEL_PUSH_ROUTES='label_push_routes'
LABEL_SWAP_ROUTES='label_swap_routes'
LABEL_DEL_ROUTES='label_del_routes'

@pytest.fixture(scope='module')
def setup(duthost, tbinfo, ptfadapter):
    """
    setup fixture gathers all test required information from DUT facts and tbinfo
    :param duthost: DUT host object
    :param tbinfo: fixture provides information about testbed
    :return: dictionary with all test required information
    """
    if tbinfo['topo']['name'] not in ('t1', 't1-lag', 't1-64-lag', 't1-64-lag-clet'):
        pytest.skip('Unsupported topology')

    # gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    int_facts = duthost.interface_facts()['ansible_facts']
    host_facts = duthost.setup()['ansible_facts']

    tor_ports_ids=[]
    tor_ports={}
    spine_ports_ids=[]
    spine_ports={}
    tor_addr={}
    tor_peer_addr={}
    spine_addr={}
    spine_peer_addr={}
    tor_mac={}
    spine_mac={}
 
    # get the list of TOR/SPINE ports
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        if not port_up(duthost, dut_port): 
            continue
        port_id = mg_facts['minigraph_port_indices'][dut_port]
        if 'T0' in neigh['name']:
            tor_ports[port_id]=dut_port
            tor_ports_ids.append(port_id)
        elif 'T2' in neigh['name']:
            spine_ports[port_id]=dut_port
            spine_ports_ids.append(port_id)
    
    logger.info('tor_ports: {}'.format(tor_ports))
    logger.info('spine_ports: {}'.format(spine_ports))    
        
    for blk in mg_facts['minigraph_interfaces']:
        if ':' in blk['peer_addr']:
            continue
        dut_port=blk['attachto']
        port_id = mg_facts['minigraph_port_indices'][dut_port] 
        neigh=mg_facts['minigraph_neighbors'][dut_port]       
        if 'T0' in neigh['name']:
             tor_addr[port_id]=blk['addr']
             tor_peer_addr[port_id]=blk['peer_addr']
        elif 'T2' in neigh['name']:
             spine_addr[port_id]=blk['addr']
             spine_peer_addr[port_id]=blk['peer_addr']
            
    for pid, dut_port in tor_ports.items():
        port_id = mg_facts['minigraph_port_indices'][dut_port]
        ansible_port='ansible_'+dut_port
        tor_mac[port_id]=host_facts[ansible_port]['macaddress']
    
    for pid, dut_port in spine_ports.items():
        port_id = mg_facts['minigraph_port_indices'][dut_port]
        ansible_port='ansible_'+dut_port
        spine_mac[port_id]=host_facts[ansible_port]['macaddress']

    setup_information = {
        'duthost': duthost,
        'dut_tmp_dir': DUT_TMP_DIR,
        'dst_ip_spine_blocked': '192.168.144.1',
        'tor_ports': tor_ports,
        'spine_ports': spine_ports,
        'tor_addr': tor_addr,
        'tor_peer_addr': tor_peer_addr,
        'spine_addr': spine_addr,
        'spine_peer_addr': spine_peer_addr,
        'tor_ports_ids': tor_ports_ids,
        'spine_ports_ids': spine_ports_ids,
        'tor_mac': tor_mac,
        'spine_mac': spine_mac,
    }

    logger.info('setup variables {}'.format(pprint.pformat(setup)))

    # FIXME: There seems to be some issue with the initial setup of the ptfadapter, causing some of the
    # TestBasicMPLS tests to fail because the forwarded packets are not being collected. This is an
    # attempt to mitigate that issue while we continue to investigate the root cause.
    #
    # Ref: GitHub Issue #2032
    logger.info("setting up the ptfadapter")
    ptfadapter.reinit()

    yield setup_information

    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_POP_ROUTES)))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_SWAP_ROUTES)))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_PUSH_ROUTES1)))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_DEL_ROUTES)))

def port_up(dut, interface):
    intf_facts = dut.interface_facts()['ansible_facts']
    try:
        port = intf_facts["ansible_interface_facts"][interface]
        if port["link"] and port["active"]:
            return True
    except KeyError:
            return False
    return False

class BaseMplsTest(object):
    """
    Base class for MPLS label testing.
    Derivatives have to provide @setup_rules method to prepare DUT for MPLS traffic test and
    optionally override @teardown_rules which base implementation is simply applying empty MPLS labels
    configuration file
    """
    __metaclass__ = ABCMeta


    @abstractmethod
    def setup_rules(self, dut, setup):
        """
        setup rules for test
        :param dut: dut host
        :param setup: setup information
        :return:
        """
        pass

    def post_setup_hook(self, dut, localhost):
        """
        perform actions after rules are applied
        :param dut: DUT host object
        :param localhost: localhost object
        :return:
        """

        pass

    def teardown_labels(self, setup, src_port, dst_port):
        """
        teardown MPLS label after test by applying empty configuration
        :param dut: DUT host object
        :param setup: setup information
        :return:
        """
        setup = setup
        duthost = setup['duthost']
    
        logger.info('removing all MPLS')
        mpls_config = '{}.json'.format(LABEL_DEL_ROUTES)
        label_del_dut_path = os.path.join(setup['dut_tmp_dir'], mpls_config)
        template_file='{}.j2'.format(LABEL_DEL_ROUTES)
        duthost.template(src=os.path.join(ADD_DIR, template_file), dest=label_del_dut_path)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_del_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        result = duthost.shell('config interface mpls remove {}'.format(src_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        result = duthost.shell('config interface mpls remove {}'.format(dst_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        
    def get_src_portid(self, setup):
        """ return source port id """

        src_pids = setup['spine_ports_ids']
        return random.choice(src_pids)

    def get_dst_portid(self, setup):
        """ return destination port id"""
        
        dst_pids = setup['tor_ports_ids']
        return random.choice(dst_pids)

    def icmp_packet(self, setup, ptfadapter, dst_pid, src_pid):
        """ create ICMP packet for testing """
        return testutils.simple_icmp_packet(
            eth_dst=setup['spine_mac'][src_pid],
            eth_src=ptfadapter.dataplane.get_mac(0, src_pid),
            ip_dst='192.168.0.1',
            ip_src=setup['spine_addr'][src_pid],
            icmp_type=8,
            icmp_code=0,
            ip_ttl=64,
        )
    def mpls_packet(self, setup, ptfadapter, dst_pid, src_pid):
        """ create MPLS packet for testing """
        return testutils.simple_mpls_packet(
            eth_dst=setup['spine_mac'][src_pid],
            eth_src=ptfadapter.dataplane.get_mac(0, src_pid),
            mpls_tags = [
                         {
                          'label':1000001,
                          'ttl': 63,
                          's':1
                         }
                        ],
            inner_frame = testutils.simple_ip_only_packet(
                ip_dst='192.168.0.1',
                ip_src=setup['spine_addr'][src_pid],
            )
        )

    def mpls_stack_packet(self, setup, ptfadapter, dst_pid, src_pid):
        """ create MPLS packet for testing """
        return testutils.simple_mpls_packet(
            eth_dst=setup['spine_mac'][src_pid],
            eth_src=ptfadapter.dataplane.get_mac(0, src_pid),
            mpls_tags = [
                         {
                          'label':1000001,
                          'ttl': 255,
                          's':0
                         },
                         {
                          'label':1000010,
                          'ttl': 255,
                          's':0
                         },
                         {
                          'label':1000011,
                          'ttl': 255,
                          's':1
                         }
                        ],
            inner_frame = testutils.simple_ip_only_packet(
                ip_dst='192.168.0.1',
                ip_src=setup['spine_addr'][src_pid],
            )
        )

         
    def expected_mask_ip_packet(self, pkt):
        """ return mask for ip packet """
        
        epkt=pkt.copy()
        exp_pkt = pkt.copy()
        exp_pkt['IP'].ttl = 62
        pkt1 = exp_pkt['IP']
        exp_pkt['Ether'].type=0x0800
        exp_pkt['Ether'].remove_payload()
        exp_pkt /= pkt1
        #exp_pkt['IP'].len=100
        epkt = mask.Mask(epkt)
        #pkt2 = mask.Mask(pkt2)
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
        return exp_pkt
    
    def expected_mask_mpls_swap_packet(self, pkt, exp_label):
        """ return mask for mpls packet """

        exp_pkt = pkt.copy()
        exp_pkt['MPLS'].ttl -= 1
        exp_pkt['MPLS'].label = exp_label
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

        return exp_pkt
    
    def expected_mask_mpls_push_packet(self, pkt, exp_label):
        """ return mask for mpls packet """
        
        exp_pkt = pkt.copy()
        exp_pkt['MPLS'].ttl = exp_pkt['IP'].ttl - 1
        exp_pkt['IP'].ttl -= 1
        exp_pkt['MPLS'].label = exp_label
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
        
        return exp_pkt

    def test_pop_label(self, setup, ptfadapter):
        """ test pop label """
            
        setup = setup
        duthost = setup['duthost']

        dst_pid=self.get_dst_portid(setup)
        src_pid=self.get_src_portid(setup)

        dst_port=setup['tor_ports'][dst_pid]
        src_port=setup['spine_ports'][src_pid]

        dst_peer_addr=setup['tor_peer_addr'][dst_pid]
        src_peer_addr=setup['spine_peer_addr'][src_pid]

        config_variables = {
            'dst_port': dst_port,
            'src_port': src_port,
            'dst_peer_addr': dst_peer_addr,
            'src_peer_addr': src_peer_addr,
        }

        logger.info('extra variables for MPLS config:\n{}'.format(pprint.pformat(config_variables)))
        duthost.host.options['variable_manager'].extra_vars.update(config_variables)
        
        logger.info('generate config for MPLS')
        mpls_config = '{}.json'.format(LABEL_POP_ROUTES)
        mpls_config_path = os.path.join(setup['dut_tmp_dir'], mpls_config)
        template_file='{}.j2'.format(LABEL_POP_ROUTES)
        duthost.template(src=os.path.join(ADD_DIR, template_file), dest=mpls_config_path)

        result = duthost.shell('config interface mpls add {}'.format(src_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        result = duthost.shell('config interface mpls add {}'.format(dst_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(mpls_config_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))
            
        time.sleep(20)
        pkt = self.mpls_packet(setup, ptfadapter, dst_pid, src_pid)
        exp_pkt = self.expected_mask_ip_packet(pkt)
 
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_labels(setup,src_port,dst_port)  
            pytest.fail('MPLS pop test failed \n' + str(e))
        
        self.teardown_labels(setup,src_port,dst_port)

    def test_swap_label(self, setup, ptfadapter):
        """ test swap label """

        setup = setup
        duthost = setup['duthost']

        dst_pid=self.get_dst_portid(setup)
        src_pid=self.get_src_portid(setup)

        dst_port=setup['tor_ports'][dst_pid]
        src_port=setup['spine_ports'][src_pid]

        dst_peer_addr=setup['tor_peer_addr'][dst_pid]
        src_peer_addr=setup['spine_peer_addr'][src_pid]

        config_variables = {
            'dst_port': dst_port,
            'src_port': src_port,
            'dst_peer_addr': dst_peer_addr,
            'src_peer_addr': src_peer_addr,
        }

        logger.info('extra variables for MPLS config:\n{}'.format(pprint.pformat(config_variables)))
        duthost.host.options['variable_manager'].extra_vars.update(config_variables)
        
        logger.info('generate config for MPLS')
        mpls_config = '{}.json'.format(LABEL_SWAP_ROUTES)
        mpls_config_path = os.path.join(setup['dut_tmp_dir'], mpls_config)
        template_file='{}.j2'.format(LABEL_SWAP_ROUTES)
        duthost.template(src=os.path.join(ADD_DIR, template_file), dest=mpls_config_path)

        result = duthost.shell('config interface mpls add {}'.format(src_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        result = duthost.shell('config interface mpls add {}'.format(dst_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(mpls_config_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))
        
        pkt = self.mpls_packet(setup, ptfadapter, dst_pid, src_pid)
        exp_pkt = self.expected_mask_mpls_swap_packet(pkt, 1000002)
        
        time.sleep(20)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
        except Exception as e:
            self.teardown_labels(setup,src_port,dst_port)
            pytest.fail('MPLS swap test failed \n' + str(e)) 
      
        self.teardown_labels(setup,src_port,dst_port)
 
    def test_push_label(self, setup, ptfadapter):
        """ test push label """
        
        setup = setup
        duthost = setup['duthost']

        dst_pid=self.get_dst_portid(setup)
        src_pid=self.get_src_portid(setup)

        dst_port=setup['tor_ports'][dst_pid]
        src_port=setup['spine_ports'][src_pid]

        dst_peer_addr=setup['tor_peer_addr'][dst_pid]
        src_peer_addr=setup['spine_peer_addr'][src_pid]

        config_variables = {
            'dst_port': dst_port,
            'src_port': src_port,
            'dst_peer_addr': dst_peer_addr,
            'src_peer_addr': src_peer_addr,
        }

        logger.info('extra variables for MPLS config:\n{}'.format(pprint.pformat(config_variables)))
        duthost.host.options['variable_manager'].extra_vars.update(config_variables)
        
        logger.info('generate config for MPLS')
        mpls_config = '{}.json'.format(LABEL_PUSH_ROUTES)
        mpls_config_path = os.path.join(setup['dut_tmp_dir'], mpls_config)
        template_file='{}.j2'.format(LABEL_PUSH_ROUTES)
        duthost.template(src=os.path.join(ADD_DIR, template_file), dest=mpls_config_path)

        result = duthost.shell('config interface mpls add {}'.format(src_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        result = duthost.shell('config interface mpls add {}'.format(dst_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(mpls_config_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        time.sleep(20)

        pkt = self.icmp_packet(setup, ptfadapter, dst_pid, src_pid)
        epkt = pkt.copy()
        pkt1 = epkt['IP']
        epkt['Ether'].type=0x8847
        epkt['Ether'].remove_payload()
        mp = MPLS(label=1000002, s=1, ttl=255)
        mp.remove_payload()
        epkt /= mp
        epkt /= pkt1
        exp_pkt = self.expected_mask_mpls_push_packet(epkt, 1000001)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)

        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_labels(setup,src_port,dst_port)
            pytest.fail('MPLS push test failed \n' + str(e))

        self.teardown_labels(setup,src_port,dst_port)

    def test_swap_labelstack(self, setup, ptfadapter):
        """ test swap labelstack """
        
        setup = setup
        duthost = setup['duthost']

        dst_pid=self.get_dst_portid(setup)
        src_pid=self.get_src_portid(setup)

        dst_port=setup['tor_ports'][dst_pid]
        src_port=setup['spine_ports'][src_pid]

        dst_peer_addr=setup['tor_peer_addr'][dst_pid]
        src_peer_addr=setup['spine_peer_addr'][src_pid]

        config_variables = {
            'dst_port': dst_port,
            'src_port': src_port,
            'dst_peer_addr': dst_peer_addr,
            'src_peer_addr': src_peer_addr,
        }

        logger.info('extra variables for MPLS config:\n{}'.format(pprint.pformat(config_variables)))
        duthost.host.options['variable_manager'].extra_vars.update(config_variables)
        
        logger.info('generate config for MPLS')
        mpls_config = '{}.json'.format(LABEL_SWAP_ROUTES)
        mpls_config_path = os.path.join(setup['dut_tmp_dir'], mpls_config)
        template_file='{}.j2'.format(LABEL_SWAP_ROUTES)
        duthost.template(src=os.path.join(ADD_DIR, template_file), dest=mpls_config_path)

        result = duthost.shell('config interface mpls add {}'.format(src_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        result = duthost.shell('config interface mpls add {}'.format(dst_port),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))
 
        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(mpls_config_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        pkt = self.mpls_stack_packet(setup, ptfadapter, dst_pid, src_pid)
        exp_pkt = self.expected_mask_mpls_swap_packet(pkt, 1000002)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)

        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_labels(setup,src_port,dst_port)
            pytest.fail('MPLS swap labelstack test failed \n' + str(e))

        self.teardown_labels(setup,src_port,dst_port)


class TestBasicMpls(BaseMplsTest):
    """
    Basic MPLS label traffic tests.
    Setup rules using full update, run traffic tests cases.
    """

    def setup_rules(self, dut, setup):
        """
        setup rules on DUT
        :param dut: dut host
        :param setup: setup information
        :return:
        """
        
        pass 
