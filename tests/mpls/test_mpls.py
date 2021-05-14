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
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('t1')
]
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR='/tmp'
ADD_DIR = os.path.join(BASE_DIR, 'configs')

LABEL_POP_ROUTES='label_pop_routes.json'
LABEL_PUSH_ROUTES='label_push_routes.json'
LABEL_SWAP_ROUTES='label_swap_routes.json'
LABEL_DEL_ROUTES='label_del_routes.json'

@pytest.fixture(scope='module')
def setup(duthost, tbinfo, ptfadapter):
    """
    setup fixture gathers all test required information from DUT facts and tbinfo
    :param duthost: DUT host object
    :param tbinfo: fixture provides information about testbed
    :return: dictionary with all test required information
    """
    if tbinfo['topo']['name'] not in ('t1'):
        pytest.skip('Unsupported topology')

    # gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    # get the list of TOR/SPINE ports
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        port_id = mg_facts['minigraph_port_indices'][dut_port]

    # get the list of port channels
    port_channels = mg_facts['minigraph_portchannels']

    host_facts = duthost.setup()['ansible_facts']

    setup_information = {
        'eth_dst': host_facts['ansible_Ethernet10']['macaddress'],
        'duthost': duthost,
        'dut_tmp_dir': DUT_TMP_DIR,
    }

    logger.info('setup variables {}'.format(pprint.pformat(setup_information)))

    # Check for: GitHub Issue #2032
    logger.info("setting up the ptfadapter")
    ptfadapter.reinit()

    yield setup_information

    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_POP_ROUTES)))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_SWAP_ROUTES)))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_PUSH_ROUTES)))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_DEL_ROUTES)))


class BaseMplsTest(object):
    """
    Base class for MPLS testing.
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

    def teardown_rules(self, setup):
        """
        teardown MPLS configurations after test by applying DEL configuration
        :param setup: setup information
        :return:
        """

        logger.info('removing all MPLS')
        duthost = setup['duthost']
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_DEL_ROUTES), dest=setup['dut_tmp_dir'])
        label_del_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_DEL_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_del_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))
    
        pass


    def icmp_packet(self, setup, ptfadapter):
        """ create ICMP packet for testing """
        return testutils.simple_icmp_packet(
            eth_dst=setup['eth_dst'],
            eth_src=ptfadapter.dataplane.get_mac(0, 10),
            ip_dst='192.168.0.1',
            ip_src='10.0.0.21',
            icmp_type=8,
            icmp_code=0,
            ip_ttl=64,
        )
    def mpls_packet(self, setup, ptfadapter):
        """ create MPLS packet for testing """
        return testutils.simple_mpls_packet(
            eth_dst=setup['eth_dst'],
            eth_src=ptfadapter.dataplane.get_mac(0, 10),
            mpls_tags = [
                         {
                          'label':1000001,
                          'ttl': 255,
                          's':1
                         }
                        ],
            inner_frame = testutils.simple_ip_only_packet(
                ip_dst='192.168.0.1',
                ip_src='10.0.0.21',
            )
        )

    def mpls_stack_packet(self, setup, ptfadapter):
        """ create stacked MPLS packet for testing """
        return testutils.simple_mpls_packet(
            eth_dst=setup['eth_dst'],
            eth_src=ptfadapter.dataplane.get_mac(0, 10),
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
                ip_src='10.0.0.21',
            )
        )

         
    def expected_mask_ip_packet(self, pkt):
        """ return mask for ip packet """
        
        epkt=pkt.copy()
        exp_pkt = pkt.copy()
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
        """ return mask for mpls swap packet """

        exp_pkt = pkt.copy()
        exp_pkt['MPLS'].ttl -= 1
        exp_pkt['MPLS'].label = exp_label
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

        return exp_pkt
    
    def expected_mask_mpls_push_packet(self, pkt, exp_label):
        """ return mask for mpls push packet """
        
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
        """ test for pop MPLS label """
        
        duthost = setup['duthost']
        
        # Copy APP_DB config to DUT
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_POP_ROUTES), dest=setup['dut_tmp_dir'])
        label_add_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_POP_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_add_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        # Create packet for sending and masked expected packet on receiving port     
        pkt = self.mpls_packet(setup, ptfadapter)
        exp_pkt = self.expected_mask_ip_packet(pkt)

        ptfadapter.dataplane.flush()
        
        # Send pkt from spine port 10
        testutils.send(ptfadapter, '10', pkt)
        
        # Capture and verify packets on tor port 25
        res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[25])
        
        # Copy Delete MPLS configs to DUT after test 
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_DEL_ROUTES), dest=setup['dut_tmp_dir'])
        label_del_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_DEL_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_del_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))


    def test_swap_label(self, setup, ptfadapter):
        """ test for swap MPLS label """
        
        duthost = setup['duthost']
        
        # Copy APP_DB config to DUT
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_SWAP_ROUTES), dest=setup['dut_tmp_dir'])
        label_add_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_SWAP_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_add_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))
        
        # Create packet for sending and masked expected packet on receiving port  
        pkt = self.mpls_packet(setup, ptfadapter)
        exp_pkt = self.expected_mask_mpls_swap_packet(pkt, 1000002)

        ptfadapter.dataplane.flush()
        
        # Send pkt from spine port 10
        testutils.send(ptfadapter, '10', pkt)
        
        # Capture and verify packets on tor port 25
        res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[25])
        
        # Copy Delete MPLS configs to DUT after test 
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_DEL_ROUTES), dest=setup['dut_tmp_dir'])
        label_del_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_DEL_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_del_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

    def test_push_label(self, setup, ptfadapter):
        """ test push MPLS label """
        
        duthost = setup['duthost']
        
        # Copy APP_DB config to DUT
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_PUSH_ROUTES), dest=setup['dut_tmp_dir'])
        label_add_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_PUSH_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_add_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        # Create packet for sending and masked expected packet on receiving port 
        pkt = self.icmp_packet(setup, ptfadapter)
        ## Add MPLS header in expected packet
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
        
        # Send pkt from spine port 10
        testutils.send(ptfadapter, '10', pkt)
        
        # Capture and verify packets on tor port 25
        res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[25])
        
        # Copy Delete MPLS configs to DUT after test
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_DEL_ROUTES), dest=setup['dut_tmp_dir'])
        label_del_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_DEL_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_del_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))
            
    def test_swap_labelstack(self, setup, ptfadapter):
        """ test swap for stack of 3 MPLS label """
        
        duthost = setup['duthost']
        
        # Copy APP_DB config to DUT
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_SWAP_ROUTES), dest=setup['dut_tmp_dir'])
        label_add_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_SWAP_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_add_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))

        # Create packet for sending and masked expected packet on receiving port 
        pkt = self.mpls_stack_packet(setup, ptfadapter)
        exp_pkt = self.expected_mask_mpls_swap_packet(pkt, 1000002)

        ptfadapter.dataplane.flush()
        
        # Send pkt from spine port 10
        testutils.send(ptfadapter, '10', pkt)
        
        # Capture and verify packets on tor port 25
        res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[25])

        # Copy Delete MPLS configs to DUT after test
        duthost.copy(src=os.path.join(ADD_DIR, LABEL_DEL_ROUTES), dest=setup['dut_tmp_dir'])
        label_del_dut_path = os.path.join(setup['dut_tmp_dir'], LABEL_DEL_ROUTES)

        # Apply routes with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(label_del_dut_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr']))


class TestBasicMpls(BaseMplsTest):
    """
    Basic MPLS traffic tests.
    """

    def setup_rules(self, dut, setup):
        """
        setup rules on DUT
        :param dut: dut host
        :param setup: setup information
        :return:
        """
        
        pass 
