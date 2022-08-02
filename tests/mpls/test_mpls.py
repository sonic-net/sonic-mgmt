import logging
import os
import pprint
import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils
import pytest
import time

logger=logging.getLogger(__name__)

pytestmark=[
    pytest.mark.topology('t1'),
]
CONFIGS_DIR=os.path.dirname(os.path.realpath(__file__))
ADD_DIR=os.path.join(CONFIGS_DIR, 'configs')

LABEL_POP_ROUTES='label_pop_routes'
LABEL_PUSH_ROUTES='label_push_routes'
LABEL_SWAP_ROUTES='label_swap_routes'
LABEL_DEL_ROUTES='label_del_routes'

class TestBasicMpls:
    """
    Base class for MPLS label testing.
    Derivatives have to provide @setup_rules method to prepare DUT for MPLS traffic test and
    optionally override @teardown_rules which base implementation is simply applying empty MPLS labels
    configuration file
    """
    def teardown_labels(self, setup):
        """
        teardown MPLS label after test by applying empty configuration
        :param dut: DUT host object
        :param setup: setup information
        :return:
        """
        logger.info("Remove mpls comfigs")
        self.config_interface_mpls(setup, LABEL_DEL_ROUTES, False)
        
    def icmp_packet(self, setup, ptfadapter):
        """ create ICMP packet for testing """
        return testutils.simple_icmp_packet(
            eth_dst=setup['src_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, setup['src_pid']),
            ip_dst='192.168.0.1',
            ip_src=setup['src_addr'],
            icmp_type=8,
            icmp_code=0,
            ip_ttl=64,
        )
    def mpls_packet(self, setup, ptfadapter):
        """ create MPLS packet for testing """
        return testutils.simple_mpls_packet(
            eth_dst=setup['src_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, setup['src_pid']),
            mpls_tags=[
                         {
                          'label':1000001,
                          'ttl': 63,
                          's':1
                         }
                        ],
            inner_frame=testutils.simple_ip_only_packet(
                ip_dst='192.168.0.1',
                ip_src=setup['src_addr'],
            )
          )

    def mpls_stack_packet(self, setup, ptfadapter):
        """ create MPLS packet for testing """
        return testutils.simple_mpls_packet(
            eth_dst=setup['src_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, setup['src_pid']),
            mpls_tags=[
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
            inner_frame=testutils.simple_ip_only_packet(
                ip_dst='192.168.0.1',
                ip_src=setup['src_addr'],
            )
        )

    def expected_mask_ip_packet(self, pkt):
        """ return mask for ip packet """
   
        epkt=pkt.copy()
        exp_pkt=pkt.copy()
        exp_pkt['IP'].ttl=62
        pkt1=exp_pkt['IP']
        exp_pkt['Ethernet'].type=0x0800
        exp_pkt['Ethernet'].remove_payload()
        exp_pkt /= pkt1
        exp_pkt=mask.Mask(exp_pkt)
        exp_pkt=mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
        return exp_pkt
 
    def expected_mask_mpls_swap_packet(self, pkt, exp_label):
        """ return mask for mpls packet """

        exp_pkt=pkt.copy()
        exp_pkt['MPLS'].ttl -= 1
        exp_pkt['MPLS'].label=exp_label
        exp_pkt=mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

        return exp_pkt
    
    def expected_mask_mpls_push_packet(self, pkt, exp_label):
        """ return mask for mpls packet """
        
        exp_pkt=pkt.copy()
        exp_pkt['MPLS'].ttl=exp_pkt['IP'].ttl - 1
        exp_pkt['IP'].ttl -= 1
        exp_pkt['MPLS'].label=exp_label
        exp_pkt=mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
        
        return exp_pkt
    
    def config_interface_mpls(self, setup,  config_file, enable=True):
        """ enable/disable mpls on interface """
        duthost=setup['duthost']

        dst_port=setup['dst_port']
        src_port=setup['src_port']

        dst_peer_addr=setup['dst_peer_addr']
        src_peer_addr=setup['src_peer_addr']

        config_variables={
            'dst_port': dst_port,
            'src_port': src_port,
            'dst_peer_addr': dst_peer_addr,
            'src_peer_addr': src_peer_addr,
        }

        logger.info('extra variables for MPLS config:\n{}'.format(pprint.pformat(config_variables)))
        duthost.host.options['variable_manager'].extra_vars.update(config_variables)

        logger.info('generate config for MPLS')
        mpls_config='{}.json'.format(config_file)
        mpls_config_path=os.path.join(setup['dut_tmp_dir'], mpls_config)
        template_file='{}.j2'.format(config_file)
        duthost.template(src=os.path.join(ADD_DIR, template_file), dest=mpls_config_path)


        for intf in [dst_port, src_port]:
            if enable:
                result=duthost.shell('config interface mpls add {}'.format(intf),
                           module_ignore_errors=True)
                if result['rc'] != 0:
                    pytest.fail('Failed to enable mplson interface {} : {}'.format(intf, result['stderr'])) 
            else:
                 result=duthost.shell('config interface mpls remove {}'.format(intf),
                           module_ignore_errors=True)
                 if result['rc'] != 0:
                    pytest.fail('Failed to disable mpls on interface {} : {}'.format(intf, result['stderr']))

        # Apply config with swssconfig
        result=duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(mpls_config_path),
                           module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply labelroute configuration file: {}'.format(result['stderr'])) 
            
    def test_pop_label(self, setup, ptfadapter):
        """ test pop label """
        dst_pid=setup['dst_pid']
        src_pid=setup['src_pid']

        self.config_interface_mpls(setup, LABEL_POP_ROUTES)
        
        time.sleep(2)
        
        pkt=self.mpls_packet(setup, ptfadapter)
        exp_pkt=self.expected_mask_ip_packet(pkt)
         
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res=testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_labels(setup)  
            pytest.fail('MPLS pop test failed \n'+ str(e))
        
        self.teardown_labels(setup)

    def test_swap_label(self, setup, ptfadapter):
        """ test swap label """

        dst_pid=setup['dst_pid']
        src_pid=setup['src_pid']

        self.config_interface_mpls(setup, LABEL_SWAP_ROUTES) 
   
        time.sleep(2)
 
        pkt=self.mpls_packet(setup, ptfadapter)
        exp_pkt=self.expected_mask_mpls_swap_packet(pkt, 1000002)
        
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res=testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_labels(setup)
            pytest.fail('MPLS swap test failed \n' + str(e)) 
      
        self.teardown_labels(setup)
 
    def test_push_label(self, setup, ptfadapter):
        """ test push label """
        
        dst_pid=setup['dst_pid']
        src_pid=setup['src_pid']

        self.config_interface_mpls(setup, LABEL_PUSH_ROUTES)

        time.sleep(2)

        pkt=self.icmp_packet(setup, ptfadapter)
        epkt=pkt.copy()
        pkt1=epkt['IP']
        epkt['Ethernet'].type=0x8847
        epkt['Ethernet'].remove_payload()
        mp=MPLS(label=1000002, s=1, ttl=255)
        mp.remove_payload()
        epkt /= mp
        epkt /= pkt1
        exp_pkt=self.expected_mask_mpls_push_packet(epkt, 1000001)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)

        try:
            res=testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_labels(setup)
            pytest.fail('MPLS push test failed \n' + str(e))

        self.teardown_labels(setup)

    def test_swap_labelstack(self, setup, ptfadapter):
        """ test swap labelstack """

        dst_pid=setup['dst_pid']
        src_pid=setup['src_pid']

        self.config_interface_mpls(setup, LABEL_SWAP_ROUTES)
 
        time.sleep(2)

        pkt=self.mpls_stack_packet(setup, ptfadapter)
        exp_pkt=self.expected_mask_mpls_swap_packet(pkt, 1000002)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)

        try:
            res=testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_labels(setup)
            pytest.fail('MPLS swap labelstack test failed \n' + str(e))

        self.teardown_labels(setup)
