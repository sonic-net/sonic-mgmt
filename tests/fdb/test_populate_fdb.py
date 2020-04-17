import json
import logging
import pytest

from common.platform.ssh_utils import prepare_testbed_ssh_keys as prepareTestbedSshKeys
from ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

# Globals
PTFRUNNER_QLEN = 1000
VXLAN_CONFIG_FILE = '/tmp/vxlan_config.json'

class TestPopulateFdb:
    '''
        TestPopulateFdb populates DUT FDB entries
    '''
    @pytest.fixture(scope='class', autouse=True)
    def prepareVxlanConfigData(self, duthost, ptfhost):
        '''
            Prepares Vxlan Configuration data

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        mgVlanPorts = []
        mgFacts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        for vlan, config in mgFacts['minigraph_vlans'].items():
            for port in config['members']:
                mgVlanPorts.append({
                    'port': port,
                    'vlan': vlan,
                    'index': mgFacts['minigraph_port_indices'][port]
                })

        vxlanConfigData = {
            'vlan_ports': mgVlanPorts,
            'vlan_interfaces': {vlan['attachto']: vlan for vlan in mgFacts['minigraph_vlan_interfaces']},
            'dut_mac': duthost.setup()['ansible_facts']['ansible_Ethernet0']['macaddress']
        }

        with open(VXLAN_CONFIG_FILE, 'w') as file:
            file.write(json.dumps(vxlanConfigData, indent=4))

        logger.info('Copying VxLan config file to {0}'.format(ptfhost.hostname))
        ptfhost.copy(src=VXLAN_CONFIG_FILE, dest='/tmp/')

    @pytest.fixture(scope='class', autouse=True)
    def copyPtfDirectory(self, ptfhost):
        '''
            Copys PTF directory to PTF host. This class-scope fixture runs once before test start

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        ptfhost.copy(src="ptftests", dest="/root")

    @pytest.fixture(scope='class', autouse=True)
    def removePtfhostIp(self, ptfhost):
        '''
            Removes IP assigned to eth<n> inerface of PTF host. This class-scope fixture runs once before test start

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        ptfhost.script(src='scripts/remove_ip.sh')

    @pytest.fixture(scope='class', autouse=True)
    def changePtfhostMacAddresses(self, ptfhost):
        '''
            Change MAC addresses (unique) on PTF host. This class-scope fixture runs once before test start

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        ptfhost.script(src="scripts/change_mac.sh")

    def testPopulateFdb(self, request, duthost, ptfhost):
        '''
            Populates DUT FDB entries

            The accepts MAC to IP ratio (default 100:1) and packet count (default 2000). It generates packets with
            ratio of distinct MAC addresses to distinct IP addresses as provided. The IP addresses starts from VLAN
            address pool.

            Args:
                request: pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        macToIpRatio = request.config.getoption("--mac_to_ip_ratio")
        startMac = request.config.getoption("--start_mac")
        packetCount = request.config.getoption("--packet_count")

        logger.info('Populate DUT FDB entries')
        ptf_runner(
            ptfhost,
            'ptftests',
            'populate_fdb.PopulateFdb',
            qlen=PTFRUNNER_QLEN,
            platform_dir='ptftests',
            platform='remote',
            params={
                'start_mac': startMac,
                'config_data': VXLAN_CONFIG_FILE,
                'packet_count': packetCount,
                'mac_to_ip_ratio': macToIpRatio,
            },
            log_file='/tmp/populate_fdb.PopulateFdb.log'
        )
