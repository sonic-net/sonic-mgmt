import json
import logging
import pytest

from common.platform.ssh_utils import prepare_testbed_ssh_keys as prepareTestbedSshKeys
from ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

# Globals
PTFRUNNER_QLEN = 1000
VXLAN_CONFIG_FILE = '/tmp/vxlan_decap.json'

class TestWrArp:
    '''
        TestWrArp Performs control plane assisted warm-reboo
    '''
    def __prepareVxlanConfigData(self, duthost, ptfhost):
        '''
            Prepares Vxlan Configuration data for Ferret service running on PTF host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        mgFacts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        vxlanConfigData = {
            'minigraph_port_indices': mgFacts['minigraph_port_indices'],
            'minigraph_portchannel_interfaces': mgFacts['minigraph_portchannel_interfaces'],
            'minigraph_portchannels': mgFacts['minigraph_portchannels'],
            'minigraph_lo_interfaces': mgFacts['minigraph_lo_interfaces'],
            'minigraph_vlans': mgFacts['minigraph_vlans'],
            'minigraph_vlan_interfaces': mgFacts['minigraph_vlan_interfaces'],
            'dut_mac': duthost.setup()['ansible_facts']['ansible_Ethernet0']['macaddress']
        }
        with open(VXLAN_CONFIG_FILE, 'w') as file:
            file.write(json.dumps(vxlanConfigData, indent=4))

        logger.info('Copying ferret config file to {0}'.format(ptfhost.hostname))
        ptfhost.copy(src=VXLAN_CONFIG_FILE, dest='/tmp/')

    @pytest.fixture(scope='class', autouse=True)
    def setupFerret(self, duthost, ptfhost):
        '''
            Sets Ferret service on PTF host. This class-scope fixture runs once before test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        ptfhost.copy(src="arp/files/ferret.py", dest="/opt")

        result = duthost.shell(
            cmd='''ip route show proto zebra type unicast |
            sed -e '/default/d' -ne '/0\//p' |
            head -n 1 |
            sed -ne 's/0\/.*$/1/p'
            '''
        )
        assert len(result['stderr_lines']) == 0, 'Could not obtain DIP'

        dip = result['stdout']
        logger.info('VxLan Sender {0}'.format(dip))

        ptfhost.host.options['variable_manager'].extra_vars.update({
            'ferret_args': '-f /tmp/vxlan_decap.json -s {0}'.format(dip)
        })

        logger.info('Copying ferret config file to {0}'.format(ptfhost.hostname))
        ptfhost.template(src='arp/files/ferret.conf.j2', dest='/etc/supervisor/conf.d/ferret.conf')

        logger.info('Generate pem and key files for ssl')
        ptfhost.command(
            cmd='''openssl req -new -x509 -keyout test.key -out test.pem -days 365 -nodes 
            -subj "/C=10/ST=Test/L=Test/O=Test/OU=Test/CN=test.com"''',
            chdir='/opt'
        )

        self.__prepareVxlanConfigData(duthost, ptfhost)

        logger.info('Refreshing supervisor control with ferret configuration')
        ptfhost.shell('supervisorctl reread && supervisorctl update')

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
    def setupRouteToPtfhost(self, duthost, ptfhost):
        '''
            Sets routes up on DUT to PTF host. This class-scope fixture runs once before test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        result = duthost.shell(cmd="ip route show table default | sed -n 's/default //p'")
        assert len(result['stderr_lines']) == 0, 'Could not find the gateway for management port'

        gwIp = result['stdout']
        ptfIp = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']

        route = duthost.shell(cmd='ip route get {0}'.format(ptfIp))['stdout']
        if 'PortChannel' in route:
            logger.info(
                "Add explicit route for PTF host ({0}) through eth0 (mgmt) interface ({1})".format(ptfIp, gwIp)
            )
            duthost.shell(cmd='ip route add {0}/32 {1}'.format(ptfIp, gwIp))

        yield

        if 'PortChannel' in route:
            logger.info(
                "Delete explicit route for PTF host ({0}) through eth0 (mgmt) interface ({1})".format(ptfIp, gwIp)
            )
            duthost.shell(cmd='ip route delete {0}/32 {1}'.format(ptfIp, gwIp))

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

    @pytest.fixture(scope='class', autouse=True)
    def prepareSshKeys(self, duthost, ptfhost):
        '''
            Prepares testbed ssh keys by generating ssh key on ptf host and adding this key to known_hosts on duthost
            This class-scope fixture runs once before test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        invetory = duthost.host.options['inventory'].split('/')[-1]
        secrets = duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']

        prepareTestbedSshKeys(duthost, ptfhost, secrets[invetory]['sonicadmin_user'])

    def testWrArp(self, request, duthost, ptfhost):
        '''
            Control Plane Assistent test for Warm-Reboot.

            The test first start Ferret server, implemented in Python. Then initiate Warm-Reboot procedure. While the
            host in Warm-Reboot test continuously sending ARP request to the Vlan member ports and expect to receive ARP
            replies. The test will fail as soon as there is no replies for more than 25 seconds for one of the Vlan
            member ports.

            Args:
                request: pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        testDuration = request.config.getoption('--test_duration')
        ptfIp = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
        dutIp = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

        logger.info('Warm-Reboot Control-Plane assist feature')
        ptf_runner(
            ptfhost,
            'ptftests',
            'wr_arp.ArpTest',
            qlen=PTFRUNNER_QLEN,
            platform_dir='ptftests',
            platform='remote',
            params={
                'ferret_ip' : ptfIp,
                'dut_ssh' : dutIp,
                'config_file' : VXLAN_CONFIG_FILE,
                'how_long' : testDuration,
            },
            log_file='/tmp/wr_arp.ArpTest.log'
        )
