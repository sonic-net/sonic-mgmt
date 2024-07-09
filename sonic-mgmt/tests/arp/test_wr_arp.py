import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                             # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                                # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses                                 # noqa F401
from tests.common.fixtures.ptfhost_utils import skip_traffic_test                                   # noqa F401
from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies     # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

# Globals
PTFRUNNER_QLEN = 1000
VXLAN_CONFIG_FILE = '/tmp/vxlan_decap.json'
DEFAULT_TEST_DURATION = 370


class TestWrArp:
    '''
        TestWrArp Performs control plane assisted warm-reboot
    '''
    def __prepareVxlanConfigData(self, duthost, ptfhost, tbinfo):
        '''
            Prepares Vxlan Configuration data for Ferret service running on PTF host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        vlan_facts = duthost.vlan_facts()['ansible_facts']['ansible_vlan_facts']
        vxlanConfigData = {
            'minigraph_port_indices': mgFacts['minigraph_ptf_indices'],
            'minigraph_portchannel_interfaces': mgFacts['minigraph_portchannel_interfaces'],
            'minigraph_portchannels': mgFacts['minigraph_portchannels'],
            'minigraph_lo_interfaces': mgFacts['minigraph_lo_interfaces'],
            'vlan_facts': vlan_facts,
            'dut_mac': duthost.facts['router_mac']
        }
        with open(VXLAN_CONFIG_FILE, 'w') as file:
            file.write(json.dumps(vxlanConfigData, indent=4))

        logger.info('Copying ferret config file to {0}'.format(ptfhost.hostname))
        ptfhost.copy(src=VXLAN_CONFIG_FILE, dest='/tmp/')

    def setupFerret(self, duthost, ptfhost, tbinfo):
        '''
            Sets Ferret service on PTF host. This class-scope fixture runs once before test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        ptfhost.copy(src="arp/files/ferret.py", dest="/opt")

        '''
            Get the IP which will be used by ferret script from the "ip route show type unicast"
            command output. The output looks as follows:

            default proto 186 src 10.1.0.32 metric 20
                nexthop via 10.0.0.57  dev PortChannel0001 weight 1
                nexthop via 10.0.0.59  dev PortChannel0002 weight 1
                nexthop via 10.0.0.61  dev PortChannel0003 weight 1
                nexthop via 10.0.0.63  dev PortChannel0004 weight 1
            10.0.0.56/31 dev PortChannel0001 proto kernel scope link src 10.0.0.56
            10.232.24.0/23 dev eth0 proto kernel scope link src 10.232.24.122
            100.1.0.29 via 10.0.0.57 dev PortChannel0001 proto 186 src 10.1.0.32 metric 20
            192.168.0.0/21 dev Vlan1000 proto kernel scope link src 192.168.0.1
            192.168.8.0/25 proto 186 src 10.1.0.32 metric 20
                nexthop via 10.0.0.57  dev PortChannel0001 weight 1
                nexthop via 10.0.0.59  dev PortChannel0002 weight 1
                nexthop via 10.0.0.61  dev PortChannel0003 weight 1
                nexthop via 10.0.0.63  dev PortChannel0004 weight 1
            192.168.16.0/25 proto 186 src 10.1.0.32 metric 20
            ...

            We'll use the first subnet IP taken from zebra protocol as the base for the host IP.
            As in the new SONiC image the proto will look as '186'(201911) or bgp (master)
            instead of 'zebra' (like it looks in 201811)the filtering output command below will pick
            the first line containing either 'proto zebra' (or 'proto 186' or 'proto bgp')
            (except the one for the deafult route) and take host IP from the subnet IP. For the output
            above 192.168.8.0/25 subnet will be taken and host IP given to ferret script will be 192.168.8.1
        '''
        result = duthost.shell(
            cmd=r'''ip route show type unicast |
            sed -e '/proto 186\|proto zebra\|proto bgp/!d' -e '/default/d' -ne '/0\//p' |
            head -n 1 |
            sed -ne 's/0\/.*$/1/p'
            '''
        )

        pytest_assert(len(result['stdout'].strip()) > 0, 'Empty DIP returned')

        dip = result['stdout']
        logger.info('VxLan Sender {0}'.format(dip))

        vxlan_port_out = duthost.shell('redis-cli -n 0 hget "SWITCH_TABLE:switch" "vxlan_port"')
        if 'stdout' in vxlan_port_out and vxlan_port_out['stdout'].isdigit():
            vxlan_port = int(vxlan_port_out['stdout'])
            ferret_args = '-f /tmp/vxlan_decap.json -s {0} -a {1} -p {2}'.format(
                dip, duthost.facts["asic_type"], vxlan_port)
        else:
            ferret_args = '-f /tmp/vxlan_decap.json -s {0} -a {1}'.format(dip, duthost.facts["asic_type"])

        ptfhost.host.options['variable_manager'].extra_vars.update({'ferret_args': ferret_args})

        logger.info('Copying ferret config file to {0}'.format(ptfhost.hostname))
        ptfhost.template(src='arp/files/ferret.conf.j2', dest='/etc/supervisor/conf.d/ferret.conf')

        logger.info('Generate pem and key files for ssl')
        ptfhost.command(
            cmd='''openssl req -new -x509 -keyout test.key -out test.pem -days 365 -nodes
            -subj "/C=10/ST=Test/L=Test/O=Test/OU=Test/CN=test.com"''',
            chdir='/opt'
        )

        self.__prepareVxlanConfigData(duthost, ptfhost, tbinfo)

        logger.info('Refreshing supervisor control with ferret configuration')
        ptfhost.shell('supervisorctl reread && supervisorctl update')

    @pytest.fixture(scope='class', autouse=True)
    def setupFerretFixture(self, duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
        duthost = duthosts[rand_one_dut_hostname]
        self.setupFerret(duthost, ptfhost, tbinfo)

    @pytest.fixture(scope='class', autouse=True)
    def clean_dut(self, duthosts, rand_one_dut_hostname):
        duthost = duthosts[rand_one_dut_hostname]
        yield
        logger.info("Clear ARP cache on DUT")
        duthost.command('sonic-clear arp')

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

        return route, ptfIp, gwIp

    def teardownRouteToPtfhost(self, duthost, route, ptfIp, gwIp):
        """
        Teardown the routes added by setupRouteToPtfhost
        """
        if 'PortChannel' in route:
            logger.info(
                "Delete explicit route for PTF host ({0}) through eth0 (mgmt) interface ({1})".format(ptfIp, gwIp)
            )
            result = duthost.shell(cmd='ip route delete {0}/32 {1}'.format(ptfIp, gwIp), module_ignore_errors=True)
            assert result["rc"] == 0 or "No such process" in result["stderr"], \
                "Failed to delete route with error '{0}'".format(result["stderr"])

    @pytest.fixture(scope='class', autouse=True)
    def setupRouteToPtfhostFixture(self, duthosts, rand_one_dut_hostname, ptfhost):
        duthost = duthosts[rand_one_dut_hostname]
        route, ptfIp, gwIp = self.setupRouteToPtfhost(duthost, ptfhost)
        yield
        self.teardownRouteToPtfhost(duthost, route, ptfIp, gwIp)

    @pytest.fixture(scope='class', autouse=True)
    def warmRebootSystemFlag(self, duthost):
        """
            Sets warm-reboot system flag to false after test. This class-scope fixture runs once before test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        yield
        if not wait_until(300, 10, 0, self.checkWarmbootFlag, duthost):
            logger.info('Setting warm-reboot system flag to false')
            duthost.shell(cmd='sonic-db-cli STATE_DB hset "WARM_RESTART_ENABLE_TABLE|system" enable false')

    def checkWarmbootFlag(self, duthost):
        """
            Checks if warm-reboot system flag is set to false.
        """
        warmbootFlag = duthost.shell(
            cmd='sonic-db-cli STATE_DB hget "WARM_RESTART_ENABLE_TABLE|system" enable')['stdout']
        logger.info("warmbootFlag: " + warmbootFlag)
        return warmbootFlag != 'true'

    def Setup(self, duthost, ptfhost, tbinfo):
        """
        A setup function that do the exactly same thing as the autoused fixtures do
        Will be called in vnet_vxlan test
        """
        self.setupFerret(duthost, ptfhost, tbinfo)
        self.route, self.ptfIp, self.gwIp = self.setupRouteToPtfhost(duthost, ptfhost)

    def Teardown(self, duthost):
        """
        A teardown function that do some cleanup after test
        Will be called in vnet_vxlan test
        """
        logger.info("Clear ARP cache on DUT")
        duthost.command('sonic-clear arp')
        self.teardownRouteToPtfhost(duthost, self.route, self.ptfIp, self.gwIp)

    def testWrArp(self, request, duthost, ptfhost, creds, skip_traffic_test):   # noqa F811
        '''
            Control Plane Assistant test for Warm-Reboot.

            The test first start Ferret server, implemented in Python. Then initiate Warm-Reboot procedure.
            While the host in Warm-Reboot test continuously sending ARP request to the Vlan member ports and
            expect to  receive ARP replies. The test will fail as soon as there is no replies for
            more than 25 seconds for one of the Vlan member ports.

            Args:
                request: pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        testDuration = request.config.getoption('--test_duration', default=DEFAULT_TEST_DURATION)
        ptfIp = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
        dutIp = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

        logger.info('Warm-Reboot Control-Plane assist feature')
        sonicadmin_alt_password = duthost.host.options['variable_manager'].\
            _hostvars[duthost.hostname]['sonic_default_passwords']
        if skip_traffic_test is True:
            return
        ptf_runner(
            ptfhost,
            'ptftests',
            'wr_arp.ArpTest',
            qlen=PTFRUNNER_QLEN,
            platform_dir='ptftests',
            platform='remote',
            params={
                'ferret_ip': ptfIp,
                'dut_ssh': dutIp,
                'dut_username': creds['sonicadmin_user'],
                'dut_password': creds['sonicadmin_password'],
                "alt_password": sonicadmin_alt_password,
                'config_file': VXLAN_CONFIG_FILE,
                'how_long': testDuration,
                'advance': False,
            },
            log_file='/tmp/wr_arp.ArpTest.log',
            is_python3=True
        )

    def testWrArpAdvance(self, request, duthost, ptfhost, creds, skip_traffic_test):    # noqa F811
        testDuration = request.config.getoption('--test_duration', default=DEFAULT_TEST_DURATION)
        ptfIp = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
        dutIp = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

        logger.info('Warm-Reboot Control-Plane assist feature')
        sonicadmin_alt_password = duthost.host.options['variable_manager'].\
            _hostvars[duthost.hostname]['sonic_default_passwords']
        if skip_traffic_test is True:
            return
        ptf_runner(
            ptfhost,
            'ptftests',
            'wr_arp.ArpTest',
            qlen=PTFRUNNER_QLEN,
            platform_dir='ptftests',
            platform='remote',
            params={
                'ferret_ip': ptfIp,
                'dut_ssh': dutIp,
                'dut_username': creds['sonicadmin_user'],
                'dut_password': creds['sonicadmin_password'],
                "alt_password": sonicadmin_alt_password,
                'config_file': VXLAN_CONFIG_FILE,
                'how_long': testDuration,
                'advance': True,
            },
            log_file='/tmp/wr_arp.ArpTest.Advance.log',
            is_python3=True
        )
