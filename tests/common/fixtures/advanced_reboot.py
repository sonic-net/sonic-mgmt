import ipaddress
import itertools
import json
import logging
import pytest
import time

from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.platform.ssh_utils import prepare_testbed_ssh_keys as prepareTestbedSshKeys
from tests.common.reboot import reboot as rebootDut
from tests.ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

# Globals
HOST_MAX_COUNT = 126
TIME_BETWEEN_SUCCESSIVE_TEST_OPER = 420
PTFRUNNER_QLEN = 1000

class AdvancedReboot:
    '''
    AdvancedReboot is used to perform reboot dut while running preboot/inboot operations

    This class collects information about the current testbed. This information is used by test cases to build
    inboot/preboot list. The class transfers number of configuration files to the dut/ptf in preparation for reboot test.
    Test cases can trigger test start utilizing runRebootTestcase API.
    '''
    def __init__(self, request, duthost, ptfhost, localhost, tbinfo, creds, **kwargs):
        '''
        Class constructor.
        @param request: pytest request object
        @param duthost: AnsibleHost instance of DUT
        @param ptfhost: PTFHost for interacting with PTF through ansible
        @param localhost: Localhost for interacting with localhost through ansible
        @param tbinfo: fixture provides information about testbed
        @param kwargs: extra parameters including reboot type
        '''
        assert 'rebootType' in kwargs and kwargs['rebootType'] in ['fast-reboot', 'warm-reboot'], (
            "Please set rebootType var."
        )

        if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
            self.kvmTest = True
            device_marks = [arg for mark in request.node.iter_markers(name='device_type') for arg in mark.args]
            if 'vs' not in device_marks:
                pytest.skip('Testcase not supported for kvm')
        else:
            self.kvmTest = False

        self.request = request
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.localhost = localhost
        self.tbinfo = tbinfo
        self.creds = creds
        self.moduleIgnoreErrors = False
        self.__dict__.update(kwargs)
        self.__extractTestParam()
        self.rebootData = {}
        self.hostMaxLen = 0
        self.lagMemberCnt = 0
        self.vlanMaxCnt = 0
        self.hostMaxCnt = HOST_MAX_COUNT

        self.__buildTestbedData(tbinfo)

    def __extractTestParam(self):
        '''
        Extract test parameters from pytest request object. Note that all the parameters have default values.
        '''
        self.vnet = self.request.config.getoption("--vnet")
        self.vnetPkts = self.request.config.getoption("--vnet_pkts")
        self.rebootLimit = self.request.config.getoption("--reboot_limit")
        self.sniffTimeIncr = self.request.config.getoption("--sniff_time_incr")
        self.allowVlanFlooding = self.request.config.getoption("--allow_vlan_flooding")
        self.stayInTargetImage = self.request.config.getoption("--stay_in_target_image")
        self.newSonicImage = self.request.config.getoption("--new_sonic_image")
        self.cleanupOldSonicImages = self.request.config.getoption("--cleanup_old_sonic_images")
        self.readyTimeout = self.request.config.getoption("--ready_timeout")
        self.replaceFastRebootScript = self.request.config.getoption("--replace_fast_reboot_script")
        self.postRebootCheckScript = self.request.config.getoption("--post_reboot_check_script")
        self.bgpV4V6TimeDiff = self.request.config.getoption("--bgp_v4_v6_time_diff")

        # Set default reboot limit if it is not given
        if self.rebootLimit is None:
            if self.kvmTest:
                self.rebootLimit = 200 # Default reboot limit for kvm
            else:
                self.rebootLimit = 30 # Default reboot limit for physical devices

    def getHostMaxLen(self):
        '''
        Accessor method for hostMaxLen
        '''
        # Number of VMS - 1
        return self.hostMaxLen

    def getlagMemberCnt(self):
        '''
        Accessor method for lagMemberCnt
        '''
        return self.lagMemberCnt

    def getVlanMaxCnt(self):
        '''
        Accessor method for vlanMaxCnt
        '''
        return self.vlanMaxCnt

    def getHostMaxCnt(self):
        '''
        Accessor method for hostMaxCnt
        '''
        return self.hostMaxCnt

    def getTestbedType(self):
        '''
        Accessor method for testbed's topology name
        '''
        return self.tbinfo['topo']['name']

    def __buildTestbedData(self, tbinfo):
        '''
        Build testbed data that are needed by ptf advanced-reboot.ReloadTest class
        '''

        self.mgFacts = self.duthost.get_extended_minigraph_facts(tbinfo)

        self.rebootData['arista_vms'] = [
            attr['mgmt_addr'] for dev, attr in self.mgFacts['minigraph_devices'].items() if attr['hwsku'] == 'Arista-VM'
        ]

        self.hostMaxLen = len(self.rebootData['arista_vms']) - 1
        self.lagMemberCnt = len(self.mgFacts['minigraph_portchannels'].values()[0]['members'])
        self.vlanMaxCnt = len(self.mgFacts['minigraph_vlans'].values()[0]['members']) - 1

        self.rebootData['dut_hostname'] = self.mgFacts['minigraph_mgmt_interface']['addr']
        self.rebootData['dut_mac'] = self.duthost.facts['router_mac']
        self.rebootData['vlan_ip_range'] = self.mgFacts['minigraph_vlan_interfaces'][0]['subnet']
        self.rebootData['dut_vlan_ip'] = self.mgFacts['minigraph_vlan_interfaces'][0]['addr']

        self.rebootData['dut_username'] = self.creds['sonicadmin_user']
        self.rebootData['dut_password'] = self.creds['sonicadmin_password']

        # Change network of the dest IP addresses (used by VM servers) to be different from Vlan network
        prefixLen = self.mgFacts['minigraph_vlan_interfaces'][0]['prefixlen'] - 3
        testNetwork = ipaddress.ip_address(self.mgFacts['minigraph_vlan_interfaces'][0]['addr']) + (1 << (32 - prefixLen))
        self.rebootData['default_ip_range'] = str(
            ipaddress.ip_interface(unicode(str(testNetwork) + '/{0}'.format(prefixLen))).network
        )
        for intf in self.mgFacts['minigraph_lo_interfaces']:
            if ipaddress.ip_interface(intf['addr']).ip.version == 6:
                self.rebootData['lo_v6_prefix'] = str(ipaddress.ip_interface(intf['addr'] + '/64').network)
                break

    def __updateNextHopIps(self):
        '''
        Update next hop IPs
        '''
        if self.inbootList is not None:
            self.rebootData['nexthop_ips'] = [
                self.tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4'],
                self.tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6'],
            ]
        else:
            self.rebootData['nexthop_ips'] = None

    def __validateAndBuildSadList(self):
        '''
        Validate sad list (preboot/inboot lists) member data
        '''
        prebootList = [] if self.prebootList is None else self.prebootList
        inbootList = [] if self.inbootList is None else self.inbootList
        sadList = [item for item in itertools.chain(prebootList, inbootList)]

        for item in sadList:
            if ':' not in item:
                continue
            itemCnt = int(item.split(':')[-1])
            if 'bgp_down' in item:
                assert itemCnt <= self.hostMaxLen, (
                    'Bgp neigh down count is greater than or equal to number of VM hosts '
                    'Current val = {0} Max val = {1}'
                ).format(itemCnt, self.hostMaxLen)
            if 'lag_down' in item:
                assert itemCnt <= self.hostMaxLen, (
                    'Lag count is greater than or equal to number of VM hosts. '
                    'Current val = {0} Max val = {1}'
                ).format(itemCnt, self.hostMaxLen)
            if 'lag_member_down' in item:
                assert itemCnt <= self.lagMemberCnt, (
                    'Lag member count is greater than available number of lag members. '
                    'Current val = {0} Available cnt = {1}'
                ).format(itemCnt, self.lagMemberCnt)
            if 'vlan_port_down' in item:
                assert itemCnt <= self.vlanMaxCnt, (
                    'Vlan count is greater than or equal to number of Vlan interfaces. '
                    'Current val = {0} Max val = {1}'
                ).format(itemCnt, self.vlanMaxCnt)
            if 'routing' in item:
                assert itemCnt <= self.hostMaxCnt, (
                    'Number of prefixes is greater than allowed max. '
                    'Current val = {0} Max val = {1}'
                ).format(itemCnt, self.hostMaxCnt)

        # Adding None item if the sadList is empty in order to run the test case once when sad list is empty
        self.rebootData['sadList'] = sadList if len(sadList) > 0 else [None]

    def __transferTestDataFiles(self, data, ansibleHost):
        '''
        Convert data into json format and transfers json file to ansible host (ptfhost/duthost)
        @param data: map that includedata source and json file name
        @param ansibleHost: Ansible host that is receiving this data
        '''
        for item in data:
            data_source = item['source']
            filename = '/tmp/' + item['name'] + '.json'
            with open(filename, 'w') as file:
                file.write(json.dumps(data_source))

            logger.info('Transferring {0} to {1}'.format(filename, ansibleHost.hostname))
            ansibleHost.copy(src=filename, dest='/tmp/')
            self.rebootData[item['name'] + '_file'] = filename

    def __runScript(self, scripts, ansibleHost):
        '''
        Run script on an Ansibl host
        @param scripts: list of script names to be run on Ansible host
        @param ansibleHost: Ansible host to run the scripts on
        '''
        # this could be done using script API from ansible modules
        for script in scripts:
            logger.info('Running script {0} on {1}'.format(script, ansibleHost.hostname))
            ansibleHost.script('scripts/' + script)

    def __prepareTestbedSshKeys(self):
        '''
        Prepares testbed ssh keys by generating ssh key on ptf host and adding this key to known_hosts on duthost
        '''
        prepareTestbedSshKeys(self.duthost, self.ptfhost, self.rebootData['dut_username'])

    def __handleMellanoxDut(self):
        '''
        Handle Mellanox DUT reboot when upgrading from SONiC-OS-201803 to SONiC-OS-201811
        '''
        if self.newSonicImage is not None and \
           self.rebootType == 'fast-reboot' and \
           isMellanoxDevice(self.duthost):
            logger.info('Handle Mellanox platform')
            nextImage = self.duthost.shell('sonic_installer list | grep Next | cut -f2 -d " "')['stdout']
            if 'SONiC-OS-201803' in self.currentImage and 'SONiC-OS-201811' in nextImage:
                self.__runScript(['upgrade_mlnx_fw.sh'], self.duthost)

    def __updateAndRestartArpResponder(self, item=None):
        '''
        Update ARP responder configuration data based on the inboot/preboot operation (item)
        @param item: inboot/preboot operation
        '''
        arp_responder_args = '-e'
        if item is not None:
            arp_responder_args += ' -c /tmp/from_t1_{0}.json'.format(item)
        self.ptfhost.host.options['variable_manager'].extra_vars.update({'arp_responder_args': arp_responder_args})

        logger.info('Copying arp responder config file to {0}'.format(self.ptfhost.hostname))
        self.ptfhost.template(src='arp_responder.conf.j2', dest='/etc/supervisor/conf.d/arp_responder.conf')

        logger.info('Refreshing supervisor control and starting arp_responder')
        self.ptfhost.shell('supervisorctl reread && supervisorctl update')

    def __handleRebootImage(self):
        '''
        Download and install new image to DUT
        '''
        if self.newSonicImage is None:
            self.newImage = False
            return

        self.currentImage = self.duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']

        tempfile = self.duthost.shell('mktemp')['stdout']

        logger.info('Download SONiC image')
        self.duthost.shell('curl {0} --output {1}'.format(self.newSonicImage, tempfile))

        self.binaryVersion = self.duthost.shell('sonic_installer binary_version {}'.format(tempfile))['stdout']

        logger.info('Cleanup sonic images that is not current and/or next')
        if self.cleanupOldSonicImages:
            self.duthost.shell('sonic_installer cleanup -y')
        if self.binaryVersion == self.currentImage:
            logger.info("Skipping image installation: new SONiC image is installed and set to current")
            self.newImage = False
            return

        self.newImage = True
        logger.info('Installing new SONiC image')
        self.duthost.shell('sonic_installer install -y {0}'.format(tempfile))

        logger.info('Remove config_db.json so the new image will reload minigraph')
        self.duthost.shell('rm -f /host/old_config/config_db.json')
        logger.info('Remove downloaded tempfile')
        self.duthost.shell('rm -f {}'.format(tempfile))

    def __setupTestbed(self):
        '''
        Sets testbed up. It tranfers test data files, ARP responder, and runs script to update IPs and MAC addresses.
        '''
        testDataFiles = [
            {'source' : self.mgFacts['minigraph_portchannels'], 'name' : 'portchannel_interfaces'},
            {'source' : self.mgFacts['minigraph_vlans'],        'name' : 'vlan_interfaces'       },
            {'source' : self.mgFacts['minigraph_ptf_indices'],  'name' : 'ports'                 },
            {'source' : self.mgFacts['minigraph_devices'],      'name' : 'peer_dev_info'         },
            {'source' : self.mgFacts['minigraph_neighbors'],    'name' : 'neigh_port_info'       },
        ]
        self.__transferTestDataFiles(testDataFiles, self.ptfhost)

        self.__runScript(['remove_ip.sh'], self.ptfhost)

        self.__prepareTestbedSshKeys()

        logger.info('Copy ARP responder to the PTF container  {}'.format(self.ptfhost.hostname))
        self.ptfhost.copy(src='scripts/arp_responder.py', dest='/opt')

        # Replace fast-reboot script
        if self.replaceFastRebootScript:
            logger.info('Replace fast-reboot script on DUT  {}'.format(self.duthost.hostname))
            self.duthost.copy(src='scripts/fast-reboot', dest='/usr/bin/')

    def __clearArpAndFdbTables(self):
        '''
        Clears ARP and FDB entries
        '''
        logger.info('Clearing arp entries on DUT  {}'.format(self.duthost.hostname))
        self.duthost.shell('sonic-clear arp')

        logger.info('Clearing all fdb entries on DUT  {}'.format(self.duthost.hostname))
        self.duthost.shell('sonic-clear fdb all')

    def __fetchTestLogs(self, rebootOper=None):
        '''
        Fetch test logs from duthost and ptfhost after individual test run
        '''
        if rebootOper is None:
            rebootLog = '/tmp/{0}.log'.format(self.rebootType)
            capturePcap = '/tmp/capture.pcap'
            filterPcap = '/tmp/capture_filtered.pcap'
            syslogFile = '/tmp/syslog'
            sairedisRec = '/tmp/sairedis.rec'
            swssRec = '/tmp/swss.rec'
        else:
            rebootLog = '/tmp/{0}-{1}.log'.format(self.rebootType, rebootOper)
            capturePcap = '/tmp/capture_{0}.pcap'.format(rebootOper)
            filterPcap = '/tmp/capture_filtered_{0}.pcap'.format(rebootOper)
            syslogFile = '/tmp/syslog_{0}'.format(rebootOper)
            sairedisRec = '/tmp/sairedis.rec.{0}'.format(rebootOper)
            swssRec = '/tmp/swss.rec.{0}'.format(rebootOper)

        logger.info('Extract log files on dut host')
        dutLogFiles = [
            {'directory': '/var/log', 'file_prefix': 'syslog', 'start_string': 'Linux version', 'target_filename': syslogFile},
            {'directory': '/var/log/swss', 'file_prefix': 'sairedis.rec', 'start_string': 'recording on:', 'target_filename': sairedisRec},
            {'directory': '/var/log/swss', 'file_prefix': 'swss.rec', 'start_string': 'recording started', 'target_filename': swssRec},
        ]
        for logFile in dutLogFiles:
            self.duthost.extract_log(**logFile)

        logger.info('Fetching log files from ptf and dut hosts')
        logFiles = {
            self.ptfhost: [
                {'src': rebootLog, 'dest': '/tmp/', 'flat': True, 'fail_on_missing': False},
                {'src': capturePcap, 'dest': '/tmp/', 'flat': True, 'fail_on_missing': False},
                {'src': filterPcap, 'dest': '/tmp/', 'flat': True, 'fail_on_missing': False},
            ],
            self.duthost: [
                {'src': syslogFile, 'dest': '/tmp/', 'flat': True},
                {'src': sairedisRec, 'dest': '/tmp/', 'flat': True},
                {'src': swssRec, 'dest': '/tmp/', 'flat': True},
            ],
        }
        for host, logs in logFiles.items():
            for log in logs:
                host.fetch(**log)

    def imageInstall(self, prebootList=None, inbootList=None, prebootFiles=None):
        '''
        This method validates and prepares test bed for reboot test case.
        @param prebootList: list of operation to run before reboot process
        @param inbootList: list of operation to run during reboot prcoess
        @param prebootFiles: preboot files
        '''
        self.prebootList = prebootList
        self.inbootList = inbootList
        self.prebootFiles = prebootFiles

        # Validating contents of preboot and inboot list and building sadList
        self.__validateAndBuildSadList()

        # Update next hop IP based on Inboot list
        self.__updateNextHopIps()

        # Collect test data and set up testbed with required files/services
        self.__setupTestbed()

        # Download and install new sonic image
        self.__handleRebootImage()

        # Handle mellanox platform
        self.__handleMellanoxDut()

    def runRebootTest(self):
        # Run advanced-reboot.ReloadTest for item in preboot/inboot list
        count = 0
        for rebootOper in self.rebootData['sadList']:
            count += 1
            try:
                result = self.__runPtfRunner(rebootOper)
            finally:
                # always capture the test logs
                self.__fetchTestLogs(rebootOper)
                self.__clearArpAndFdbTables()
            if not result:
                return result
            if len(self.rebootData['sadList']) > 1 and count != len(self.rebootData['sadList']):
                time.sleep(TIME_BETWEEN_SUCCESSIVE_TEST_OPER)
        return result

    def runRebootTestcase(self, prebootList=None, inbootList=None, prebootFiles=None):
        '''
        This method validates and prepares test bed for reboot test case. It runs the reboot test case using provided
        test arguments
        @param prebootList: list of operation to run before reboot process
        @param inbootList: list of operation to run during reboot prcoess
        @param prebootFiles: preboot files
        '''
        self.imageInstall(prebootList, inbootList, prebootFiles)
        return self.runRebootTest()

    def __runPtfRunner(self, rebootOper=None):
        '''
        Run single PTF advanced-reboot.ReloadTest
        @param rebootOper:Reboot operation to conduct before/during reboot process
        '''
        logger.info("Running PTF runner on PTF host: {0}".format(self.ptfhost))

        # Non-routing neighbor/dut lag/bgp, vlan port up/down operation is performed before dut reboot process
        # lack of routing indicates it is preboot operation
        prebootOper = rebootOper if rebootOper is not None and 'routing' not in rebootOper else None
        # Routing add/remove is performed during dut reboot process
        # presence of routing in reboot operation indicates it is during reboot operation (inboot)
        inbootOper = rebootOper if rebootOper is not None and 'routing' in rebootOper else None

        self.__updateAndRestartArpResponder(rebootOper)

        logger.info('Run advanced-reboot ReloadTest on the PTF host')
        result = ptf_runner(
            self.ptfhost,
            "ptftests",
            "advanced-reboot.ReloadTest",
            qlen=PTFRUNNER_QLEN,
            platform_dir="ptftests",
            platform="remote",
            params={
                "dut_username" : self.rebootData['dut_username'],
                "dut_password" : self.rebootData['dut_password'],
                "dut_hostname" : self.rebootData['dut_hostname'],
                "reboot_limit_in_seconds" : self.rebootLimit,
                "reboot_type" : self.rebootType,
                "portchannel_ports_file" : self.rebootData['portchannel_interfaces_file'],
                "vlan_ports_file" : self.rebootData['vlan_interfaces_file'],
                "ports_file" : self.rebootData['ports_file'],
                "dut_mac" : self.rebootData['dut_mac'],
                "dut_vlan_ip" : self.rebootData['dut_vlan_ip'],
                "default_ip_range" : self.rebootData['default_ip_range'],
                "vlan_ip_range" : self.rebootData['vlan_ip_range'],
                "lo_v6_prefix" : self.rebootData['lo_v6_prefix'],
                "arista_vms" : self.rebootData['arista_vms'],
                "preboot_files" : self.prebootFiles,
                "preboot_oper" : prebootOper,
                "inboot_oper" : inbootOper,
                "nexthop_ips" : self.rebootData['nexthop_ips'],
                "allow_vlan_flooding" : self.allowVlanFlooding,
                "sniff_time_incr" : self.sniffTimeIncr,
                "setup_fdb_before_test" : True,
                "vnet" : self.vnet,
                "vnet_pkts" : self.vnetPkts,
                "bgp_v4_v6_time_diff": self.bgpV4V6TimeDiff
            },
            log_file=u'/tmp/advanced-reboot.ReloadTest.log',
            module_ignore_errors=self.moduleIgnoreErrors
        )
        return result

    def __restorePrevImage(self):
        '''
        Restore previous image and reboot DUT
        '''
        currentImage = self.duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
        if currentImage != self.currentImage:
            logger.info('Restore current image')
            self.duthost.shell('sonic_installer set_default {0}'.format(self.currentImage))

            rebootDut(
                self.duthost,
                self.localhost,
                reboot_type=self.rebootType.replace('-reboot', ''),
                wait = self.readyTimeout
            )

    def tearDown(self):
        '''
        Tears down test case. It also verifies that config_db.json exists.
        '''
        logger.info('Running test tear down')
        if 'warm-reboot' in self.rebootType and self.newSonicImage is not None:
            logger.info('Save configuration after warm rebooting into new image')
            self.duthost.shell('config save -y')

        result = self.duthost.shell('stat /etc/sonic/config_db.json')
        assert len(result['stderr_lines']) == 0, '/etc/sonic/config_db.json is missing'

        self.__runScript(['remove_ip.sh'], self.ptfhost)

        if self.postRebootCheckScript:
            logger.info('Run the post reboot check script')
            self.__runScript([self.postRebootCheckScript], self.duthost)

        if not self.stayInTargetImage:
            self.__restorePrevImage()

@pytest.fixture
def get_advanced_reboot(request, duthosts, rand_one_dut_hostname, ptfhost, localhost, tbinfo, creds):
    '''
    Pytest test fixture that provides access to AdvancedReboot test fixture
        @param request: pytest request object
        @param duthost: AnsibleHost instance of DUT
        @param ptfhost: PTFHost for interacting with PTF through ansible
        @param localhost: Localhost for interacting with localhost through ansible
        @param tbinfo: fixture provides information about testbed
    '''
    duthost = duthosts[rand_one_dut_hostname]
    instances = []

    def get_advanced_reboot(**kwargs):
        '''
        API that returns instances of AdvancedReboot class
        '''
        assert len(instances) == 0, "Only one instance of reboot data is allowed"
        advancedReboot = AdvancedReboot(request, duthost, ptfhost, localhost, tbinfo, creds, **kwargs)
        instances.append(advancedReboot)
        return advancedReboot

    yield get_advanced_reboot

    # Perform clean up
    for s in instances:
        s.tearDown()
