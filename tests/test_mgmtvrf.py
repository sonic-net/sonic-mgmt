import pytest
import sys
import time
from common import reboot
from common.utilities import wait_until
import re
from ansible_host import AnsibleModuleException
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module',autouse=True)
def setup_mvrf(duthost, testbed_devices, testbed, localhost):
    '''
    Setup Management vrf configs before the start of testsuite
    '''
    logging.info(' Configure mgmt vrf')
    global var
    global mvrf 
    mvrf = True  
    var = {}
    var['dut_ip'] = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']
    var['ptf_ip'] = testbed['ptf_ip']
    var['filename'] = 'README.md'
    duthost.command('sudo config vrf add  mgmt')
    logger.info('waiting for ssh to startup')
    SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'

    res = localhost.wait_for(host=var['dut_ip'],
                             port=22,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             timeout=90)
    time.sleep(5)
    verify_show_command(duthost)
    yield 
    mvrf = False 
    logging.info(' Unconfigure  mgmt vrf')
    duthost.copy(src="mvrf/config_vrf_del.sh",dest="/tmp/config_vrf_del.sh",mode=0755)
    duthost.shell("nohup /tmp/config_vrf_del.sh < /dev/null > /dev/null 2>&1 &")

    res = localhost.wait_for(host=var['dut_ip'],
                             port=22,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             timeout=90)
    time.sleep(10)

    duthost.command('sudo config save -y')
    verify_show_command(duthost, mvrf=False)


def verify_show_command(duthost, mvrf=True):

    show_mgmt_vrf=duthost.shell('show mgmt-vrf')['stdout']
    mvrf_interfaces = {}
    logging.debug("show mgmt vrf \n {}".format(show_mgmt_vrf))
    if mvrf: 
        mvrf_interfaces['mgmt'] = "\d+:\s+mgmt:\s+<NOARP,MASTER,UP,LOWER_UP> mtu\s+\d+\s+qdisc\s+noqueue\s+state\s+UP"
        mvrf_interfaces['vrf_table'] = "vrf table 5000"
        mvrf_interfaces['eth0'] = "\d+:\s+eth0+:\s+<BROADCAST,MULTICAST,UP,LOWER_UP>.*master mgmt\s+state\s+UP "
        mvrf_interfaces['lo']   = "\d+:\s+lo-m:\s+<BROADCAST,NOARP,UP,LOWER_UP>.*master mgmt"    
        assert "ManagementVRF : Enabled" in show_mgmt_vrf
        for intf , pattern in mvrf_interfaces.items():
            assert re.search(pattern,show_mgmt_vrf) is not None
    else: 
         assert "ManagementVRF : Disabled" in show_mgmt_vrf


def execute_dut_command(duthost, command, mvrf = True, ignore_errors=False):
    result = {} 
    prefix = ""
    if mvrf: 
         prefix = "sudo  cgexec -g l3mdev:mgmt "
    result=duthost.command(prefix+command, module_ignore_errors=ignore_errors)
    return result
    
class TestMvrfInbound():

    def test_ping(self,duthost, localhost):
       res = duthost.ping()

    def test_snmp_fact(self,testbed_devices):
       localhost = testbed_devices['localhost']
       duthost = testbed_devices['dut']
       snmp_res = localhost.snmp_facts(host=var['dut_ip'],version='v2c',community='public' )  
       
class TestMvrfOutbound(): 

    @pytest.fixture  
    def apt_install_wget(self, duthost):
        logging.info("apt-get update , apt-get install wget")
        apt_update_cmd = ' apt-get update -y'
        apt_install_wget = ' apt-get install wget -y'
        apt_remove = ' apt-get remove wget -y'
        execute_dut_command(duthost, apt_update_cmd, mvrf=True)
        execute_dut_command(duthost, apt_install_wget, mvrf=True)
        yield 
        logging.info(" remove wget")
        duthost.file(path=var['filename'], state='absent')
        execute_dut_command(duthost, apt_remove, mvrf = True)

    def test_ping(self, testbed, duthost):
        logging.info("Test OutBound Ping")
        command = "ping  -c 3 " + var['ptf_ip'] 
        result = execute_dut_command(duthost, command, mvrf=True)
            
    def test_wget(self, duthost, apt_install_wget):
        logging.info("Test Wget")
        wget_command=" wget  https://raw.githubusercontent.com/Azure/SONiC/master/README.md"
        result = execute_dut_command(duthost, wget_command, mvrf=True)
        file_exists=duthost.stat(path=var['filename'])
        assert file_exists['stat']['exists'] == True

    def test_curl(self, duthost):
        logging.info("Test Curl")
        curl_cmd = 'curl https://raw.githubusercontent.com/Azure/SONiC/master/README.md -o %s -f'%var['filename']
        result = execute_dut_command(duthost,curl_cmd,mvrf=True)
        file_exists = duthost.stat(path=var['filename'])
        assert file_exists['stat']['exists']==True
        duthost.file(path=var['filename'], state='absent')



class TestServices():

    def check_ntp_status(self, duthost): 
       ntpstat_cmd = "ntpstat"
       ntp_stat = execute_dut_command(duthost,ntpstat_cmd,mvrf=True,ignore_errors=True)
       if ntp_stat['rc'] != 0 :
          return False 
       return True 

    def test_ntp(self, duthost):
        force_ntp=" ntpd -gq"
        duthost.service(name='ntp' , state='stopped') 
        logging.info("Ntp restart in mgmt vrf")
        execute_dut_command(duthost, force_ntp)
        duthost.service(name='ntp' , state='restarted')
        assert wait_until(100, 10, self.check_ntp_status , duthost), "Ntp not started"

    def test_service_acl(self, duthost, localhost):
        # SSH definitions
        logging.info("test Service acl")
        SONIC_SSH_PORT  = 22
        SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'
        dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']
        duthost.copy(src="mvrf/config_service_acls.sh",dest="/tmp/config_service_acls.sh",mode=0755) 
        duthost.shell("nohup /tmp/config_service_acls.sh < /dev/null > /dev/null 2>&1 &")       
        time.sleep(5)
        logger.info('waiting for ssh to drop')
        res = localhost.wait_for(host=dut_ip,
                         port=SONIC_SSH_PORT,
                         state='stopped',
                         search_regex=SONIC_SSH_REGEX,
                         timeout=90)
        logger.info("ssh stopped for few seconds , wait for the ssh to come up")
        res = localhost.wait_for(host=dut_ip,
                         port=SONIC_SSH_PORT,
                         state='started',
                         search_regex=SONIC_SSH_REGEX,
                         timeout=90)
        time.sleep(20) 
        duthost.file(path="/tmp/config_service_acls.sh",state='absent')


class TestReboot():

    def basic_check_after_reboot(self, duthost, localhost, testbed_devices, testbed):
         verify_show_command(duthost)
         inbound_test = TestMvrfInbound()
         outbound_test = TestMvrfOutbound()
         outbound_test.test_ping(testbed,duthost)
         inbound_test.test_ping(duthost,localhost)
         inbound_test.test_snmp_fact(testbed_devices)


    def test_warmboot(self, localhost, testbed_devices, testbed):

        duthost = testbed_devices["dut"]
        duthost.command('sudo config save -y')
        reboot(duthost, localhost, reboot_type='warm')
        assert wait_until(120, 20, duthost.critical_services_fully_started), "Not all critical services are fully started"
        self.basic_check_after_reboot(duthost, localhost, testbed_devices, testbed)


    def test_reboot(self, localhost, testbed_devices, testbed):
        duthost = testbed_devices["dut"]
        duthost.command('sudo config save -y')
        reboot(duthost, localhost)
        assert wait_until(300, 20, duthost.critical_services_fully_started), "Not all critical services are fully started"
        self.basic_check_after_reboot(duthost, localhost, testbed_devices, testbed)

    def test_fastboot(self, localhost, testbed_devices, testbed):
 
        duthost = testbed_devices["dut"]
        duthost.command('sudo config save -y')
        reboot(duthost, localhost,reboot_type='fast')
        assert wait_until(300, 20, duthost.critical_services_fully_started), "Not all critical services are fully started"
        self.basic_check_after_reboot(duthost, localhost, testbed_devices, testbed)

