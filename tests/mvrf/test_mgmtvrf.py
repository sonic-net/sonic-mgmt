import pytest
import time
import re
import logging

from tests.common import reboot
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.snmp_helpers import get_snmp_facts
from pkg_resources import parse_version
from tests.common.devices.ptf import PTFHost

pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

SONIC_SSH_REGEX = "OpenSSH_[\\w\\.]+ Debian"
SONIC_SSH_PORT = 22


def restore_config_db(duthost):
    # Restore the original config_db to override the config_db with mgmt vrf config
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")

    # Reload to restore configuration
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

@pytest.fixture(scope="module")
def check_ntp_sync(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    ntp_stat = duthost.command('ntpstat', module_ignore_errors=True)['rc']
    return ntp_stat

@pytest.fixture(scope="module", autouse=True)
def setup_mvrf(duthosts, rand_one_dut_hostname, localhost, check_ntp_sync):
    """
    Setup Management vrf configs before the start of testsuite
    """
    duthost = duthosts[rand_one_dut_hostname]
    # Backup the original config_db without mgmt vrf config
    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

    try:
        logger.info("Configure mgmt vrf")
        duthost.command("sudo config vrf add mgmt", module_async=True)
        time.sleep(5)
        verify_show_command(duthost, mvrf=True)
    except Exception as e:
        logger.error("Exception raised in setup, exception: {}".format(repr(e)))
        restore_config_db(duthost)
        pytest.fail("Configure mgmt vrf failed, no test case will be executed. Code after 'yield' will not be executed either.")

    yield

    try:
        logger.info("Unconfigure  mgmt vrf")
        duthost.shell("sudo config vrf del mgmt", module_async=True)
        time.sleep(5)

        localhost.wait_for(host=duthost.mgmt_ip,
                        port=SONIC_SSH_PORT,
                        state="started",
                        search_regex=SONIC_SSH_REGEX,
                        timeout=90)

        verify_show_command(duthost, mvrf=False)

    finally:    # Always restore and reload the original config_db.
        restore_config_db(duthost)

@pytest.fixture(scope='module')
def ntp_servers(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    ntp_servers = config_facts.get('NTP_SERVER', {})
    return ntp_servers

@pytest.fixture()
def ntp_teardown(ptfhost, duthosts, rand_one_dut_hostname, ntp_servers):
    yield

    duthost = duthosts[rand_one_dut_hostname]
    # stop ntp server
    ptfhost.service(name="ntp", state="stopped")
    # reset ntp client configuration
    duthost.command("config ntp del %s" % ptfhost.mgmt_ip, module_ignore_errors=True)
    for ntp_server in ntp_servers:
        duthost.command("config ntp add %s" % ntp_server, module_ignore_errors=True)

@pytest.fixture()
def change_critical_services(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    backup = duthost.critical_services
    services = duthost.DEFAULT_ASIC_SERVICES
    duthost.reset_critical_services_tracking_list(services + ['pmon'])
    yield
    duthost.reset_critical_services_tracking_list(backup)

def check_ntp_status(host):
    ntpstat_cmd = 'ntpstat'
    if isinstance(host, PTFHost):
        res = host.command(ntpstat_cmd, module_ignore_errors=True)
    else:
        res = execute_dut_command(host, ntpstat_cmd, mvrf=True, ignore_errors=True)
    return res['rc'] == 0

def verify_show_command(duthost, mvrf=True):
    show_mgmt_vrf = duthost.shell("show mgmt-vrf")["stdout"]
    mvrf_interfaces = {}
    if mvrf:
        mvrf_interfaces["mgmt"] = "\d+:\s+mgmt:\s+<NOARP,MASTER,UP,LOWER_UP> mtu\s+\d+\s+qdisc\s+noqueue\s+state\s+UP"
        mvrf_interfaces["vrf_table"] = "vrf table 5000"
        mvrf_interfaces["eth0"] = "\d+:\s+eth0+:\s+<BROADCAST,MULTICAST,UP,LOWER_UP>.*master mgmt\s+state\s+UP "
        mvrf_interfaces["lo"] = "\d+:\s+lo-m:\s+<BROADCAST,NOARP,UP,LOWER_UP>.*master mgmt"
        if not "ManagementVRF : Enabled" in show_mgmt_vrf:
            raise Exception("'ManagementVRF : Enabled' not in output of 'show mgmt vrf'")
        for _, pattern in mvrf_interfaces.items():
            if not re.search(pattern, show_mgmt_vrf):
                raise Exception("Unexpected output for MgmtVRF=enabled")
    else:
        if not "ManagementVRF : Disabled" in show_mgmt_vrf:
            raise Exception("'ManagementVRF : Disabled' not in output of 'show mgmt vrf'")


def execute_dut_command(duthost, command, mvrf=True, ignore_errors=False):
    result = {}
    prefix = ""
    if mvrf:
        dut_kernel = duthost.shell("cat /proc/version | awk '{ print $3 }' | cut -d '-' -f 1")["stdout"]
        if parse_version(dut_kernel) > parse_version("4.9.0"):
            prefix = "sudo ip vrf exec mgmt "
        else:
            prefix = "sudo cgexec -g l3mdev:mgmt "
    result = duthost.command(prefix + command, module_ignore_errors=ignore_errors)
    return result


def setup_ntp(ptfhost, duthost, ntp_servers):
    """setup ntp client and server"""
    ptfhost.lineinfile(path="/etc/ntp.conf", line="server 127.127.1.0 prefer")
    # restart ntp server
    ntp_en_res = ptfhost.service(name="ntp", state="restarted")
    pytest_assert(wait_until(120, 5, 0, check_ntp_status, ptfhost), \
        "NTP server was not started in PTF container {}; NTP service start result {}".format(ptfhost.hostname, ntp_en_res))
    # setup ntp on dut to sync with ntp server
    for ntp_server in ntp_servers:
        duthost.command("config ntp del %s" % ntp_server)
    duthost.command("config ntp add %s" % ptfhost.mgmt_ip)

class TestMvrfInbound():
    def test_ping(self, duthost):
        duthost.ping()

    def test_snmp_fact(self, localhost, duthost, creds):
        get_snmp_facts(localhost, host=duthost.mgmt_ip, version="v2c", community=creds['snmp_rocommunity'])


class TestMvrfOutbound():

    def get_free_port(self, ptfhost):
        res = ptfhost.shell('netstat -lntu | grep -Eo "^tcp +[0-9]+ +[0-9]+ +[^:]+:([0-9]+)" | cut -d: -f2')
        used_ports = set(res['stdout_lines'])
        for p in range(8000, 9000):
            if str(p) not in used_ports:
                return p

    @pytest.fixture
    def setup_http_server(self, localhost, ptfhost):
        # Run a script on PTF to start a temp http server
        server_script_dest_path = "/tmp/temp_http_server.py"
        ptfhost.copy(src="mvrf/temp_http_server.py", dest=server_script_dest_path)
        logger.info("Starting http server on PTF")
        free_port = self.get_free_port(ptfhost)
        ptfhost.command("python {} {}".format(server_script_dest_path, free_port), module_async=True)
        localhost.wait_for(host=ptfhost.mgmt_ip, port=int(free_port), state="started", timeout=30)

        url = "http://{}:{}".format(ptfhost.mgmt_ip, free_port)
        from temp_http_server import MAGIC_STRING

        yield url, MAGIC_STRING

        ptfhost.file(path=server_script_dest_path, state="absent")

    def test_ping(self, duthost, ptfhost):
        logger.info("Test OutBound Ping")
        command = "ping  -c 3 " + ptfhost.mgmt_ip
        execute_dut_command(duthost, command, mvrf=True)

    def test_curl(self, duthosts, rand_one_dut_hostname, setup_http_server):
        duthost = duthosts[rand_one_dut_hostname]
        logger.info("Test Curl")

        url, MAGIC_STRING = setup_http_server

        curl_cmd = "curl {}".format(url)
        result = execute_dut_command(duthost, curl_cmd, mvrf=True)
        pytest_assert(result["stdout"].strip() == MAGIC_STRING)


class TestServices():
    @pytest.mark.usefixtures("ntp_teardown")
    def test_ntp(self, duthosts, rand_one_dut_hostname, ptfhost, check_ntp_sync, ntp_servers):
        duthost = duthosts[rand_one_dut_hostname]
        # Check if ntp was not in sync with ntp server before enabling mvrf, if yes then setup ntp server on ptf
        if check_ntp_sync:
            setup_ntp(ptfhost, duthost, ntp_servers)
        ntp_uid = ":".join(duthost.command("getent passwd ntp")['stdout'].split(':')[2:4])
        force_ntp = "timeout 20 ntpd -gq -u {}".format(ntp_uid)
        duthost.service(name="ntp", state="stopped")
        logger.info("Ntp restart in mgmt vrf")
        execute_dut_command(duthost, force_ntp)
        duthost.service(name="ntp", state="restarted")
        pytest_assert(wait_until(400, 10, 0, check_ntp_status, duthost), "Ntp not started")

    def test_service_acl(self, duthosts, rand_one_dut_hostname, localhost):
        duthost = duthosts[rand_one_dut_hostname]
        # SSH definitions
        logger.info("test Service acl")

        duthost.copy(src="mvrf/config_service_acls.sh", dest="/tmp/config_service_acls.sh", mode=0755)
        duthost.shell("nohup /tmp/config_service_acls.sh < /dev/null > /dev/null 2>&1 &")
        time.sleep(5)
        logger.info("waiting for ssh to drop")
        localhost.wait_for(host=duthost.mgmt_ip,
                           port=SONIC_SSH_PORT,
                           state="stopped",
                           search_regex=SONIC_SSH_REGEX,
                           timeout=90)
        logger.info("ssh stopped for few seconds, wait for the ssh to come up")
        localhost.wait_for(host=duthost.mgmt_ip,
                           port=SONIC_SSH_PORT,
                           state="started",
                           search_regex=SONIC_SSH_REGEX,
                           timeout=90)
        time.sleep(20)
        duthost.file(path="/tmp/config_service_acls.sh", state="absent")


class TestReboot():
    def basic_check_after_reboot(self, duthost, localhost, ptfhost, creds):
        verify_show_command(duthost)
        inbound_test = TestMvrfInbound()
        outbound_test = TestMvrfOutbound()
        outbound_test.test_ping(duthost=duthost, ptfhost=ptfhost)
        inbound_test.test_ping(duthost=duthost)
        inbound_test.test_snmp_fact(localhost=localhost, duthost=duthost, creds=creds)

    @pytest.mark.disable_loganalyzer
    def test_warmboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds, change_critical_services):
        duthost = duthosts[rand_one_dut_hostname]
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost, reboot_type="warm")
        pytest_assert(wait_until(120, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started")
        # Change default critical services to check services that starts with bootOn timer
        duthost.reset_critical_services_tracking_list(['snmp', 'telemetry', 'mgmt-framework'])
        pytest_assert(wait_until(180, 20, 0, duthost.critical_services_fully_started),
                      "Not all services which start with bootOn timer are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    @pytest.mark.disable_loganalyzer
    def test_reboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds):
        duthost = duthosts[rand_one_dut_hostname]
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost)
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    @pytest.mark.disable_loganalyzer
    def test_fastboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds):
        duthost = duthosts[rand_one_dut_hostname]
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost, reboot_type="fast")
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)
