import pytest
import time
import re
import logging

from tests.common import reboot
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert

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
    config_reload(duthost)


@pytest.fixture(scope="module", autouse=True)
def setup_mvrf(duthost, localhost):
    """
    Setup Management vrf configs before the start of testsuite
    """
    # Backup the original config_db without mgmt vrf config
    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

    try:
        logger.info("Configure mgmt vrf")
        duthost.command("sudo config vrf add mgmt")
        verify_show_command(duthost, mvrf=True)
    except Exception as e:
        logger.error("Exception raised in setup, exception: {}".format(repr(e)))
        restore_config_db(duthost)
        pytest.fail("Configure mgmt vrf failed, no test case will be executed. Code after 'yield' will not be executed either.")

    yield

    try:
        logger.info("Unconfigure  mgmt vrf")
        duthost.copy(src="mvrf/config_vrf_del.sh", dest="/tmp/config_vrf_del.sh", mode=0755)
        duthost.shell("nohup /tmp/config_vrf_del.sh < /dev/null > /dev/null 2>&1 &")
        localhost.wait_for(host=duthost.mgmt_ip,
                        port=SONIC_SSH_PORT,
                        state="stopped",
                        search_regex=SONIC_SSH_REGEX,
                        timeout=90)

        localhost.wait_for(host=duthost.mgmt_ip,
                        port=SONIC_SSH_PORT,
                        state="started",
                        search_regex=SONIC_SSH_REGEX,
                        timeout=90)

        verify_show_command(duthost, mvrf=False)

    finally:    # Always restore and reload the original config_db.
        restore_config_db(duthost)


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
        prefix = "sudo cgexec -g l3mdev:mgmt "
    result = duthost.command(prefix + command, module_ignore_errors=ignore_errors)
    return result


class TestMvrfInbound():
    def test_ping(self, duthost):
        duthost.ping()

    def test_snmp_fact(self, localhost, duthost, creds):
        localhost.snmp_facts(host=duthost.mgmt_ip, version="v2c", community=creds['snmp_rocommunity'])


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

    def test_curl(self, duthost, setup_http_server):
        logger.info("Test Curl")

        url, MAGIC_STRING = setup_http_server

        curl_cmd = "curl {}".format(url)
        result = execute_dut_command(duthost, curl_cmd, mvrf=True)
        pytest_assert(result["stdout"].strip() == MAGIC_STRING)


class TestServices():
    def check_ntp_status(self, duthost):
        ntpstat_cmd = "ntpstat"
        ntp_stat = execute_dut_command(duthost, ntpstat_cmd, mvrf=True, ignore_errors=True)
        return ntp_stat["rc"] == 0

    def test_ntp(self, duthost):
        force_ntp = "ntpd -gq"
        duthost.service(name="ntp", state="stopped")
        logger.info("Ntp restart in mgmt vrf")
        execute_dut_command(duthost, force_ntp)
        duthost.service(name="ntp", state="restarted")
        pytest_assert(wait_until(100, 10, self.check_ntp_status, duthost), "Ntp not started")

    def test_service_acl(self, duthost, localhost):
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
        outbound_test.test_ping(duthost, ptfhost)
        inbound_test.test_ping(duthost)
        inbound_test.test_snmp_fact(localhost, duthost, creds)

    @pytest.mark.disable_loganalyzer
    def test_warmboot(self, duthost, localhost, ptfhost, creds):
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost, reboot_type="warm")
        pytest_assert(wait_until(120, 20, duthost.critical_services_fully_started), "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    @pytest.mark.disable_loganalyzer
    def test_reboot(self, duthost, localhost, ptfhost, creds):
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost)
        pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started), "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    @pytest.mark.disable_loganalyzer
    def test_fastboot(self, duthost, localhost, ptfhost, creds):
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost, reboot_type="fast")
        pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started), "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)
