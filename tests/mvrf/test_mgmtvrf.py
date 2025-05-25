import pytest
import time
import re
import logging

from tests.common import reboot
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.ntp_helper import NtpDaemon, ntp_daemon_in_use, run_ntp  # noqa: F401
from tests.common.helpers.snmp_helpers import get_snmp_facts
from tests.common.devices.ptf import PTFHost

pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

SONIC_SSH_REGEX = "OpenSSH_[\\w\\.]+ Debian"
SONIC_SSH_PORT = 22


@pytest.fixture(autouse=True)
def _ignore_mux_errlogs(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(
            [
                ".*ERR pmon#CCmisApi.*y_cable_port.*GET http.*"
            ])
    return


@pytest.fixture(scope="module", autouse=True)
def setup_mvrf(request, duthosts, rand_one_dut_hostname, localhost):
    """
    Setup Management vrf configs before the start of testsuite
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Backup the original config_db without mgmt vrf config
    duthost.command("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

    # Restore the original config_db without mgmt vrf config
    # With mvrf on, config reload does not do some of the necessary operations
    # after loading config into running config, so a reboot is a must
    def restore_config_db():
        duthost.command("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
        reboot(duthost, localhost, check_intf_up_ports=True, wait_for_bgp=True)
    # We will undo the changes with cli, and we expect no error
    # but a config reload will be performed at the end, to make sure no leftover
    request.addfinalizer(restore_config_db)

    logger.info("Configure mgmt vrf")
    duthost.command("sudo config vrf add mgmt", module_async=True)
    time.sleep(5)
    verify_show_command(duthost, mvrf=True)

    duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config

    yield

    logger.info("Unconfigure mgmt vrf")
    duthost.shell("sudo config vrf del mgmt", module_async=True)
    time.sleep(5)
    localhost.wait_for(host=duthost.mgmt_ip,
                       port=SONIC_SSH_PORT,
                       state="started",
                       search_regex=SONIC_SSH_REGEX,
                       timeout=90)
    verify_show_command(duthost, mvrf=False)

    duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config


@pytest.fixture(scope="module")
def ntp_servers(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    ntp_servers = config_facts.get("NTP_SERVER", {})
    return ntp_servers


@pytest.fixture()
def change_critical_services(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    backup = duthost.critical_services
    services = duthost.DEFAULT_ASIC_SERVICES
    duthost.reset_critical_services_tracking_list(services + ["pmon"])
    yield
    duthost.reset_critical_services_tracking_list(backup)


def check_ntp_status(host, ntp_daemon_in_use):  # noqa: F811
    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        ntpstat_cmd = "chronyc -c tracking"
    else:
        ntpstat_cmd = "ntpstat"
    if isinstance(host, PTFHost):
        res = host.command(ntpstat_cmd, module_ignore_errors=True)
    else:
        res = execute_dut_command(host, ntpstat_cmd, mvrf=True, ignore_errors=True)
    return res["rc"] == 0


def verify_show_command(duthost, mvrf=True):
    show_mgmt_vrf = duthost.shell("show mgmt-vrf")["stdout"]
    mvrf_interfaces = {}
    if mvrf:
        mvrf_interfaces["mgmt"] = r"\d+:\s+mgmt:\s+<NOARP,MASTER,UP,LOWER_UP> mtu\s+\d+\s+qdisc\s+noqueue\s+state\s+UP"
        mvrf_interfaces["vrf_table"] = "vrf table 5000"
        mvrf_interfaces["eth0"] = r"\d+:\s+eth0+:\s+<BROADCAST,MULTICAST,UP,LOWER_UP>.*master mgmt\s+state\s+UP "
        mvrf_interfaces["lo"] = r"\d+:\s+lo-m:\s+<BROADCAST,NOARP,UP,LOWER_UP>.*master mgmt"
        if "ManagementVRF : Enabled" not in show_mgmt_vrf:
            raise Exception("'ManagementVRF : Enabled' not in output of 'show mgmt vrf'")
        for _, pattern in list(mvrf_interfaces.items()):
            if not re.search(pattern, show_mgmt_vrf):
                raise Exception("Unexpected output for MgmtVRF=enabled")
    else:
        if "ManagementVRF : Disabled" not in show_mgmt_vrf:
            raise Exception("'ManagementVRF : Disabled' not in output of 'show mgmt vrf'")


def execute_dut_command(duthost, command, mvrf=True, ignore_errors=False):
    result = {}
    prefix = ""
    if mvrf:
        prefix = "sudo ip vrf exec mgmt "
    result = duthost.command(prefix + command, module_ignore_errors=ignore_errors)
    return result


@pytest.fixture
def setup_ntp_server(duthosts, rand_one_dut_hostname, ptfhost, ntp_daemon_in_use, ntp_servers):  # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]

    # Check if ntp was not in sync with ntp server before enabling mvrf, if yes then setup ntp server on ptf
    # It should normally be set to lab ntp server
    ntp_in_sync = check_ntp_status(duthost, ntp_daemon_in_use)
    logger.info("ntp is in sync: {}".format(ntp_in_sync))

    # If lab ntp server is not working, use ptf to setup ntp server
    if ntp_in_sync is False:
        """setup ntp client and server"""
        ptfhost.lineinfile(path="/etc/ntp.conf", line="server 127.127.1.0 prefer")
        # restart ntp server
        ntp_en_res = ptfhost.service(name="ntp", state="restarted")
        pytest_assert(wait_until(120, 5, 0, check_ntp_status, ptfhost, NtpDaemon.NTP),
                      "NTP server was not started in PTF container {}; NTP service start result {}"
                      .format(ptfhost.hostname, ntp_en_res))
        # setup ntp on dut to sync with ntp server
        for ntp_server in ntp_servers:
            duthost.command("config ntp del {}".format(ntp_server))
        duthost.command("config ntp add {}".format(ptfhost.mgmt_ip))

    yield

    if ntp_in_sync is False:
        # stop ntp server
        ptfhost.service(name="ntp", state="stopped")
        # reset ntp client configuration
        duthost.command("config ntp del {}".format(ptfhost.mgmt_ip), module_ignore_errors=True)
        for ntp_server in ntp_servers:
            duthost.command("config ntp add {}".format(ntp_server), module_ignore_errors=True)


@pytest.fixture
def setup_ntp_mgmt_vrf(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ntp_vrf_cmd = "sonic-cfggen -d -v 'NTP[\"global\"][\"vrf\"]'"
    ntp_vrf = duthost.command(ntp_vrf_cmd, module_ignore_errors=True)["stdout"]

    if ntp_vrf == "default":
        duthost.command("redis-cli -n 4 hset \"NTP|global\" \"vrf\" \"mgmt\"")
        pytest_assert(duthost.command("sonic-cfggen -d -v 'NTP[\"global\"][\"vrf\"]'")["stdout"] == "mgmt",
                      "Failed to set ntp global vrf to mgmt")

    yield

    if ntp_vrf == "default":
        duthost.command("redis-cli -n 4 hset \"NTP|global\" \"vrf\" \"default\"")
        pytest_assert(duthost.command("sonic-cfggen -d -v 'NTP[\"global\"][\"vrf\"]'")["stdout"] == "default",
                      "Failed to reset ntp global vrf to default")


class TestMvrfInbound():
    def test_ping(self, duthost):
        duthost.ping()

    def test_snmp_fact(self, localhost, duthost, creds):
        get_snmp_facts(duthost, localhost, host=duthost.mgmt_ip, version="v2c", community=creds["snmp_rocommunity"])


class TestMvrfOutbound():

    def get_free_port(self, ptfhost):
        res = ptfhost.shell('netstat -lntu | grep -Eo "^tcp +[0-9]+ +[0-9]+ +[^:]+:([0-9]+)" | cut -d: -f2')
        used_ports = set(res["stdout_lines"])
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
        localhost.wait_for(host=ptfhost.mgmt_ip, port=int(free_port), state="started", timeout=60)

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
    def test_ntp(self, duthosts, rand_one_dut_hostname, ptfhost, setup_ntp_server,
                 setup_ntp_mgmt_vrf, ntp_daemon_in_use):  # noqa: F811
        duthost = duthosts[rand_one_dut_hostname]
        run_ntp(duthost, ntp_daemon_in_use, mvrf=True)

    def test_service_acl(self, duthosts, rand_one_dut_hostname, localhost):
        duthost = duthosts[rand_one_dut_hostname]
        # SSH definitions
        logger.info("test Service acl")

        duthost.copy(src="mvrf/config_service_acls.sh", dest="/tmp/config_service_acls.sh", mode=0o755)
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


@pytest.mark.disable_loganalyzer
class TestReboot():
    def basic_check_after_reboot(self, duthost, localhost, ptfhost, creds):
        verify_show_command(duthost)
        inbound_test = TestMvrfInbound()
        outbound_test = TestMvrfOutbound()
        outbound_test.test_ping(duthost=duthost, ptfhost=ptfhost)
        inbound_test.test_ping(duthost=duthost)
        inbound_test.test_snmp_fact(localhost=localhost, duthost=duthost, creds=creds)

    def test_warmboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds, change_critical_services):
        duthost = duthosts[rand_one_dut_hostname]
        reboot(duthost, localhost, reboot_type="warm")
        pytest_assert(wait_until(120, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")

        # Change default critical services to check services that starts with bootOn timer
        # In some images, we have gnmi container only
        # In some images, we have telemetry container only
        # And in some images, we have both gnmi and telemetry container
        critical_services = ["snmp"]
        tentative_critical_services = ["mgmt-framework", "gnmi", "telemetry"]
        for service in tentative_critical_services:
            cmd = "docker ps | grep -w {}".format(service)
            if duthost.shell(cmd, module_ignore_errors=True)["rc"] == 0:
                critical_services.append(service)
        duthost.reset_critical_services_tracking_list(critical_services)

        pytest_assert(wait_until(180, 20, 0, duthost.critical_services_fully_started),
                      "Not all services which start with bootOn timer are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    def test_reboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds):
        duthost = duthosts[rand_one_dut_hostname]
        reboot(duthost, localhost)
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    def test_fastboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds):
        duthost = duthosts[rand_one_dut_hostname]
        reboot(duthost, localhost, reboot_type="fast")
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)
