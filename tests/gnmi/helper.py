import logging
import time
import pytest

from tests.common.utilities.hostname_check import check_hostname
from tests.common.helpers.dut_utils import check_container_state
from tests.common.utilities.wait_until import wait_until
from gnmi_env import GNMIEnvironment
from tests.common.helpers.ntp_helper import GetNtpDaemonInUse as get_ntp_daemon_in_use, NtpDaemon

logger = logging.getLogger(__name__)

GNMI_SERVER_START_WAIT_TIME = 60


def gnmi_container(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    return env.gnmi_container


def apply_cert_config(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    # Get subtype
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    metadata = cfg_facts["DEVICE_METADATA"]["localhost"]
    subtype = metadata.get('subtype', None)
    # Stop all running programs and track which ones we stopped
    stopped_programs = []
    dut_command = "docker exec %s supervisorctl status" % (env.gnmi_container)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    for line in output['stdout_lines']:
        res = line.split()
        if len(res) < 3:
            continue
        program = res[0]
        status = res[1]
        if status == "RUNNING":
            dut_command = "docker exec %s supervisorctl stop %s" % (env.gnmi_container, program)
            duthost.shell(dut_command, module_ignore_errors=True)
            stopped_programs.append(program)
    dut_command = "docker exec %s pkill %s" % (env.gnmi_container, env.gnmi_process)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % env.gnmi_container
    dut_command += "\"/usr/bin/nohup /usr/sbin/%s -logtostderr --port %s " % (env.gnmi_process, env.gnmi_port)
    dut_command += "--server_crt /etc/sonic/telemetry/gnmiserver.crt --server_key /etc/sonic/telemetry/gnmiserver.key "
    dut_command += "--config_table_name GNMI_CLIENT_CERT "
    dut_command += "--client_auth cert "
    dut_command += "--enable_crl=true "
    if subtype == 'SmartSwitch':
        dut_command += "--zmq_address=tcp://127.0.0.1:8100 "
    dut_command += "--ca_crt /etc/sonic/telemetry/gnmiCA.pem -gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)

    # Setup gnmi client cert common name
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
    add_gnoi_client_common_name(duthost, "test.client.gnui.sonic", role)

    time.sleep(GNMI_SERVER_START_WAIT_TIME)
    dut_command = "sudo netstat -nap | grep %d" % env.gnmi_port
    output = duthost.shell(dut_command, module_ignore_errors=True)
    if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
        is_time_synced = wait_until(80, 3, 0, check_system_time_sync, duthost)
        assert is_time_synced, "Failed to synchronize DUT system time with NTP Server"
    if env.gnmi_process not in output['stdout']:
        # Dump tcp port status and gnmi log
        logger.info("TCP port status: " + output['stdout'])
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        pytest.fail("Failed to start gnmi server")
    return stopped_programs


def check_gnmi_process(duthost):
    """
    Make sure there's no GNMI process running.
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s pgrep -f %s" % (env.gnmi_container, env.gnmi_process)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return output['stdout'].strip() == ""


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def _check_monit_container_checker(duthost):
    """Check if monit container_checker service is healthy.

    After gNMI cert config recovery, monit needs time to re-evaluate
    container status. This function checks if container_checker has
    returned to a healthy state (OK or Status ok).
    """
    monit_services = duthost.get_monit_services_status()
    if not monit_services:
        return False
    container_checker = monit_services.get("container_checker", {})
    status = container_checker.get("service_status", "")
    return status in ("OK", "Status ok")


def recover_cert_config(duthost, stopped_programs=None):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    # Kill the GNMI process
    dut_command = "docker exec %s pkill %s" % (env.gnmi_container, env.gnmi_process)
    duthost.shell(dut_command, module_ignore_errors=True)
    wait_until(60, 1, 0, check_gnmi_process, duthost)
    # Restore only the programs that apply_cert_config explicitly stopped
    if stopped_programs:
        for program in stopped_programs:
            logger.info("recover_cert_config: starting stopped program %s in container %s", program, env.gnmi_container)
            dut_command = "docker exec %s supervisorctl start %s" % (env.gnmi_container, program)
            start_output = duthost.shell(dut_command, module_ignore_errors=True)
            logger.debug("recover_cert_config: start %s result: %s", program, start_output["stdout"])

    # Remove gnmi client cert common name
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    del_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic")
    ret = wait_until(300, 3, 0, check_gnmi_status, duthost)
    if not ret:
        dut_command = "tail /var/log/gnmi.log"
        output = duthost.shell(dut_command, module_ignore_errors=True)
        logger.error("GNMI service failed to start. GNMI log: {}".format(output['stdout']))
        pytest.fail("Failed to recover GNMI client cert configuration.")

    # Restart telemetry container if it was stopped during cert config change
    # apply_cert_config may trigger ctrmgrd to stop the telemetry container
    if not check_container_state(duthost, "telemetry", should_be_running=True):
        logger.info("Telemetry container is not running after cert config recovery, restarting it")
        duthost.shell("sudo systemctl restart telemetry", module_ignore_errors=True)

    # Wait for monit container_checker to report healthy status.
    # After restarting processes/containers, monit needs time to re-evaluate
    # service status. Without this wait, post-test sanity check may see stale
    # "Status failed" from container_checker and fail the test on teardown.
    if not wait_until(120, 10, 30, _check_monit_container_checker, duthost):
        logger.warning("Monit container_checker did not recover to healthy status after cert config recovery")
