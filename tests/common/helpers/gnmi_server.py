"""Shared helpers for configuring the gNMI server with client certificates."""

import logging
import time

import pytest

from tests.common.helpers.dut_utils import (
    get_container_processes,
    kill_container_processes,
    start_container_process,
)
from tests.common.helpers.gnmi_utils import (
    GNMIEnvironment,
    add_gnmi_client_common_name,
    del_gnmi_client_common_name,
    dump_gnmi_log,
    dump_system_status,
)
from tests.common.helpers.ntp_helper import NtpDaemon, check_ntp_sync_status, get_ntp_daemon_in_use
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
GNMI_SERVER_START_WAIT_TIME = 15


def apply_cert_config(duthost, vrf_name=None):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    metadata = cfg_facts["DEVICE_METADATA"]["localhost"]
    subtype = metadata.get("subtype", None)
    stopped_programs = []
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    if "RUNNING" in duthost.shell(dut_command, module_ignore_errors=True)["stdout"]:
        duthost.shell("docker exec %s supervisorctl stop %s" % (env.gnmi_container, env.gnmi_program))
        logger.info("Stopped supervisord program: %s", env.gnmi_program)
        stopped_programs.append(env.gnmi_program)

    processes = get_container_processes(duthost, env.gnmi_container, env.gnmi_process)
    kill_container_processes(duthost, processes)
    gnmi_command = "/usr/sbin/%s -logtostderr --port %s " % (env.gnmi_process, env.gnmi_port)
    gnmi_command += "--server_crt /etc/sonic/telemetry/gnmiserver.crt "
    gnmi_command += "--server_key /etc/sonic/telemetry/gnmiserver.key "
    gnmi_command += "--config_table_name GNMI_CLIENT_CERT "
    gnmi_command += "--client_auth cert --enable_crl=true "
    if subtype == "SmartSwitch":
        gnmi_command += "--zmq_address=tcp://127.0.0.1:8100 "
    if vrf_name:
        gnmi_command += "--gnmi_vrf %s " % vrf_name
    gnmi_command += "--ca_crt /etc/sonic/telemetry/gnmiCA.pem "
    gnmi_command += "-gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1"
    start_container_process(duthost, env.gnmi_container, gnmi_command)

    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
    add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)

    def _gnmi_server_listening():
        cmd = 'sudo ss -ltnp | grep ":{} " | grep {}'.format(env.gnmi_port, env.gnmi_process)
        return duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip() != ""

    server_started = wait_until(GNMI_SERVER_START_WAIT_TIME * 2, 3, 5, _gnmi_server_listening)
    if not server_started:
        output = duthost.shell('sudo ss -ltnp | grep ":{} "'.format(env.gnmi_port), module_ignore_errors=True)
        logger.info("TCP port status: " + output["stdout"])
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        pytest.fail("Failed to start gnmi server")
    if duthost.facts["platform"] != "x86_64-kvm_x86_64-r0":
        is_time_synced = wait_until(80, 3, 0, check_system_time_sync, duthost)
        assert is_time_synced, "Failed to synchronize DUT system time with NTP Server"
    return stopped_programs


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output["stdout"]


def recover_cert_config(duthost, stopped_programs=None):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    processes = get_container_processes(duthost, env.gnmi_container, env.gnmi_process)
    kill_container_processes(duthost, processes)
    if stopped_programs:
        for program in stopped_programs:
            logger.info("Restarting supervisord program: %s", program)
            dut_command = "docker exec %s supervisorctl start %s" % (env.gnmi_container, program)
            duthost.shell(dut_command, module_ignore_errors=True)

    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    del_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic")
    ret = wait_until(300, 3, 0, check_gnmi_status, duthost)
    if not ret:
        output = duthost.shell("tail /var/log/gnmi.log", module_ignore_errors=True)
        logger.error("GNMI service failed to start. GNMI log: {}".format(output["stdout"]))
        pytest.fail("Failed to recover GNMI client cert configuration.")
    duthost.shell("sudo /usr/bin/container_checker")


def check_system_time_sync(duthost):
    """Check DUT NTP synchronization, restarting the time service if needed."""
    if check_ntp_sync_status(duthost) is True:
        return True
    ntp_daemon = get_ntp_daemon_in_use(duthost)
    if ntp_daemon == NtpDaemon.CHRONY:
        restart_ntp_cmd = "sudo systemctl restart chrony"
    else:
        restart_ntp_cmd = "sudo systemctl restart ntp"
    logger.info("DUT %s is NOT synchronized. Restarting NTP service...", duthost)
    duthost.command(restart_ntp_cmd)
    time.sleep(5)
    ntp_status = check_ntp_sync_status(duthost)
    if ntp_status is True:
        logger.info("DUT %s is now synchronized with NTP server.", duthost)
        return True
    logger.error("DUT %s: NTP synchronization failed. Please check manually.", duthost)
    return False
