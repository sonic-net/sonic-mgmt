from tests.common.utilities import (wait, wait_until)  # noqa F401
from tests.common.helpers.assertions import pytest_assert  # noqa F401
from tests.common.snappi_tests.uhd.uhd_helpers import NetworkConfigSettings  # noqa: F403, F401
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from pathlib import Path
import snappi
import time
import os
import glob
import re
import json

import logging

logger = logging.getLogger(__name__)


def set_static_routes(duthost, static_ipmacs_dict):

    static_macs = static_ipmacs_dict['static_macs']

    # Install Static Routes
    logger.info('Configuring static routes')
    for ip in static_macs:
        try:
            logger.info(f'{duthost.hostname} setting: sudo arp -s {ip} {static_macs[ip]}')
            duthost.shell(f'sudo arp -s {ip} {static_macs[ip]}')
        except Exception as e:  # noqa F841
            pass

    return


def wait_for_all_dpus_status(duthost, desired_status, timeout=300, interval=5):

    if isinstance(desired_status, (list, tuple, set)):
        desired_set = {str(s).strip().lower() for s in desired_status}
    else:
        desired_set = {str(desired_status).strip().lower()}

    deadline = time.time() + timeout
    while time.time() < deadline:
        result = duthost.shell("show chassis module status", module_ignore_errors=True)
        stdout = result.get("stdout", "") or ""

        # Keep only DPU rows
        dpu_lines = [ln for ln in stdout.splitlines() if ln.strip().startswith("DPU")]
        if dpu_lines:
            statuses = []
            for ln in dpu_lines:
                parts = re.split(r"\s{2,}", ln.strip())
                # Expected columns: [Name, Description, Physical-Slot, Oper-Status, Admin-Status, ...]
                if len(parts) >= 4:
                    statuses.append(parts[3].strip().lower())
                else:
                    statuses.append(None)

            if statuses and all(st in desired_set for st in statuses):
                return True

        time.sleep(interval)

    return False


def wait_for_all_dpus_offline(duthost, timeout=600, interval=5):

    logger.info("Waiting for all DPUs to be Offline")
    return wait_for_all_dpus_status(duthost, "offline", timeout=timeout, interval=interval)


def wait_for_all_dpus_online(duthost, timeout=600, interval=5, allow_partial=True):

    # logger.info("Waiting for all DPUs to be Online")

    desired = ["online", "partial online"] if allow_partial else "online"
    if allow_partial:
        logger.info(f"Waiting for all DPUs to be Online or Partial Online on {duthost.hostname}")
    else:
        logger.info(f"Waiting for all DPUs to be Online on {duthost.hostname}")

    return wait_for_all_dpus_status(duthost, desired, timeout=timeout, interval=interval)


def _telemetry_run_on_dut(duthost):

    cmd = (
        "docker exec -d gnmi "
        "/usr/sbin/telemetry -logtostderr "
        "--server_crt /etc/sonic/tls/server.crt "
        "--server_key /etc/sonic/tls/server.key "
        "--port 8080 --allow_no_client_auth -v=2 "
        "-zmq_port=8100 --threshold 100 --idle_conn_duration 5"
    )
    logger.info(f"Running telemetry on the DUT {duthost.hostname}")
    # Ignore errors if it is already running; let caller proceed
    duthost.shell(cmd, module_ignore_errors=True)


def _ensure_remote_dir_on_dut(duthost, remote_dir):
    logger.info("Make directory on DUT to store DPU config files:")
    duthost.shell(f"sudo mkdir -p {remote_dir}")


def _copy_files_to_dut(duthost, local_files, remote_dir):

    logger.info(f"Copying files to DUT {duthost.hostname}")
    # duthost.copy copies from the test controller to the DUT
    for lf in local_files:
        duthost.copy(src=lf, dest=remote_dir)


def _check_files_copied(duthost):
    logger.info("Checking DPU files copied to DUT")
    output = duthost.shell('ls /tmp/dpu_configs/dpu0/ | wc -l')['stdout']

    return output.strip()


def _duplicate_dpu_config(duthost, remote_dir, dpu_index):
    logger.info("Duplicating DPU config files for HA test case")
    duthost.shell(f"cp /tmp/dpu_configs/dpu0/* {remote_dir}/")


def _iter_dpu_config_files(dpu_index, local_dir):

    logger.info(f"Iterating through dpu_config files for DPU {dpu_index}")
    subdir = os.path.join(local_dir, f"dpu{dpu_index}")

    if os.path.isdir(subdir):
        return sorted(glob.glob(os.path.join(subdir, "*.json")))

    return False


def _get_dpu0_lf(local_dir):

    dpu_index = 0
    subdir = os.path.join(local_dir, f"dpu{dpu_index}")

    if os.path.isdir(subdir):
        return sorted(glob.glob(os.path.join(subdir, "*.json")))

    return False


def set_ha_roles(duthosts, duthost):
    if duthost == duthosts[0]:
        try:
            # Active side
            active_cmd1 = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SET_CONFIG_TABLE:haset0_0 version \"1\" vip_v4 "221.0.0.1" scope "dpu" preferred_vdpu_id "vdpu0_0" preferred_standalone_vdpu_index 0 vdpu_ids '["vdpu0_0","vdpu1_0"]' '''  # noqa E501
            active_cmd2 = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SCOPE_CONFIG_TABLE:vdpu0_0:haset0_0 version \"1\" disabled "true" desired_ha_state "active" ha_set_id "haset0_0" owner "dpu" '''  # noqa E501

            logger.info("Setting up HA creation Active side cmd1")
            output_cmd1 = duthost.shell(active_cmd1)
            logger.info(f"Active side cmd1 output: {output_cmd1['stdout']}")

            time.sleep(2)
            logger.info("Setting up HA creation Active side cmd2")
            output_cmd2 = duthost.shell(active_cmd2)
            logger.info(f"Active side cmd2 output: {output_cmd2['stdout']}")
        except Exception as e:
            logger.error(f"{duthost.hostname} Error setting HA roles active side: {str(e)}")
    else:
        try:
            # Standby side
            standby_cmd1 = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SET_CONFIG_TABLE:haset0_0 version \"1\" vip_v4 "221.0.0.1" scope "dpu" preferred_vdpu_id "vdpu0_0" preferred_standalone_vdpu_index 0 vdpu_ids '["vdpu0_0","vdpu1_0"]' '''  # noqa E501
            standby_cmd2 = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SCOPE_CONFIG_TABLE:vdpu1_0:haset0_0 version \"1\" disabled "true" desired_ha_state "unspecified" ha_set_id "haset0_0" owner "dpu" '''  # noqa E501

            logger.info("Setting up HA creation Standby side cmd1")
            output_cmd1 = duthost.shell(standby_cmd1)
            logger.info(f"Standby side cmd1 output: {output_cmd1['stdout']}")

            time.sleep(2)
            logger.info("Setting up HA creation Standby side cmd2")
            output_cmd2 = duthost.shell(standby_cmd2)
            logger.info(f"Standby side cmd2 output: {output_cmd2['stdout']}")
        except Exception as e:
            logger.error(f"{duthost.hostname} Error setting HA roles standby side: {str(e)}")

    return


def set_ha_admin_up(duthosts, duthost, tbinfo):

    if duthost == duthosts[0]:
        # Active side
        try:
            standby_ethpass_ip = tbinfo['standby_ethpass_ip']
            standby_mac = tbinfo['standby_mac']

            active_cmd1 = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SCOPE_CONFIG_TABLE:vdpu0_0:haset0_0 version \"1\" disabled "false" desired_ha_state "active" ha_set_id "haset0_0" owner "dpu"'''  # noqa E501
            logger.info("Setting up HA admin up Active side cmd1")
            output_cmd1 = duthost.shell(active_cmd1)
            logger.info(f"Active side cmd1 output: {output_cmd1['stdout']}")

            time.sleep(2)
            output = duthost.shell(f'sudo arp -s {standby_ethpass_ip} {standby_mac}')
            output_ping = duthost.command(f"ping -c 3 {standby_ethpass_ip}", module_ignore_errors=True)  # noqa: F841
        except Exception as e:
            logger.error(f"{duthost.hostname} Error setting HA admin up active side: {str(e)}")
    else:
        # Standby side
        try:
            active_ethpass_ip = tbinfo['active_ethpass_ip']
            active_mac = tbinfo['active_mac']

            standby_cmd1 = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SCOPE_CONFIG_TABLE:vdpu1_0:haset0_0 version \"1\" disabled "false" desired_ha_state "unspecified" ha_set_id "haset0_0" owner "dpu"'''  # noqa E501
            logger.info("Setting up HA admin up Standby side cmd1")
            output_cmd1 = duthost.shell(standby_cmd1)
            logger.info(f"Standby side cmd1 output: {output_cmd1['stdout']}")

            time.sleep(2)
            output = duthost.shell(f'sudo arp -s {active_ethpass_ip} {active_mac}')  # noqa: F841
            output_ping = duthost.command(f"ping -c 3 {active_ethpass_ip}", module_ignore_errors=True)  # noqa: F841
        except Exception as e:
            logger.error(f"{duthost.hostname} Error setting HA admin up standby side: {str(e)}")

    return


def set_ha_activate_role(duthosts, duthost):
    # Extract pending_operation_ids from both Active and Standby sides
    logger.info(f'{duthost.hostname} Resting for 30 seconds before attempting to set HA activation role for pending '
                f'operation id is set')
    time.sleep(30)
    retries = 3

    if duthost == duthosts[0]:
        # Active side
        cmd = r'''docker exec dash-hadpu0 swbus-cli show hamgrd actor /hamgrd/0/ha-scope/vdpu0_0:haset0_0'''
        logger.info("Setting up HA activation role Active side")
    else:
        # Standby side
        cmd = r'''docker exec dash-hadpu0 swbus-cli show hamgrd actor /hamgrd/0/ha-scope/vdpu1_0:haset0_0'''
        logger.info("Setting up HA activation role Standby side")

    # Extract the pending_operation_ids UUID using regex
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

    # Execute command (without grep) and parse in Python
    while retries > 0:
        # Run the command, tolerating errors (module_ignore_errors=True)
        result = duthost.shell(cmd, module_ignore_errors=True)
        rc = result.get('rc', 1)  # Default to 1 if no rc
        stdout = result.get('stdout', '')
        stderr = result.get('stderr', '')

        if rc != 0:
            # Command failed (e.g., docker error) - log and retry
            logger.warning(f"Command failed on {duthost.hostname} (rc={rc}): {cmd}")
            logger.info(f"STDERR: {stderr}")
            logger.info(f"STDOUT (partial): {stdout[:200]}...")  # Partial for brevity
        else:
            # Command succeeded - check for the field and extract UUID
            if 'pending_operation_ids' in stdout:
                match = re.search(uuid_pattern, stdout)
                if match:
                    pending_operation_id = match.group(0)
                    logger.info(f"Found pending_operation_id on {duthost.hostname}: {pending_operation_id}")
                    logger.info(f"Applying pending_operation_id on {duthost.hostname}")
                    if duthost == duthosts[0]:
                        # Active side
                        cmd = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SCOPE_CONFIG_TABLE:vdpu0_0:haset0_0 version \"3\" disabled "false" desired_ha_state "active" ha_set_id "haset0_0" owner "dpu" approved_pending_operation_ids [\"{}\"]'''.format(  # noqa E501
                            pending_operation_id)
                        logger.info("Setting up HA activation role Active side")
                        output = duthost.shell(cmd)
                        logger.info(f"Active side output after cmd output: {output['stdout']}")
                    else:
                        cmd = r'''docker exec swss python /etc/sonic/proto_utils.py hset DASH_HA_SCOPE_CONFIG_TABLE:vdpu1_0:haset0_0 version \"3\" disabled "false" desired_ha_state "unspecified" ha_set_id "haset0_0" owner "dpu" approved_pending_operation_ids [\"{}\"]'''.format(  # noqa E501
                            pending_operation_id)
                        logger.info("Setting up HA activation role Standby side")
                        output = duthost.shell(cmd)
                        logger.info(f"Standby side output after cmd output: {output['stdout']}")
                    return pending_operation_id  # Success - return the ID
            else:
                logger.info(f"pending_operation_ids not found yet in output on {duthost.hostname}")

        # No match or error - retry
        retries -= 1
        logger.warning(f"Could not extract pending_operation_id from {duthost.hostname} (retries left: {retries})")
        logger.info(f"Raw output: {stdout}")
        if retries > 0:
            logger.info("Sleeping for 10 seconds then trying again")
            time.sleep(10)
        else:
            logger.error(f"Exhausted retries on {duthost.hostname}")
            return False

    return False


def _set_routes_on_dut(duthosts, duthost, tbinfo, local_files, local_dir, dpu_index, ha_test_case):
    logger.info(f"Preparing to load DPU configs on DUT for dpu_index={dpu_index}")
    username = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_user']
    password = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_password']
    jump_host = {
        'device_type': 'linux',
        'ip': f'{duthost.mgmt_ip}',
        'username': f'{username}',
        'password': f'{password}',
    }

    if ha_test_case != "cps":
        if len(duthosts) > 1:
            if duthost == duthosts[1]:
                target_ip = f'169.254.200.{dpu_index + 1}'
            else:
                target_ip = f'18.{dpu_index}.202.1'
        else:
            target_ip = f'18.{dpu_index}.202.1'
    else:
        target_ip = f'18.{dpu_index}.202.1'
    target_username = 'admin'
    target_password = 'YourPaSsWoRd'

    # Connect to jump host
    net_connect_jump = ConnectHandler(**jump_host)

    # SSH from jump host to target device using proper netmiko method
    # First, create the SSH command
    ssh_command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {target_username}@{target_ip}"

    try:
        # Use send_command_timing to handle the password prompt
        net_connect_jump.write_channel(f"{ssh_command}\n")
        time.sleep(2)  # Wait for password prompt

        # Check if we got a password prompt
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} SSH output: {output}")

        if 'password' in output.lower():
            net_connect_jump.write_channel(f"{target_password}\n")
            time.sleep(3)  # Wait for login to complete

        # Clear the buffer and set the base prompt
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} Login output: {output}")

        # Now use send_command_timing instead of send_command for better compatibility
        logger.info(f"{duthost.hostname} Execute on DPU Target - Connected")

        output = net_connect_jump.send_command_timing('show version', delay_factor=2)
        logger.info(f"{duthost.hostname} Execute on DPU Target {output}")

        output = net_connect_jump.send_command_timing('show ip route', delay_factor=2)
        logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")

        if ha_test_case == "cps":
            found = False
            if 'S>*0.0.0.0/0' in output:
                found = True

            if found is False:
                output = net_connect_jump.send_command_timing('sudo ip route del 0.0.0.0/0 via 169.254.200.254',
                                                              delay_factor=2)
                logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
                output = net_connect_jump.send_command_timing(
                    'sudo config route del prefix 0.0.0.0/0 via 169.254.200.254', delay_factor=2)
                logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
                time.sleep(1)
                logger.info(f'sudo config route add prefix 0.0.0.0/0 nexthop 18.{dpu_index}.202.0')
                output = net_connect_jump.send_command_timing(
                    f'sudo config route add prefix 0.0.0.0/0 nexthop 18.{dpu_index}.202.0', delay_factor=2)
                logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
                output = net_connect_jump.send_command_timing('show ip route', delay_factor=2)
                logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")

            output = net_connect_jump.send_command_timing('show ip interfaces', delay_factor=2)
            found = False
            for line in output.split('\n'):
                if 'Loopback0' in line.strip():
                    found = True
                    break
            if found is False:
                logger.info(f'sudo config interface ip add Loopback0 221.0.0.{dpu_index + 1}')
                output = net_connect_jump.send_command_timing(
                    f'sudo config interface ip add Loopback0 221.0.0.{dpu_index + 1}', delay_factor=2)
                logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
                output = net_connect_jump.send_command_timing('show ip interfaces', delay_factor=2)
                logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")

            output = net_connect_jump.send_command_timing('show ip interfaces', delay_factor=2)
            logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
            found = False
            for line in output.split('\n'):
                if 'Loopback1' in line.strip():
                    found = True
                    break
            if found is False:
                logger.info(f'sudo config interface ip add Loopback1 221.0.{dpu_index + 1}.{dpu_index + 1}')
                output = net_connect_jump.send_command_timing(
                    f'sudo config interface ip add Loopback1 221.0.{dpu_index + 1}.{dpu_index + 1}', delay_factor=2)
                logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")

            output = net_connect_jump.send_command_timing('show ip interfaces', delay_factor=2)
            logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
            output = net_connect_jump.send_command_timing('show ip route', delay_factor=2)
            logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
            output = net_connect_jump.send_command_timing('sudo arp -a', delay_factor=2)
            logger.info(f"{duthost.hostname} Execute on DPU Target: {output}")
        else:
            # Not a CPS test
            if dpu_index == 0:
                if len(duthosts) > 1 and duthost == duthosts[1]:
                    # DPU1 initial standby side
                    logger.info(f'Restarting hamgrd on {duthost.hostname}: docker restart dash-hadpu0')
                    duthost.shell("docker restart dash-hadpu0")
                    logger.info(f'Removing interface from {duthost.hostname}: '
                                f'sudo config interface ip rem Ethernet0 18.{dpu_index}.202.1/31')
                    time.sleep(2)
                    output = net_connect_jump.send_command_timing(
                        f'sudo config interface ip rem Ethernet0 18.{dpu_index}.202.1/31', delay_factor=2)
                    logger.info(
                        f'Deleting route on {duthost.hostname}: sudo ip route del 0.0.0.0/0 via 169.254.200.254')
                    time.sleep(2)
                    output = net_connect_jump.send_command_timing(
                        'sudo ip route del 0.0.0.0/0 via 169.254.200.254', delay_factor=2)
                    logger.info(
                        f'Adding route on {duthost.hostname}: '
                        f'sudo config route add prefix 0.0.0.0/0 nexthop 20.{dpu_index}.202.0')
                    time.sleep(2)
                    output = net_connect_jump.send_command_timing(
                        f'sudo config route add prefix 0.0.0.0/0 nexthop 20.{dpu_index}.202.0', delay_factor=2)
                    active_ethpass_ip = tbinfo['active_ethpass_ip']
                    active_mac = tbinfo['active_mac']
                    logger.info(
                        f'Adding to arp table on {duthost.hostname}: sudo arp -s {active_ethpass_ip} {active_mac}')  # noqa:  E231
                    output = duthost.shell(f'sudo arp -s {active_ethpass_ip} {active_mac}')
                    logger.info(
                        f'Pinging standby side loopback intf from {duthost.hostname}: '
                        f'ping -c 3 {active_ethpass_ip}')  # noqa:  E231
                    output_ping = duthost.command(f"ping -c 3 {active_ethpass_ip}", module_ignore_errors=True)
                    logger.info(f'Correcting route on {duthost.hostname}: '
                                f'sudo config route del prefix 221.0.0.{dpu_index+1}/32 nexthop 20.{dpu_index}.202.1')
                    output = duthost.command(f'sudo config route del prefix 221.0.0.{dpu_index+1}/32 '
                                             f'nexthop 20.{dpu_index}.202.1', module_ignore_errors=True)
                    logger.info(f'Adding correct route on {duthost.hostname}: '
                                f'sudo config route add prefix 221.0.0.{dpu_index+1}/32 nexthop 220.0.4.1')
                    output = duthost.command(f'sudo config route add prefix 221.0.0.{dpu_index+1}/32 '
                                             f'nexthop 220.0.4.1', module_ignore_errors=True)

                else:
                    # DPU0 initial active side
                    logger.info(f'Restarting hamgrd on {duthost.hostname}: docker restart dash-hadpu0')
                    duthost.shell("docker restart dash-hadpu0")
                    logger.info(f'Deleting route on {duthost.hostname}: '
                                f'sudo ip route del 0.0.0.0/0 via 169.254.200.254')
                    time.sleep(2)
                    output = net_connect_jump.send_command_timing(
                        'sudo ip route del 0.0.0.0/0 via 169.254.200.254', delay_factor=2)
                    logger.info(f'Adding route on {duthost.hostname}: '
                                f'sudo config route add prefix 0.0.0.0/0 nexthop 18.{dpu_index}.202.0')
                    time.sleep(2)
                    output = net_connect_jump.send_command_timing(
                        f'sudo config route add prefix 0.0.0.0/0 nexthop 18.{dpu_index}.202.0', delay_factor=2)

                    standby_ethpass_ip = tbinfo['standby_ethpass_ip']
                    standby_mac = tbinfo['standby_mac']
                    logger.info(
                        f'Adding to arp table on {duthost.hostname}: sudo arp -s {standby_ethpass_ip} {standby_mac}')  # noqa:  E231
                    output = duthost.shell(f'sudo arp -s {standby_ethpass_ip} {standby_mac}')
                    logger.info(
                        f'Pinging active side loopback intf from {duthost.hostname}: sudo ping -c 3 {standby_ethpass_ip}')  # noqa:  E231
                    output_ping = duthost.command(f"ping -c 3 {standby_ethpass_ip}",  # noqa: F841
                                                  module_ignore_errors=True)
    except Exception as e:
        logger.error(f"{duthost.hostname} Error during DPU configuration: {str(e)}")
        raise
    finally:
        # Disconnect from target and then jump host
        try:
            net_connect_jump.write_channel('exit\n')  # Exit target device session
            time.sleep(1)
        except Exception:
            pass
        net_connect_jump.disconnect()

    if not local_files:
        if not local_dir:
            # Default to repo path: tests/snappi_tests/dash/dpu_configs
            local_dir = str((Path(__file__).resolve().parents[3] / "snappi_tests" / "dash" / "dpu_configs"))

        if not os.path.isdir(local_dir):
            raise RuntimeError(f"Config directory does not exist: {local_dir}")

        local_files = _iter_dpu_config_files(dpu_index, local_dir)

    if not local_files:
        logger.info(f"No matching JSON files found to load for this DPU; skipping on DUT "  # noqa: E702
                    f"{duthost.hostname}.")
        return

    return local_files, local_dir


def _docker_run_config_on_dut(duthost, remote_dir, dpu_index, remote_basename):

    logger.info(f"{duthost.hostname} Docker run config for DPU{dpu_index}, remote_dir={remote_dir}, "
                f"remote_basename={remote_basename}")

    cmd = (
        "docker run --rm --network host "
        f"--mount src={remote_dir},target=/dpu,type=bind,readonly "  # noqa: E231
        "--mount src=/root/go_gnmi_utils.py,"
        "target=/usr/lib/python3/dist-packages/gnmi_agent/go_gnmi_utils.py,"
        "type=bind,readonly "
        "-t sonic-gnmi-agent:latest -c "
        f"'gnmi_client.py --batch_val 500 --dpu_index {dpu_index} --num_dpus 8 "
        f"--target 127.0.0.1:8080 update --filename /dpu/{remote_basename}'"  # noqa: E231
    )

    return duthost.shell(cmd, module_ignore_errors=True)


def load_dpu_configs_on_dut(
        duthosts,
        duthost,
        tbinfo,
        dpu_index,
        passing_dpus,
        local_dir=None,
        local_files=None,
        remote_dir="/tmp/dpu_configs",
        initial_delay_sec=20,
        retry_delay_sec=10,
        ha_test_case=None
):
    """
    Load DPU config JSONs by running gnmi_client in a Docker container on the DUT.
    """

    local_files, local_dir = _set_routes_on_dut(duthosts, duthost, tbinfo, local_files, local_dir, dpu_index,
                                                ha_test_case)
    remote_dir = f"{remote_dir}/dpu{dpu_index}"
    _ensure_remote_dir_on_dut(duthost, remote_dir)
    _telemetry_run_on_dut(duthost)
    _copy_files_to_dut(duthost, local_files, remote_dir)

    delay = initial_delay_sec
    for lf in local_files:
        if dpu_index in passing_dpus:
            rb = os.path.basename(lf)
            logger.info(f"Loading {lf} on DUT {duthost.hostname}")
            res = _docker_run_config_on_dut(duthost, remote_dir, dpu_index, rb)
            out = res.get("stdout", "")
            err = res.get("stderr", "")
            if "Set failed: rpc error: code = Unavailable desc = connection err" in (out + err):
                logger.info(f"RPC unavailable for {rb}; retrying after telemetry restart")  # noqa: E702
                duthost.shell("docker ps --format '{{.Names}}' | grep -w gnmi || true", module_ignore_errors=True)
                time.sleep(120)
                _telemetry_run_on_dut(duthost)
                time.sleep(retry_delay_sec)
                _docker_run_config_on_dut(duthost, remote_dir, dpu_index, rb)

            time.sleep(delay)
            delay = 2

    logger.info(f"Finished loading all DPU configs on DUT {duthost.hostname}")


def duthost_port_config(duthost):

    # copy HA config
    # duthost.command("sudo cp {} {}".format(
    #    "/etc/sonic/0HA_BACKUP/config_db.json", "/etc/sonic/config_db.json"))
    logger.info(f"{duthost.hostname} Loading custom HA config_db.json")
    duthost.shell("sudo sonic-cfggen -j /etc/sonic/0HA_BACKUP/config_db.json --write-to-db")
    duthost.shell("sudo cp /etc/sonic/0HA_BACKUP/config_db.json  /etc/sonic/config_db.json")

    # logger.info(f"{duthost.hostname} Reloading config_db.json")
    # duthost.shell("sudo config reload -y \n")

    logger.info(f"{duthost.hostname} Saving config_db.json")
    duthost.shell("sudo config save -y")

    return


def duthost_ha_config(duthost, nw_config):

    # Smartswitch configure
    """
    logger.info('Cleaning up config')
    logger.info("Wait until all critical services are fully started")
    pytest_assert(wait_until(360, 10, 1,
                             duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    """

    static_ipsmacs_dict = {}

    config_db_stdout = duthost.shell("cat /etc/sonic/config_db.json")["stdout"]
    config_db = json.loads(config_db_stdout)

    static_ips = {}
    for static_ip in config_db['STATIC_ROUTE']:
        static_ips[f"{static_ip.split('|', 1)[1].split('/', 1)[0]}"] = config_db['STATIC_ROUTE'][static_ip]['nexthop']

    tmp_mac = ""
    static_macs = {}
    staticKeys = [k for k in static_ips if k.startswith("221.1")]
    staticArpMacKeys = sorted(staticKeys, key=lambda k: int(k.rsplit('.', 1)[1]))

    for x, key in enumerate((staticArpMacKeys)):
        if x == 0:
            tmp_mac = nw_config.first_staticArpMac
            static_macs[static_ips[key]] = nw_config.first_staticArpMac
        else:
            tmp = tmp_mac.split(':')
            tmp[5] = "0{}".format(int(tmp[5]) + 1)
            static_arp_mac = ":".join(tmp)

            static_macs[static_ips[key]] = static_arp_mac
            tmp_mac = static_arp_mac

    static_ipsmacs_dict['static_ips'] = static_ips
    static_ipsmacs_dict['static_macs'] = static_macs

    return static_ipsmacs_dict


def remove_dpu_ip_addresses_from_npu(duthost, ip_prefixes_to_remove=["18"], additional_filters=None):

    logger.info(f"======== Starting IP address removal from NPU {duthost.hostname} ========")
    logger.info(f"Looking for IPs matching prefixes: {ip_prefixes_to_remove}")
    if additional_filters:
        logger.info(f"Additional filter patterns: {additional_filters}")

    # Get current IP interface configuration
    logger.info(f"Executing 'show ip interface' command on NPU {duthost.hostname}")
    result = duthost.shell("show ip interface", module_ignore_errors=True)
    output = result.get("stdout", "")

    logger.info(f"Raw output from 'show ip interface' on NPU {duthost.hostname}: ")
    logger.info(f"\n{output}\n")

    # Parse the output to find interfaces with ALL their IPs and identify which to remove
    lines = output.split('\n')
    interface_all_ips = {}  # Track ALL IPs per interface
    interfaces_to_clean = {}  # Track IPs to remove

    current_interface = None
    line_count = 0

    logger.info(f"Starting to parse output line by line on NPU {duthost.hostname}")

    for line in lines:
        line_count += 1
        stripped_line = line.strip()

        # Skip header and separator lines
        if not stripped_line or stripped_line.startswith('Interface') or stripped_line.startswith('---'):
            logger.info(f"Line {line_count}: Skipping header/separator line")
            continue

        parts = line.split()

        # Check if this is a new interface line (not indented)
        if len(parts) > 0 and not line.startswith(' '):
            current_interface = parts[0]
            logger.info(f"Line {line_count}: Found new interface: {current_interface}")
            if current_interface not in interface_all_ips:
                interface_all_ips[current_interface] = []

        # Collect ALL IP addresses for the interface
        if current_interface and len(parts) > 1:
            for part in parts:
                if '/' in part and not part.startswith('-'):
                    # This is an IP address with subnet
                    if part not in interface_all_ips[current_interface]:
                        interface_all_ips[current_interface].append(part)
                        logger.info(f"Line {line_count}: Tracked IP {part} for interface {current_interface}")

        # Check if this line contains an IP address we want to remove
        if current_interface and len(parts) > 1:
            matched = False

            # Check primary IP prefixes with 202. pattern
            for ip_prefix in ip_prefixes_to_remove:
                if f"{ip_prefix}." in line and "202." in line:
                    logger.info(
                        f"Line {line_count}: Found matching IP pattern (prefix={ip_prefix}) in line for interface "
                        f"{current_interface}")
                    logger.info(f"Line {line_count}: Line content: '{line}'")

                    # Extract the IP address with subnet
                    for part in parts:
                        if f"{ip_prefix}." in part and '/' in part and "202." in part:
                            if current_interface not in interfaces_to_clean:
                                interfaces_to_clean[current_interface] = []
                                logger.info(
                                    f"Line {line_count}: Initialized removal list for interface {current_interface}")

                            interfaces_to_clean[current_interface].append(part)
                            logger.info(f"Line {line_count}: Added IP {part} to removal list for {current_interface}")
                            matched = True
                            break
                    if matched:
                        break

            # Check additional filter patterns (for standby side cleanup)
            if not matched and additional_filters:
                for filter_pattern in additional_filters:
                    # More precise matching - look for the exact IP/subnet in parts
                    # The filter_pattern should be like "220.0.4.1/" to match exactly
                    for part in parts:
                        if '/' in part:
                            ip_part = part.split('/')[0]
                            # Check if the IP matches the filter pattern
                            # filter_pattern is like "220.0.4.1/" so we need to check if ip starts with it minus
                            # the trailing /
                            filter_ip = filter_pattern.rstrip('/')

                            if ip_part == filter_ip:
                                logger.info(
                                    f"Line {line_count}: Found exact matching IP ({ip_part}) for filter pattern "
                                    f"({filter_pattern}) in interface {current_interface}")
                                logger.info(f"Line {line_count}: Line content: '{line}'")

                                if current_interface not in interfaces_to_clean:
                                    interfaces_to_clean[current_interface] = []
                                    logger.info(
                                        f"Line {line_count}: Initialized removal list for interface "
                                        f"{current_interface}")

                                interfaces_to_clean[current_interface].append(part)
                                logger.info(
                                    f"Line {line_count}: Added IP {part} to removal list for {current_interface}")
                                matched = True
                                break
                    if matched:
                        break

    logger.info(f"Parsing complete on NPU {duthost.hostname}")
    logger.info(f"Total lines processed: {line_count}")
    logger.info(f"Interfaces with IPs to remove: {list(interfaces_to_clean.keys())}")
    logger.info(f"All interfaces and their IPs: {interface_all_ips}")

    if not interfaces_to_clean:
        logger.info(f"No matching IP addresses found on NPU {duthost.hostname} - nothing to remove")
        return {}

    logger.info(f"Starting IP address removal process on NPU {duthost.hostname}")
    removal_count = 0
    interfaces_with_remaining_ips = {}

    for interface, ip_list in interfaces_to_clean.items():
        logger.info(f"Processing interface {interface} on NPU {duthost.hostname}")
        logger.info(f"IPs to remove from {interface}: {ip_list}")

        # Determine which IPs will remain after removal
        all_ips = interface_all_ips.get(interface, [])
        remaining_ips = [ip for ip in all_ips if ip not in ip_list]

        if remaining_ips:
            logger.info(f"Interface {interface} will have remaining IPs after removal: {remaining_ips}")
            interfaces_with_remaining_ips[interface] = remaining_ips
        else:
            logger.info(f"Interface {interface} will have NO remaining IPs after removal")

        for ip_with_subnet in ip_list:
            removal_count += 1
            ip_addr, subnet = ip_with_subnet.split('/')

            logger.info(f"[{removal_count}] Preparing to remove {ip_addr}/{subnet} from {interface}")
            cmd = f"sudo config interface ip remove {interface} {ip_with_subnet}"
            logger.info(f"[{removal_count}] Executing command: {cmd}")

            result = duthost.shell(cmd, module_ignore_errors=True)

            if result.get("rc", 1) == 0:
                logger.info(f"[{removal_count}] Successfully removed {ip_addr}/{subnet} from {interface}")
            else:
                logger.info(f"[{removal_count}] WARNING: Failed to remove {ip_addr}/{subnet} from {interface}")
                logger.info(f"[{removal_count}] Return code: {result.get('rc')}")
                logger.info(f"[{removal_count}] stdout: {result.get('stdout', '')}")
                logger.info(f"[{removal_count}] stderr: {result.get('stderr', '')}")

    # Re-add remaining IPs to ensure they become primary
    if interfaces_with_remaining_ips:
        logger.info("Re-adding remaining IPs to ensure they are properly configured as primary")
        for interface, remaining_ips in interfaces_with_remaining_ips.items():
            for ip_with_subnet in remaining_ips:
                ip_addr, subnet = ip_with_subnet.split('/')
                logger.info(f"Re-adding {ip_addr}/{subnet} to {interface} to ensure it's the primary IP")

                # First remove it (in case it still exists as secondary)
                remove_cmd = f"sudo config interface ip remove {interface} {ip_with_subnet}"
                duthost.shell(remove_cmd, module_ignore_errors=True)

                # Then add it back (this makes it primary)
                add_cmd = f"sudo config interface ip add {interface} {ip_with_subnet}"
                logger.info(f"Executing command: {add_cmd}")
                result = duthost.shell(add_cmd, module_ignore_errors=True)

                if result.get("rc", 1) == 0:
                    logger.info(f"Successfully re-added {ip_addr}/{subnet} to {interface}")
                else:
                    logger.info(f"WARNING: Failed to re-add {ip_addr}/{subnet} to {interface}")
                    logger.info(f"Return code: {result.get('rc')}")
                    logger.info(f"stdout: {result.get('stdout', '')}")
                    logger.info(f"stderr: {result.get('stderr', '')}")

    logger.info(f"IP address removal complete on NPU {duthost.hostname}")
    logger.info(f"Total IP addresses removed: {removal_count}")
    logger.info("Summary of changes: ")
    for interface, ip_list in interfaces_to_clean.items():
        logger.info(f"  {interface}: Removed {', '.join(ip_list)}")
        if interface in interfaces_with_remaining_ips:
            logger.info(
                f"  {interface}: Remaining IPs re-added as primary: "
                f"{', '.join(interfaces_with_remaining_ips[interface])}")

    # Verify the changes
    logger.info(f"Verifying IP removal on NPU {duthost.hostname}")
    verify_result = duthost.shell("show ip interface", module_ignore_errors=True)
    verify_output = verify_result.get("stdout", "")
    logger.info(f"Updated 'show ip interface' output on NPU {duthost.hostname}: ")
    logger.info(f"\n{verify_output}\n")

    logger.info(f"======== IP address removal completed on NPU {duthost.hostname} ========")

    return interfaces_to_clean


def npu_startup(duthosts, duthost, localhost):
    retries = 3
    wait_time = 180
    timeout = 300

    while True:
        logger.info("Issuing a {} on the dut {}".format(
            "reboot", duthost.hostname))
        duthost.shell("shutdown -r now")
        logger.info(f"Waiting for dut ssh to start on {duthost.hostname}")
        localhost.wait_for(host=duthost.mgmt_ip, port=22, state="started", delay=10, timeout=timeout)
        wait(wait_time, msg=f"Wait for system to be stable on DUT {duthost.hostname}.")

        logger.info("Moving next to DPU config")

        # SKIP AHEAD for now to the ping
        dpus_online_result = wait_for_all_dpus_online(duthost, timeout)
        dpus_online_result = True

        if dpus_online_result is False:
            retries -= 1
            logger.info(f"DPU boot failed, not all DPUs are online on {duthost.hostname}")
            logger.info(f"Will retry boot, number of retries left on {duthost.hostname}: {retries}")
            if retries == 0:
                return False
        else:
            logger.info(f"DPU boot successful on {duthost.hostname}")
            break

    if duthost == duthosts[1]:  # standby device
        logger.info(f"Removing unwanted IPs from standby device: {duthost.hostname}")
        remove_dpu_ip_addresses_from_npu(
            duthost,
            ip_prefixes_to_remove=["18"],  # Removes 18.X.202.0/31 addresses
            additional_filters=["220.0.1.1/", "220.0.2.1/", "220.0.3.1/", "220.0.4.1/"]
        )

    return True


def dpu_startup(duthosts, duthost, tbinfo, static_ipmacs_dict, ha_test_case):

    logger.info(f"Pinging each DPU on {duthost.hostname}")
    """
    dpuIFKeys = [k for k in static_ipmacs_dict['static_ips'] if k.startswith("221.0")]
    passing_dpus = []

    for x, ipKey in enumerate(dpuIFKeys):
        logger.info(f"On {duthost.hostname} pinging DPU{x}: {static_ipmacs_dict['static_ips'][ipKey]}")
        output_ping = duthost.command(f"ping -c 3 {static_ipmacs_dict['static_ips'][ipKey]}", module_ignore_errors=True)
        if output_ping.get("rc", 1) == 0 and "0% packet loss" in output_ping.get("stdout", ""):
            logger.info(f"Ping success on {duthost.hostname}")
            passing_dpus.append(x)
            pass
        else:
            logger.info(f"Ping failure on {duthost.hostname}")
            pass
    """
    remote_dir = "/tmp/dpu_configs"
    initial_delay_sec = 20
    retry_delay_sec = 10

    # Determine which IPs to ping based on duthost
    if len(duthosts) > 1 and duthost == duthosts[1]:
        # For duthosts[1], ping 20.0.202.1, 20.1.202.1, ..., 20.7.202.1
        ip_list_to_ping = [f"169.254.200.{i+1}" for i in range(8)]
        logger.info(f"Using standby side midplane IPs for {duthost.hostname}: {ip_list_to_ping}")
    elif len(duthosts) > 1 and duthost == duthosts[0]:
        # For duthosts[0], ping 18.0.202.1, ..., 18.7.202.1
        ip_list_to_ping = [f"18.{i}.202.1" for i in range(8)]
        logger.info(f"Using active side IPs for {duthost.hostname}: {ip_list_to_ping}")
    else:
        # Fallback to original logic for single DUT setup
        dpuIFKeys = [k for k in static_ipmacs_dict['static_ips'] if k.startswith("221.0")]
        ip_list_to_ping = [static_ipmacs_dict['static_ips'][ipKey] for ipKey in dpuIFKeys]
        logger.info(f"Using default IP list for {duthost.hostname}: {ip_list_to_ping}")

    passing_dpus = []

    for x, ip_to_ping in enumerate(ip_list_to_ping):
        logger.info(f"On {duthost.hostname} pinging DPU{x}: {ip_to_ping}")
        output_ping = duthost.command(f"ping -c 3 {ip_to_ping}", module_ignore_errors=True)
        if output_ping.get("rc", 1) == 0 and "0% packet loss" in output_ping.get("stdout", ""):
            logger.info(f"Ping success {ip_to_ping} on {duthost.hostname}")
            passing_dpus.append(x)
            pass
        else:
            logger.info(f"Ping failure {ip_to_ping} on {duthost.hostname}")
            pass

    errors = {}

    """
    if ha_test_case != "cps":
        max_workers = 2
        required_dpus = [0, 2]
        if all(dpu in passing_dpus for dpu in required_dpus):
            passing_dpus = required_dpus
        else:
            passing_dpus = []
            return passing_dpus
    else:
        max_workers = min(8, max(1, len(passing_dpus)))
    """

    # max_workers = min(8, max(1, len(passing_dpus)))
    max_workers = min(8, max(1, len(passing_dpus)))
    logger.info("{} DPU config loading DPUs, passing_dpus: {}".format(duthost.hostname, passing_dpus))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        fm = {
            executor.submit(
                load_dpu_configs_on_dut,
                duthosts=duthosts,
                duthost=duthost,
                tbinfo=tbinfo,
                dpu_index=target_dpu_index,
                passing_dpus=passing_dpus,
                remote_dir=remote_dir,
                initial_delay_sec=initial_delay_sec,
                retry_delay_sec=retry_delay_sec,
                ha_test_case=ha_test_case
            ): target_dpu_index
            for target_dpu_index in passing_dpus
        }

        for future in as_completed(fm):
            idx = fm[future]
            try:
                _ = future.result()  # load_dpu_configs_on_dut returns None on success
                logger.info(f"DPU{idx}: configuration load completed on {duthost.hostname}")
            except Exception as e:
                logger.error(f"DPU{idx}: configuration load failed: {e} on {duthost.hostname}")
                errors[idx] = str(e)

    if errors:
        logger.error(f"One or more DPUs failed on {duthost.hostname}: {errors}")
        return False

    return True, passing_dpus


def assignPorts(api, ports_list):

    communityListUrl = "ixload/test/activeTest/communityList"
    communityList = ports_list

    communityNameList = []
    for ports_name in ports_list:
        communityNameList.append(ports_name)

    portListPerCommunity = ports_list
    for communityName in portListPerCommunity:
        if communityName not in communityNameList:
            errorMsg = ("Error while executing assignPorts operation. Invalid NetTraffic name: %s. "
                        "This NetTraffic is not defined in the loaded rxf.") % communityName
            raise Exception(errorMsg)

    for community in communityList:
        portListForCommunity = portListPerCommunity[community]
        if community == 'Traffic1@Network1':
            objectID = 0
        else:
            objectID = 1
        portListUrl = "%s/%s/network/portList" % (communityListUrl, objectID)

        for portTuple in portListForCommunity:
            chassisId, cardId, portId = portTuple
            paramDict = {"chassisId": chassisId, "cardId": cardId, "portId": portId}
            try:
                # Code that may raise an exception
                res = api.ixload_configure("post", portListUrl, paramDict)  # noqa: F841
            except Exception as e:
                # Handle any exception
                logger.info(f"An error occurred: {e}")

    return


def build_node_ips(count, vpc, nw_config, nodetype="client"):
    if nodetype in "client":
        ip = nw_config.ipp(int(nw_config.IP_R_START) + (nw_config.IP_STEP_NSG * count)
                           + int(nw_config.IP_STEP_ENI) * (vpc - 1))
    if nodetype in "server":
        ip = nw_config.ipp(int(nw_config.IP_L_START) + int(nw_config.IP_STEP_ENI) * (vpc - 1))

    return str(ip)


def build_node_macs(count, vpc, nw_config, nodetype="client"):

    if nodetype in "client":
        m = nw_config.maca(int(nw_config.MAC_R_START) + int(nw_config.maca(nw_config.ENI_MAC_STEP)) * (vpc - 1)
                           + (int(nw_config.maca(nw_config.ACL_TABLE_MAC_STEP)) * count))
    if nodetype in "server":
        m = nw_config.maca(int(nw_config.MAC_L_START) + int(nw_config.maca(nw_config.ENI_MAC_STEP)) * (vpc - 1))

    return str(m).replace('-', ':')


def build_node_vlan(index, nw_config, nodetype="client"):

    hero_b2b = False

    if nodetype == 'client':
        vlan = nw_config.ENI_L2R_STEP + index + 1
    else:
        if hero_b2b is True:
            vlan = 0
        else:
            vlan = nw_config.ENI_STEP + index

    return vlan


def create_ip_list(nw_config):

    ip_list = []

    ENI_COUNT = nw_config.ENI_COUNT
    logger.info("Creating an ENI_COUNT = {} for l47 trafficgen".format(ENI_COUNT))

    for eni in range(nw_config.ENI_START, ENI_COUNT + 1):
        ip_dict_temp = {}
        ip_client = build_node_ips(0, eni, nw_config, nodetype="client")
        mac_client = build_node_macs(0, eni, nw_config, nodetype="client")
        vlan_client = build_node_vlan(eni - 1, nw_config, nodetype="client")

        ip_server = build_node_ips(0, eni, nw_config, nodetype="server")
        mac_server = build_node_macs(0, eni, nw_config, nodetype="server")
        vlan_server = build_node_vlan(eni - 1, nw_config, nodetype="server")

        ip_dict_temp['eni'] = eni
        ip_dict_temp['ip_client'] = ip_client
        ip_dict_temp['mac_client'] = mac_client
        ip_dict_temp['vlan_client'] = vlan_client

        ip_dict_temp['ip_server'] = ip_server
        ip_dict_temp['mac_server'] = mac_server
        ip_dict_temp['vlan_server'] = vlan_server

        ip_list.append(ip_dict_temp)

    return ip_list


def edit_l1_settings(api):

    params = {'useIEEEDefaults': 'false',
              'autoNegotiate': 'false',
              'enableRSFEC': 'true',
              'enableRSFECStatistics': 'true'}

    for i in range(2):
        portl1_url = "ixload/test/activeTest/communityList/{}/network/portL1Settings".format(i)
        try:
            # Code that may raise an exception
            res = api.ixload_configure("patch", portl1_url, params)  # noqa: F841
        except Exception as e:
            # Handle any exception
            logger.info(f"An error occurred: {e}")

    return


def find_test_role(test_type, server_vlan):

    test_role = ""
    if test_type == 'all':
        test_role = 'all'
    else:
        if (server_vlan - 1) % 4 == 3:
            # TCP BG
            test_role = "tcpbg"
        else:
            # CPS
            test_role = "cps"

    return test_role


def get_objectIDs(api, url):

    objectIDs = []
    payload = {}
    res = api.ixload_configure("get", url, payload)
    for r in res:
        objectIDs.append(r['objectID'])

    return objectIDs


def set_rangeList(api):
    """
    Adjust both rangeList, macRange, and vlanRange as needed
    """
    clientList_url = "ixload/test/activeTest/communityList/0/network/stack/childrenList/2/childrenList/3/rangeList"

    serverList_url = "ixload/test/activeTest/communityList/1/network/stack/childrenList/5/childrenList/6/rangeList"

    # get all the IDs
    client_objectIDs = get_objectIDs(api, clientList_url)
    server_objectIDs = get_objectIDs(api, serverList_url)

    # Adjust client side
    dict1 = {'doubleIncrement': True}
    dict2 = {
        'firstCount': '10',
        'firstIncrementBy': '0.2.0.0',
        'secondCount': '64',
        'secondIncrementBy': '0.0.0.2'
    }
    vlan_dict = {'uniqueCount': 1}

    for i, cid in enumerate(client_objectIDs):
        try:
            # Code that may raise an exception
            res1 = api.ixload_configure("patch", "{}/{}".format(clientList_url, cid), dict1)  # noqa: F841
            res2 = api.ixload_configure("patch", "{}/{}".format(clientList_url, cid), dict2)  # noqa: F841
            res3 = api.ixload_configure("patch", "{}/{}/vlanRange".format(clientList_url, cid), vlan_dict)  # noqa: F841
        except Exception as e:
            # Handle any exception
            logger.info(f"An error occurred: {e}")

    for i, sid in enumerate(server_objectIDs):
        try:
            # Code that may raise an exception
            res1 = api.ixload_configure("patch", "{}/{}/vlanRange".format(serverList_url, sid), vlan_dict)  # noqa: F841
        except Exception as e:
            # Handle any exception
            logger.info(f"An error occurred: {e}")

    return


def set_trafficMapProfile(api):

    # Make Traffic Map Settings
    portMapPolicy_json = {'portMapPolicy': 'customMesh'}
    destination_url = "ixload/test/activeTest/communityList/0/activityList/0/destinations/0"
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", destination_url, portMapPolicy_json)
    except Exception as e:
        # Handle any exception
        logger.info(f"An error occurred: {e}")

    # meshType
    meshType_json = {'meshType': 'vlanRangePairs'}
    submapsIpv4_url = "ixload/test/activeTest/communityList/0/activityList/0/destinations/0/customPortMap/submapsIPv4/0"
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", submapsIpv4_url, meshType_json)  # noqa: F841
    except Exception as e:
        # Handle any exception
        logger.info(f"An error occurred: {e}")

    return


def set_tcpCustom(api):

    tcp_agent_url = "ixload/test/activeTest/communityList/0/activityList/0/agent"
    # url = "{}/{}".format(base_url, tcp_agent_url)

    param_json = {'maxPersistentRequests': 1}
    # response = requests.patch(url, json=param_json)
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", tcp_agent_url, param_json)  # noqa: F841
    except Exception as e:
        # Handle any exception
        logger.info(f"An error occurred: {e}")

    return


def set_timelineCustom(api, initial_cps_value):

    activityList_url = "ixload/test/activeTest/communityList/0/activityList/0"  # noqa: F841
    timelineObjectives_url = "ixload/test/activeTest/communityList/0/activityList/0/timeline"

    activityList_json = {  # noqa: F841
        'constraintType': 'ConnectionRateConstraint',
        'constraintValue': initial_cps_value,
        'enableConstraint': False,
    }

    timeline_json = {
        'rampUpValue': 1000000,
        'sustainTime': 300
    }

    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", timelineObjectives_url, timeline_json)  # noqa: F841
    except Exception as e:
        # Handle any exception
        logger.info(f"An error occurred: {e}")

    return


def set_userIPMappings(api):

    url = "ixload/test/activeTest/communityList/0/activityList/0"

    param_userIpMapping = {
        'userIpMapping': '1:ALL-PER-CONNECTION',
    }

    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", url, param_userIpMapping)  # noqa: F841
    except Exception as e:
        # Handle any exception
        logger.info(f"An error occurred: {e}")
        return None

    return


def l47_trafficgen_main(ports_list, connection_dict, nw_config, test_type, test_filename, initial_cps_value):

    # Start Here ######
    main_start_time = time.time()
    gw_ip = connection_dict['gw_ip']
    port = connection_dict['port']
    chassis_ip = connection_dict['chassis_ip']
    ixl_version = connection_dict['version']

    api = snappi.api(location="{}:{}".format(gw_ip, port), ext="ixload", verify=False, version=ixl_version)
    config = api.config()

    port_1 = config.ports.port(name="p1", location="{}/1/1".format(chassis_ip))[-1]  # noqa: F841
    port_2 = config.ports.port(name="p2", location="{}/1/2".format(chassis_ip))[-1]  # noqa: F841

    # client/server IP ranges created here
    ip_list = create_ip_list(nw_config)

    logger.info("Setting devices")
    time_device_time = time.time()
    (d1, d2) = config.devices.device(name="d1").device(name="d2")
    time_device_finish = time.time()
    logger.info("Devices completed: {}".format(time_device_finish - time_device_time))

    logger.info("Building Network traffic")
    for eni, eni_info in enumerate(ip_list):
        # Change when adding in tcpbg
        test_role = find_test_role(test_type, eni_info['vlan_server'])
        test_role = 'cps'

        # client ######
        if test_role == 'cps' or test_role == 'all':
            de_tmp = "d1.e1"
            d1.name = de_tmp

            # ethernet section
            eth = d1.ethernets.add()
            eth.name = "e1"
            eth.connection.port_name = "p1"
            eth.mac = eni_info['mac_client']
            eth.step = "00:00:00:00:00:02"

            # ip section
            ip1 = eth.ipv4_addresses.ipv4()[-1]
            ip1.name = "{}.ipv4".format(eth.name)
            ip1.address = eni_info['ip_client']
            ip1.prefix = 10
            ip1.gateway = "0.0.0.0"
            # ip1.count = ACL_RULES_NSG * ACL_TABLE_COUNT * IP_PER_ACL_RULE * 2
            ip1.count = 1

            # vlan section
            vlan = eth.vlans.vlan()[-1]
            vlan.name = "{}.vlan".format(eth.name)
            vlan.id = eni_info['vlan_client']
            vlan.priority = 1
            vlan.count = 1
            vlan.tpid = "x8100"

            # SERVER ######
            de_tmp_server = "d2.e2"
            d2.name = de_tmp_server

            # ethernet section
            eth2 = d2.ethernets.add()
            eth2.name = "e2"
            eth2.connection.port_name = "p2"
            eth2.mac = eni_info['mac_server']
            eth2.step = "00:00:00:00:00:02"

            # ip section
            ip2 = eth2.ipv4_addresses.ipv4()[-1]
            ip2.name = "{}.ipv4".format(eth2.name)
            ip2.address = eni_info['ip_server']
            ip2.prefix = 10
            ip2.gateway = "0.0.0.0"
            ip2.count = 1

            # vlan section
            vlan2 = eth2.vlans.vlan()[-1]
            vlan2.name = "{}.vlan".format(eth2.name)
            vlan2.id = eni_info['vlan_server']
            vlan2.priority = 1
            vlan2.count = 1
            vlan2.tpid = "x8100"

    logger.info("Net Traffic completed:")

    # tcp/http client settings
    logger.info("Configuring TCP client settings")
    (t1,) = d1.tcps.tcp(name="Tcp1")
    t1.ip_interface_name = ip1.name
    t1.adjust_tcp_buffers = False
    t1.receive_buffer_size = 1024
    t1.transmit_buffer_size = 1024
    t1.keep_alive_time = 7200
    t1.keep_alive_interval = 75
    t1.keep_alive_probes = 9
    t1.retransmission_minimum_timeout = 200
    t1.retransmission_maximum_timeout = 120000
    t1.minimum_source_port = 1024
    t1.maximum_source_port = 65530
    t1.inter_packet_gap = 8
    t1.inter_packet_delay = 0
    t1.ip_fragment_time = 30
    t1.fin_timeout = 60
    t1.syn_retries = 5
    t1.synack_retries = 5
    t1.retansmit_retries1 = 3
    t1.retransmit_retries2 = 5
    t1.packet_reordering = 3
    t1.delayed_acks_segments = 0
    t1.delayed_acks_timeout = 0
    t1.disable_path_mtu = True
    t1.window_scaling = False
    t1.selective_ack = True
    t1.time_wait_reuse = False
    t1.time_wait_recycle = True
    t1.time_wait_rfc1323_strict = False
    t1.packet_timestamps = True
    t1.explicit_congestion_notification = False
    t1.fragment_reassembly_timer = 30
    logger.info("TCP completed")

    # http
    logger.info("Configuring HTTP client settings")
    (http_1,) = d1.https.http(name="HTTP1")
    http_1.tcp_name = t1.name  # UDP configs can be mapped http.transport = udp_1.name
    http_1.url_stats_count = 10
    http_1.time_to_live_value = 64
    http_1.high_perf_with_simulated_user = False
    (http_client,) = http_1.clients.client()
    http_client.name = "http_client1"
    http_client.cookie_jar_size = 10
    http_client.version = "1"
    http_client.cookie_reject_probability = True
    http_client.enable_cookie_support = False
    http_client.command_timeout = 600
    http_client.command_timeout_ms = 0
    http_client.keep_alive = False
    http_client.max_persistent_requests = 1
    http_client.max_sessions = 1
    http_client.max_streams = 1
    http_client.max_pipeline = 1
    http_client.piggy_back_ack = True
    http_client.tcp_fast_open = False
    http_client.content_length_deviation_tolerance = 0

    (get_a, delete_a) = http_client.methods.method().method()
    (get1,) = get_a.get.get()
    get1.destination = "Traffic2_http_server1:80"
    get1.page = "./1b.html"
    get1.name_value_args = ""
    # (delete1,) = delete_a.delete.delete()
    # delete1.destination = "Traffic2_Http1Server1:80"
    # delete1.page = "./1b.html"
    logger.info("HTTP client completed")

    # tcp/http server settings
    # tcp
    logger.info("Configuring TCP server settings")
    (t2,) = d2.tcps.tcp(name="Tcp2")
    t2.ip_interface_name = ip2.name
    t2.adjust_tcp_buffers = False
    t2.receive_buffer_size = 1024
    t2.transmit_buffer_size = 1024
    t2.time_wait_recycle = False
    t2.time_wait_rfc1323_strict = True
    t2.keep_alive_time = 600
    logger.info("TCP server completed")

    # http
    logger.info("Configuring HTTP server settings")
    (http_2,) = d2.https.http(name="HTTP2")
    http_2.tcp_name = t2.name  # UDP configs can be mapped http.transport = udp_2.name
    http_2.enable_tos = False
    http_2.url_stats_count = 10
    http_2.time_to_live_value = 64
    http_2.high_perf_with_simulated_user = False  # UDP configs can be mapped http.transport = udp_2.name
    (http_server,) = http_2.servers.server()
    http_server.name = "http_server1"
    http_server.rst_timeout = 100
    http_server.enable_http2 = False
    http_server.port = 80
    http_server.request_timeout = 5
    http_server.maximum_response_delay = 0
    http_server.minimum_response_delay = 0
    http_server.url_page_size = 1024
    logger.info("HTTP server completed")

    # Traffic Profile
    ENI_COUNT = nw_config.ENI_COUNT   # Change when scale up
    logger.info("Configuring Traffic Profile settings")
    (tp1,) = config.trafficprofile.trafficprofile()
    # traffic_profile = config.TrafficProfiles.TrafficProfile(name = "traffic_profile_1")
    tp1.app = [http_client.name, http_server.name]
    tp1.objective_type = ["connection_per_sec", "simulated_user"]
    tp1.objective_value = [4500000, ENI_COUNT*250000]
    (obj_type,) = tp1.objectives.objective()
    obj_type.connection_per_sec.enable_controlled_user_adjustment = True
    obj_type.connection_per_sec.sustain_time = 14
    obj_type.connection_per_sec.ramp_down_time = 12
    obj_type.connection_per_sec.time_to_first_iter = 3
    obj_type.connection_per_sec.iteration = 4
    (segment1, segment2) = tp1.segment.segment().segment()
    segment1.name = "Linear segment1"
    segment1.start = 0
    segment1.duration = 10
    # segment1.rate = int((ENI_COUNT * 25000) * .10)
    # segment1.target = 100
    segment2.name = "Linear segment2"
    # segment2.start = 0
    segment2.duration = 1000
    segment2.rate = 10
    segment2.target = ENI_COUNT*250000
    # tp1.timeline = [segment1.name, segment2.name]
    # tp1.timeline = ['Timeline5']
    logger.info("Traffic profile completed")

    # Traffic Maps
    """
    logger.info("Configuring Traffic Maps settings")
    tm1 = tp1.trafficmap.trafficmap()
    tm1[0].port_map_policy_name  = "custom"
    cust1 = tm1[0].custom.custom()
    cust1[0].name = "vlanRangePairs"
    mt1 = cust1[0].mapping_type
    mt1.vlan_range_pairs.enable = True
    #mt1.vlan_range_pairs.destination_id = 2
    end_trafficmaps_time = time.time()
    logger.info("Traffic map completed: {}".format(end_trafficmaps_time - start_time))
    """

    # Set config
    logger.info("Configuring custom settings")
    time_custom_time = time.time()
    response = api.set_config(config)  # noqa: F841
    port = connection_dict['port']

    time_custom_finish = time.time()
    logger.info("Custom settings completed: {}".format(time_custom_finish - time_custom_time))

    # Edit userIpMapping
    logger.info("Configuring userIpMapping settings")
    set_userIPMappings(api)
    logger.info("userIpMapping completed")

    logger.info("Configuring custom port settings")
    time_assignPort_time = time.time()
    assignPorts(api, ports_list)
    time_assignPort_finish = time.time()
    logger.info("Custom port settings completed: {}".format(time_assignPort_finish - time_assignPort_time))

    logger.info("Configuring port L1 settings")
    time_customl1_time = time.time()
    edit_l1_settings(api)
    time_customl1_finished = time.time()
    logger.info("Custom port L1 settings completed: {}".format(time_customl1_finished - time_customl1_time))

    # Here adjust Double Increment and vlanRange unique number
    logger.info("Configuring rangeList settings for client and server")
    test_rangeList_time = time.time()
    set_rangeList(api)
    test_rangeList_finish_time = time.time()
    logger.info("rangeList settings completed {}".format(test_rangeList_finish_time-test_rangeList_time))

    # Adjust Traffic Profile
    logger.info("Custom trafficmaps")
    test_trafficmaps_time = time.time()
    set_trafficMapProfile(api)
    test_trafficmaps_finish = time.time()
    logger.info("Finished traffic maps configuration {}".format(test_trafficmaps_finish - test_trafficmaps_time))

    # Set custom TCP parameters
    logger.info("Custom TCP settings")
    test_tcp_time = time.time()
    set_tcpCustom(api)
    test_tcp_finish_time = time.time()
    logger.info("Finished TCP configuration {}".format(test_tcp_finish_time - test_tcp_time))

    logger.info("Custom timeline settings")
    test_timeline_time = time.time()
    set_timelineCustom(api, initial_cps_value)
    test_timeline_finish = time.time()
    logger.info("Finished timeline configurations {}".format(test_timeline_finish - test_timeline_time))

    # save file
    # logger.info("Saving Test File")
    test_save_time = time.time()  # noqa: F841
    test_save_finish_time = time.time()  # noqa: F841
    # logger.info("Finished saving: {}".format(test_save_finish_time - test_save_time))
    main_finish_time = time.time()
    logger.info("Ixload configuration app finished in {}".format(main_finish_time - main_start_time))

    return api, config, initial_cps_value


def saveAs(api, test_filename):

    saveAs_operation = 'ixload/test/operations/saveAs'
    # url = "{}/{}".format(base_url, saveAs_operation)
    paramDict = {
        'fullPath': "C:\\automation\\{}.rxf".format(test_filename),
        'overWrite': True
    }

    # response = requests.post(url, data=json.dumps(paramDict), headers=headers)
    try:
        # Code that may raise an exception
        res = api.ixload_configure("post", saveAs_operation, paramDict)  # noqa: F841
    except Exception as e:
        # Handle any exception
        logger.info(f"An error occurred: {e}")

    return
