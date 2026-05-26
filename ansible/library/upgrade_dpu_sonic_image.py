#!/usr/bin/python

import logging
import os
import time
import paramiko
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.smartswitch_utils import smartswitch_hwsku_config
from ansible.module_utils.debug_utils import config_module_logging

DOCUMENTATION = '''
module:  upgrade_dpu_sonic_image
version_added:  "1.0"

short_description: Install a new SONiC image on one or all DPUs of a SmartSwitch

description:
    - Downloads the image on the NPU (which has lab network access), then transfers
      it to each DPU via SCP over the midplane network (169.254.200.x).
    - Cleans up old images, installs using sonic-installer, reboots the DPU.
    - Follows the same installation logic as reduce_and_add_sonic_images but executed
      remotely on DPUs via paramiko SSH (modeled after load_extra_dpu_config).

Options:
    - option-name: hwsku
      description: Hardware SKU of the SmartSwitch (determines DPU count)
      required: True
    - option-name: hostname
      description: NPU hostname (used for logging)
      required: True
    - option-name: host_username
      description: SSH username for the DPU
      required: True
    - option-name: host_passwords
      description: List of SSH passwords to try for the DPU
      required: True
    - option-name: new_image_url
      description: URL pointing to the new SONiC image to install on DPUs
      required: True
    - option-name: target_dpu_index
      description: Index of a specific DPU to upgrade (-1 for all DPUs)
      required: False
      Default: -1
    - option-name: disk_used_pcent
      description: Maximum disk used percentage threshold for cleanup
      required: False
      Default: 50
'''

config_module_logging("upgrade_dpu_sonic_image")

DPU_HOST_IP_BASE = "169.254.200.{}"
NPU_DOWNLOAD_PATH = "/tmp/dpu-sonic-image"
DPU_IMAGE_PATH = "/tmp/downloaded-sonic-image"

MAX_RETRIES = 5
RETRY_DELAY = 60
SUCCESS_THRESHOLD = 1.0

# Longer timeout for SCP transfer and install operations (20 minutes)
LONG_CMD_TIMEOUT = 1200
# Standard timeout for quick commands
SHORT_CMD_TIMEOUT = 120
# How long to wait for DPU to come back after startup
REBOOT_TIMEOUT = 600
# Poll interval while waiting for DPU reboot
REBOOT_POLL_INTERVAL = 30


class UpgradeDpuSonicImageModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                hwsku=dict(type='str', required=True),
                hostname=dict(type='str', required=True),
                host_username=dict(type='str', required=True),
                host_passwords=dict(type='list', elements='str', required=True, no_log=True),
                new_image_url=dict(type='str', required=True),
                target_dpu_index=dict(type='int', required=False, default=-1),
                disk_used_pcent=dict(type='int', required=False, default=50),
            ),
            supports_check_mode=False
        )

        self.messages = []

        self.hwsku = self.module.params['hwsku']
        self.hostname = self.module.params['hostname']
        self.host_username = self.module.params['host_username']
        self.host_passwords = self.module.params['host_passwords']
        self.new_image_url = self.module.params['new_image_url']
        self.target_dpu_index = self.module.params['target_dpu_index']
        self.disk_used_pcent = self.module.params['disk_used_pcent']

        self.log("Initializing: hostname={}, hwsku={}, image_url={}, target_dpu_index={}".format(
            self.hostname, self.hwsku, self.new_image_url, self.target_dpu_index))

        try:
            self.hwsku_config = smartswitch_hwsku_config[self.hwsku]
            self.dpu_num = self.hwsku_config.get('dpu_num', 0)
            self.log("HWSKU config: dpu_num={}".format(self.dpu_num))
            if self.dpu_num == 0:
                self.module.fail_json(msg="No DPUs defined for hwsku: {}".format(self.hwsku))
        except KeyError:
            self.module.fail_json(msg="No DPU configuration found for hwsku: {}".format(self.hwsku))

    def log(self, msg):
        """Log a timestamped message to both the messages list and the logging framework."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.messages.append("{} {}".format(timestamp, msg))
        logging.debug(msg)

    def connect_to_dpu(self, dpu_ip):
        """Establish an SSH connection to the DPU with retry."""
        retry_count = 0
        last_exception = None

        self.log("Connecting to DPU {} (max {} retries, {}s delay)".format(
            dpu_ip, MAX_RETRIES, RETRY_DELAY))

        while retry_count < MAX_RETRIES:
            for password in self.host_passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(dpu_ip, username=self.host_username, password=password, timeout=30)
                    self.log("SSH connected to DPU {} on attempt {}".format(
                        dpu_ip, retry_count + 1))
                    return ssh
                except Exception as e:
                    last_exception = e
                    continue

            retry_count += 1
            if retry_count < MAX_RETRIES:
                self.log("SSH to DPU {} failed (attempt {}/{}), retrying in {}s: {}".format(
                    dpu_ip, retry_count, MAX_RETRIES, RETRY_DELAY, str(last_exception)))
                time.sleep(RETRY_DELAY)

        self.log("WARNING: Failed to connect to DPU {} after {} retries: {}".format(
            dpu_ip, MAX_RETRIES, str(last_exception)))
        return None

    def execute_command(self, ssh, dpu_ip, command, timeout=SHORT_CMD_TIMEOUT, get_pty=False):
        """Execute a command on the DPU via SSH and return (success, stdout, stderr)."""
        try:
            self.log("[DPU {}] Running: {} (timeout={}s)".format(dpu_ip, command, timeout))
            start_time = time.time()
            _, stdout, stderr = ssh.exec_command(command, timeout=timeout, get_pty=get_pty)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            elapsed = time.time() - start_time
            if exit_code != 0:
                self.log("WARNING: [DPU {}] Command failed (rc={}, {:.1f}s): {} | stderr: {}".format(
                    dpu_ip, exit_code, elapsed, command, err.strip()))
                return False, out, err
            self.log("[DPU {}] Command succeeded ({:.1f}s): {}".format(
                dpu_ip, elapsed, command))
            return True, out, err
        except Exception as e:
            self.log("WARNING: [DPU {}] Exception running '{}': {}".format(dpu_ip, command, str(e)))
            return False, "", str(e)

    def reduce_installed_images(self, ssh, dpu_ip):
        """Clean up old SONiC images on the DPU, keeping only the current image."""
        self.log("[DPU {}] Step: Reducing installed images".format(dpu_ip))

        ok = False
        out = ""
        for attempt in range(3):
            ok, out, _ = self.execute_command(ssh, dpu_ip, "sudo sonic-installer list")
            if ok:
                break
            self.log("[DPU {}] sonic-installer list failed (attempt {}/3), retrying in 20s".format(
                dpu_ip, attempt + 1))
            time.sleep(20)

        if not ok:
            self.log("WARNING: [DPU {}] Failed to list images after 3 attempts. Continuing anyway.".format(dpu_ip))
            return

        curr_image = ""
        next_image = ""
        for line in out.split('\n'):
            if 'Current:' in line:
                curr_image = line.split(':')[1].strip()
            elif 'Next:' in line:
                next_image = line.split(':')[1].strip()

        self.log("[DPU {}] Current image: '{}', Next image: '{}'".format(
            dpu_ip, curr_image, next_image))

        if not curr_image:
            self.log("WARNING: [DPU {}] Could not determine current image".format(dpu_ip))
            return

        if curr_image != next_image and next_image:
            self.log("[DPU {}] Setting next-boot to current image".format(dpu_ip))
            self.execute_command(ssh, dpu_ip,
                                 "sudo sonic-installer set-next-boot {}".format(curr_image))

        self.execute_command(ssh, dpu_ip, "sudo sonic-installer cleanup -y")
        self.log("[DPU {}] Done reducing images".format(dpu_ip))

    def free_up_disk_space(self, ssh, dpu_ip):
        """Remove old logs, core dumps, and other expendable files on the DPU."""
        self.log("[DPU {}] Step: Checking disk space".format(dpu_ip))

        should_cleanup = True
        ok, out, _ = self.execute_command(ssh, dpu_ip, "df -BM --output=pcent /host")
        if ok:
            try:
                used_pcent = int(out.splitlines()[-1].strip().rstrip('%'))
                if used_pcent <= self.disk_used_pcent:
                    self.log("[DPU {}] Disk usage {}% <= threshold {}%, no cleanup needed".format(
                        dpu_ip, used_pcent, self.disk_used_pcent))
                    should_cleanup = False
                else:
                    self.log("[DPU {}] Disk usage {}% > threshold {}%, cleaning up".format(
                        dpu_ip, used_pcent, self.disk_used_pcent))
            except (ValueError, IndexError):
                self.log("[DPU {}] Could not parse disk usage, performing cleanup as precaution".format(dpu_ip))
        else:
            self.log("[DPU {}] Could not check disk usage, performing cleanup as precaution".format(dpu_ip))

        if not should_cleanup:
            return

        cleanup_cmds = [
            "sudo rm -f /var/log/*.gz",
            "sudo rm -f /var/core/*",
            "sudo rm -rf /var/dump/*",
            "sudo rm -rf /home/admin/*",
            "sudo rm -rf /host/logs_before_reboot/*",
        ]
        for cmd in cleanup_cmds:
            self.execute_command(ssh, dpu_ip, cmd)

        self.log("[DPU {}] Done freeing disk space".format(dpu_ip))

    def download_image_on_npu(self):
        """Download the SONiC image on the NPU using curl."""
        self.log("Downloading DPU image on NPU from {}".format(self.new_image_url))
        start_time = time.time()
        rc, out, err = self.module.run_command(
            "curl -fLo {} {}".format(NPU_DOWNLOAD_PATH, self.new_image_url),
            use_unsafe_shell=True
        )
        elapsed = time.time() - start_time
        if rc != 0:
            self.module.fail_json(
                msg="Failed to download image on NPU ({:.1f}s): rc={}, err={}".format(elapsed, rc, err))
        if not os.path.exists(NPU_DOWNLOAD_PATH):
            self.module.fail_json(msg="Downloaded image not found at {}".format(NPU_DOWNLOAD_PATH))
        size = os.path.getsize(NPU_DOWNLOAD_PATH)
        self.log("Image downloaded on NPU: {} bytes in {:.1f}s ({:.1f} MB/s)".format(
            size, elapsed, size / 1024 / 1024 / max(elapsed, 0.1)))

    def cleanup_npu_image(self):
        """Remove the downloaded image from the NPU."""
        self.module.run_command("rm -f {}".format(NPU_DOWNLOAD_PATH))

    def scp_image_to_dpu(self, dpu_ip):
        """Transfer the image from NPU to DPU using paramiko SFTP over the midplane."""
        src_size = os.path.getsize(NPU_DOWNLOAD_PATH)
        self.log("[DPU {}] Step: SCP transfer ({:.1f} MB) to {}".format(
            dpu_ip, src_size / 1024 / 1024, DPU_IMAGE_PATH))
        ssh = self.connect_to_dpu(dpu_ip)
        if not ssh:
            return False
        try:
            start_time = time.time()
            with ssh.open_sftp() as sftp:
                sftp.put(NPU_DOWNLOAD_PATH, DPU_IMAGE_PATH)
            elapsed = time.time() - start_time
            self.log("[DPU {}] SCP transfer succeeded in {:.1f}s ({:.1f} MB/s)".format(
                dpu_ip, elapsed, src_size / 1024 / 1024 / max(elapsed, 0.1)))
            return True
        except Exception as e:
            self.log("WARNING: [DPU {}] SCP transfer failed: {}".format(dpu_ip, str(e)))
            return False
        finally:
            ssh.close()

    def install_image_on_dpu(self, ssh, dpu_ip):
        """Transfer the image from NPU to DPU via SCP and install it."""
        self.log("[DPU {}] Step: Install image".format(dpu_ip))

        # Clean up any previous download
        self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DPU_IMAGE_PATH))

        # Transfer image from NPU to DPU
        if not self.scp_image_to_dpu(dpu_ip):
            return False

        # Check for --skip-package-migration support
        skip_param = ""
        ok, help_out, _ = self.execute_command(ssh, dpu_ip, "sudo sonic-installer install --help")
        if "skip-package-migration" in help_out:
            skip_param = "--skip-package-migration"
            self.log("[DPU {}] Using --skip-package-migration".format(dpu_ip))

        # Install the image
        self.log("[DPU {}] Running sonic-installer install (timeout={}s)".format(
            dpu_ip, LONG_CMD_TIMEOUT))
        ok, out, err = self.execute_command(
            ssh, dpu_ip,
            "sudo sonic-installer install {} {} -y".format(DPU_IMAGE_PATH, skip_param),
            timeout=LONG_CMD_TIMEOUT,
            get_pty=True
        )

        # Clean up downloaded image
        self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DPU_IMAGE_PATH))

        if not ok:
            self.log("WARNING: [DPU {}] Image installation FAILED: {}".format(dpu_ip, err.strip()))
            return False

        self.log("[DPU {}] Image installed successfully".format(dpu_ip))
        return True

    def verify_installed_image(self, ssh, dpu_ip, dpu_index):
        """Log the current and next boot image versions after upgrade."""
        ok, out, _ = self.execute_command(ssh, dpu_ip, "sudo sonic-installer list")
        if not ok:
            self.log("WARNING: [DPU{}] Could not verify installed image version".format(dpu_index))
            return

        for line in out.split('\n'):
            line = line.strip()
            if line.startswith("Current:") or line.startswith("Next:"):
                self.log("[DPU{}] {}".format(dpu_index, line))

    def reboot_dpu(self, dpu_index):
        """Reboot DPU by shutting down and starting it via NPU chassis module commands."""
        dpu_name = "DPU{}".format(dpu_index)
        self.log("[DPU{}] Step: Rebooting via chassis module shutdown/startup".format(dpu_index))

        rc, out, err = self.module.run_command("config chassis modules shutdown {}".format(dpu_name))
        if rc != 0:
            self.log("WARNING: [DPU{}] shutdown failed (rc={}): stdout={} stderr={}".format(
                dpu_index, rc, out.strip(), err.strip()))
            return False

        self.log("[DPU{}] Shutdown issued, waiting 60s before startup".format(dpu_index))
        time.sleep(60)

        rc, out, err = self.module.run_command("config chassis modules startup {}".format(dpu_name))
        if rc != 0:
            self.log("WARNING: [DPU{}] startup failed (rc={}): stdout={} stderr={}".format(
                dpu_index, rc, out.strip(), err.strip()))
            return False

        self.log("[DPU{}] Startup issued successfully".format(dpu_index))
        return True

    def remove_known_host(self, dpu_ip):
        """Remove DPU entry from SSH known_hosts on the NPU after reboot."""
        self.log("Removing {} from SSH known_hosts for root and admin".format(dpu_ip))
        self.module.run_command("ssh-keygen -R {}".format(dpu_ip))
        self.module.run_command(
            "sudo -u admin ssh-keygen -R {} -f /home/admin/.ssh/known_hosts".format(dpu_ip)
        )

    def wait_for_dpu_reboot(self, dpu_ip):
        """Wait for a DPU to become reachable again after reboot."""
        self.log("[DPU {}] Step: Waiting up to {}s for DPU to come back".format(
            dpu_ip, REBOOT_TIMEOUT))

        elapsed = 0
        while elapsed < REBOOT_TIMEOUT:
            ssh = None
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                for password in self.host_passwords:
                    try:
                        ssh.connect(dpu_ip, username=self.host_username,
                                    password=password, timeout=15)
                        self.log("[DPU {}] Back online after {}s".format(dpu_ip, elapsed))
                        ssh.close()
                        return True
                    except Exception as e:
                        self.log("SSH connection to DPU {} failed during reboot wait: {}".format(dpu_ip, str(e)))
                        continue
            except Exception as e:
                self.log("Exception while waiting for DPU {} to reboot: {}".format(dpu_ip, str(e)))
            finally:
                if ssh:
                    try:
                        ssh.close()
                    except Exception as e:
                        self.log("Exception while closing SSH connection to DPU {}: {}".format(dpu_ip, str(e)))

            time.sleep(REBOOT_POLL_INTERVAL)
            elapsed += REBOOT_POLL_INTERVAL
            if elapsed % 120 == 0:
                self.log("[DPU {}] Still waiting... {}s/{}s elapsed".format(
                    dpu_ip, elapsed, REBOOT_TIMEOUT))

        self.log("WARNING: [DPU {}] Did NOT come back within {}s".format(dpu_ip, REBOOT_TIMEOUT))
        return False

    def get_dpu_online_mid_plane_up_counts(self):
        """Return (online_count, midplane_up_count) from NPU system health."""
        cmd = "show system-health dpu all"
        rc, out, err = self.module.run_command(cmd)
        if rc != 0:
            self.log("WARNING: Failed to get DPU health (rc={}): {}".format(rc, err))
            return 0, 0

        online_count = 0
        midplane_up_count = 0
        for line in out.split("\n"):
            if "up" in line and "dpu_midplane_link_state" in line:
                midplane_up_count += 1
            if line.startswith("DPU") and "Online" in line:
                online_count += 1

        self.log("DPU health: {} online, {} midplane up".format(online_count, midplane_up_count))
        return online_count, midplane_up_count

    def wait_for_dpu_count_fully_online(self, required_count):
        """Wait until at least required_count DPUs report 'Online' status."""
        retry_count = 0
        while retry_count < MAX_RETRIES:
            online, _ = self.get_dpu_online_mid_plane_up_counts()
            if online >= required_count:
                return True
            self.log("Waiting for {} DPUs online (currently {})".format(
                required_count, online))
            time.sleep(RETRY_DELAY)
            retry_count += 1
        return False

    def upgrade_single_dpu(self, dpu_index):
        """Upgrade a single DPU. Returns True on success."""
        dpu_ip = DPU_HOST_IP_BASE.format(dpu_index + 1)
        start_time = time.time()
        self.log("========== Starting upgrade of DPU{} at {} ==========".format(dpu_index, dpu_ip))

        ssh = self.connect_to_dpu(dpu_ip)
        if not ssh:
            self.log("WARNING: [DPU{}] FAILED: Could not establish SSH connection".format(dpu_index))
            return False

        try:
            self.reduce_installed_images(ssh, dpu_ip)
            self.free_up_disk_space(ssh, dpu_ip)

            if not self.install_image_on_dpu(ssh, dpu_ip):
                self.log("WARNING: [DPU{}] FAILED: Image installation failed".format(dpu_index))
                return False
        except Exception as e:
            self.log("WARNING: [DPU{}] FAILED: Exception during upgrade: {}".format(dpu_index, str(e)))
            return False
        finally:
            try:
                ssh.close()
            except Exception as e:
                self.log("WARNING: [DPU{}] Exception while closing SSH connection: {}".format(dpu_index, str(e)))

        if not self.reboot_dpu(dpu_index):
            self.log("WARNING: [DPU{}] FAILED: Reboot command failed".format(dpu_index))
            return False

        self.remove_known_host(dpu_ip)

        if not self.wait_for_dpu_reboot(dpu_ip):
            self.log("WARNING: [DPU{}] FAILED: Did not come back after reboot".format(dpu_index))
            return False

        # Clean up old images after reboot and verify the new version
        ssh = self.connect_to_dpu(dpu_ip)
        if ssh:
            try:
                self.reduce_installed_images(ssh, dpu_ip)
                self.verify_installed_image(ssh, dpu_ip, dpu_index)
            finally:
                try:
                    ssh.close()
                except Exception as e:
                    self.log("WARNING: [DPU{}] Exception while closing SSH connection: {}".format(dpu_index, str(e)))
        else:
            self.log("WARNING: [DPU{}] Could not connect for post-reboot image cleanup".format(dpu_index))

        elapsed = time.time() - start_time
        self.log("========== DPU{} upgrade SUCCEEDED ({:.0f}s) ==========".format(
            dpu_index, elapsed))
        return True

    def upgrade_dpus(self):
        """Upgrade all targeted DPUs and return (success_count, failure_count)."""
        if self.target_dpu_index >= 0:
            if self.target_dpu_index >= self.dpu_num:
                self.module.fail_json(
                    msg="target_dpu_index {} out of range (dpu_num={})".format(
                        self.target_dpu_index, self.dpu_num))
            dpu_indices = [self.target_dpu_index]
        else:
            dpu_indices = list(range(self.dpu_num))

        total = len(dpu_indices)
        required = max(1, int(total * SUCCESS_THRESHOLD))
        success_count = 0
        failure_count = 0
        results_per_dpu = {}

        self.download_image_on_npu()

        self.log("===== DPU upgrade: {} DPU(s) to upgrade, {} required for success =====".format(
            total, required))

        try:
            for idx in dpu_indices:
                if self.upgrade_single_dpu(idx):
                    success_count += 1
                    results_per_dpu[idx] = "SUCCESS"
                else:
                    failure_count += 1
                    results_per_dpu[idx] = "FAILED"
                self.log("Progress: {}/{} complete ({} succeeded, {} failed)".format(
                    success_count + failure_count, total, success_count, failure_count))
        finally:
            self.cleanup_npu_image()

        self.log("DPU upgrade results: {}".format(results_per_dpu))

        self.log("Verifying DPU online status after upgrades")
        if not self.wait_for_dpu_count_fully_online(success_count):
            self.log("WARNING: Not all upgraded DPUs came fully online")

        if success_count < required:
            self.module.fail_json(
                msg="DPU upgrade failed: {}/{} succeeded (required {})".format(
                    success_count, total, required),
                success_count=success_count,
                failure_count=failure_count,
                total_dpus=total,
                messages=self.messages)

        return success_count, failure_count

    def run(self):
        success_count, failure_count = self.upgrade_dpus()
        total = success_count + failure_count

        if failure_count == 0:
            msg = "Successfully upgraded all {} DPU(s)".format(success_count)
        else:
            msg = ("Upgraded {} of {} DPU(s) ({} failures, "
                   "met success threshold)").format(success_count, total, failure_count)

        self.module.exit_json(
            changed=True,
            msg=msg,
            success_count=success_count,
            failure_count=failure_count,
            total_dpus=total,
            messages=self.messages)


def main():
    module = UpgradeDpuSonicImageModule()
    module.run()


if __name__ == '__main__':
    main()
