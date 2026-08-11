#!/usr/bin/python

import logging
import os
import threading
import shlex
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    - Skips DPUs whose CHASSIS_MODULE admin_status is down.
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
    - option-name: max_parallel_dpus
      description: >-
        Maximum number of DPUs to upgrade concurrently. -1 (default) upgrades all
        targeted DPUs in parallel; a positive integer caps concurrency (1 = sequential).
        0 and values less than -1 are rejected.
      required: False
      Default: -1
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
# Extra /host headroom (MB) required beyond the image size before a DPU install
DPU_INSTALL_MARGIN_MB = 500
# Minimum plausible initrd size (bytes); anything smaller means a corrupt image
DPU_MIN_INITRD_BYTES = 1024 * 1024
# Max wait for a chassis-module state transition to clear (startup/shutdown no-op while set)
MODULE_TRANSITION_TIMEOUT = 300
# Poll interval while waiting for a chassis-module transition to clear
MODULE_TRANSITION_POLL_INTERVAL = 5
# Grace period after shutdown for chassisd to register the transition before polling
MODULE_TRANSITION_SETTLE = 10


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
                max_parallel_dpus=dict(type='int', required=False, default=-1),
            ),
            supports_check_mode=False
        )

        self.messages = []
        # Locks for thread-safe parallel DPU upgrades: _log_lock guards the shared
        # messages list; _cli_lock serializes NPU-side commands that touch shared
        # state (chassis module config and the SSH known_hosts files).
        self._log_lock = threading.Lock()
        self._cli_lock = threading.Lock()

        self.hwsku = self.module.params['hwsku']
        self.hostname = self.module.params['hostname']
        self.host_username = self.module.params['host_username']
        self.host_passwords = self.module.params['host_passwords']
        self.new_image_url = self.module.params['new_image_url']
        self.target_dpu_index = self.module.params['target_dpu_index']
        self.disk_used_pcent = self.module.params['disk_used_pcent']
        self.max_parallel_dpus = self.module.params['max_parallel_dpus']
        if self.max_parallel_dpus == 0 or self.max_parallel_dpus < -1:
            self.module.fail_json(
                msg="Invalid max_parallel_dpus={}: use -1 to upgrade all DPUs in parallel "
                    "or a positive integer to cap concurrency (1 = sequential)".format(
                        self.max_parallel_dpus))

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
        with self._log_lock:
            self.messages.append("{} {}".format(timestamp, msg))
        # logging is thread-safe on its own, so keep it outside the lock to avoid
        # serializing all threads on the frequent per-DPU log calls.
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

    def get_installed_images(self, ssh, dpu_ip, attempts=3):
        """Return (ok, current, next) from sonic-installer list, retrying transient failures."""
        ok = False
        out = ""
        for attempt in range(attempts):
            ok, out, _ = self.execute_command(ssh, dpu_ip, "sudo sonic-installer list")
            if ok:
                break
            self.log("[DPU {}] sonic-installer list failed (attempt {}/{}), retrying in 20s".format(
                dpu_ip, attempt + 1, attempts))
            time.sleep(20)
        curr = nxt = ""
        for line in out.split('\n'):
            if 'Current:' in line:
                curr = line.split(':', 1)[1].strip().lstrip('/')
            elif 'Next:' in line:
                nxt = line.split(':', 1)[1].strip().lstrip('/')
        return ok, curr, nxt

    def get_host_avail_mb(self, ssh, dpu_ip):
        """Return free MB on /host, or None if it cannot be read/parsed."""
        ok, out, _ = self.execute_command(ssh, dpu_ip, "df -BM --output=avail /host")
        if not ok:
            return None
        try:
            return int(out.splitlines()[-1].strip().rstrip('M'))
        except (ValueError, IndexError):
            return None

    def get_host_path_size_mb(self, ssh, dpu_ip, path):
        """Return du -sm size (MB) of a /host path, or None if it cannot be read/parsed."""
        ok, out, _ = self.execute_command(ssh, dpu_ip, "sudo du -sm -- {}".format(shlex.quote(path)))
        if not ok:
            return None
        try:
            return int(out.split()[0])
        except (ValueError, IndexError):
            return None

    def reduce_installed_images(self, ssh, dpu_ip):
        """Free disk space without removing an image referenced by the bootloader."""
        self.log("[DPU {}] Step: Reducing installed images".format(dpu_ip))

        list_ok, curr_image, next_image = self.get_installed_images(ssh, dpu_ip)
        if not (list_ok and curr_image and next_image):
            self.log("WARNING: [DPU {}] Could not list images after retries; "
                     "skipping cleanup to protect the boot image".format(dpu_ip))
            return False

        self.log("[DPU {}] Current image: '{}', Next image: '{}'".format(
            dpu_ip, curr_image, next_image))
        if curr_image != next_image:
            self.log("[DPU {}] Making current image the persistent and one-time boot target".format(dpu_ip))
            if not self.prepare_image_for_reboot(ssh, dpu_ip, curr_image):
                self.log("WARNING: [DPU {}] Could not protect current image before cleanup".format(dpu_ip))
                return False

        cleaned = False
        for attempt in range(3):
            cleaned, _, err = self.execute_command(ssh, dpu_ip, "sudo sonic-installer cleanup -y")
            if cleaned:
                break
            self.log("[DPU {}] sonic-installer cleanup failed (attempt {}/3), retrying in 20s: {}".format(
                dpu_ip, attempt + 1, err.strip()))
            time.sleep(20)

        if not cleaned:
            self.log("WARNING: [DPU {}] sonic-installer cleanup did not succeed after 3 attempts".format(dpu_ip))
            return False
        self.log("[DPU {}] Done reducing images".format(dpu_ip))
        return True

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

    def restore_boot_to_current(self, ssh, dpu_ip, curr_image, next_image):
        """Point default and next-boot back at the current image so a reboot can't land on a bad image."""
        if curr_image and curr_image != next_image:
            self.log("[DPU {}] Restoring default and next boot to current image '{}'".format(
                dpu_ip, curr_image))
            if not self.prepare_image_for_reboot(ssh, dpu_ip, curr_image):
                self.log("WARNING: [DPU {}] Failed to restore current image boot target".format(dpu_ip))

    def prepare_image_for_reboot(self, ssh, dpu_ip, image):
        """Persist an image as both the default and one-time boot target, then verify it."""
        # Pensando DPUs use U-Boot; platforms without its tools use the sonic-installer path below.
        uboot_slot_cmd = (
            "if command -v fw_printenv >/dev/null 2>&1 && command -v fw_setenv >/dev/null 2>&1; then "
            "printf '%s\\n' \"$(fw_printenv -n sonic_version_1 2>/dev/null || true)\" "
            "\"$(fw_printenv -n sonic_version_2 2>/dev/null || true)\"; "
            "else echo __NOT_UBOOT__; fi"
        )
        slot_ok, slot_out, slot_err = self.execute_command(ssh, dpu_ip, uboot_slot_cmd)
        if not slot_ok:
            self.log("WARNING: [DPU {}] Failed to read boot slots for '{}': {}".format(
                dpu_ip, image, slot_err.strip()))
            return False

        slots = slot_out.splitlines()
        if slots != ["__NOT_UBOOT__"]:
            matching_slots = [index for index, version in enumerate(slots[:2], 1) if version == image]
            if len(matching_slots) != 1:
                self.log("WARNING: [DPU {}] Image '{}' maps to {} U-Boot slots; refusing reboot".format(
                    dpu_ip, image, len(matching_slots)))
                return False

            boot_target = "run sonic_image_{}".format(matching_slots[0])
            quoted_target = shlex.quote(boot_target)
            for variable in ("boot_next", "boot_once"):
                ok, _, err = self.execute_command(
                    ssh, dpu_ip, "sudo fw_setenv {} {}".format(variable, quoted_target))
                if not ok:
                    self.log("WARNING: [DPU {}] Failed to set {} to '{}': {}".format(
                        dpu_ip, variable, boot_target, err.strip()))
                    return False

            sync_ok, _, sync_err = self.execute_command(ssh, dpu_ip, "sudo sync")
            if not sync_ok:
                self.log("WARNING: [DPU {}] Failed to persist U-Boot selection for '{}': {}".format(
                    dpu_ip, image, sync_err.strip()))
                return False

            verify_cmd = "fw_printenv -n boot_next"
            verify_ok, verify_out, verify_err = self.execute_command(ssh, dpu_ip, verify_cmd)
            if not verify_ok or verify_out.strip() != boot_target:
                self.log("WARNING: [DPU {}] U-Boot target verification failed for '{}': {}".format(
                    dpu_ip, image, verify_err.strip() or verify_out.strip()))
                return False
            return True

        quoted_image = shlex.quote(image)
        default_ok, _, default_err = self.execute_command(
            ssh, dpu_ip, "sudo sonic-installer set-default {}".format(quoted_image))
        if not default_ok:
            self.log("WARNING: [DPU {}] Failed to persist default image '{}': {}".format(
                dpu_ip, image, default_err.strip()))
            return False

        next_ok, _, next_err = self.execute_command(
            ssh, dpu_ip, "sudo sonic-installer set-next-boot {}".format(quoted_image))
        if not next_ok:
            self.log("WARNING: [DPU {}] Failed to set one-time boot image '{}': {}".format(
                dpu_ip, image, next_err.strip()))
            return False

        sync_ok, _, sync_err = self.execute_command(ssh, dpu_ip, "sudo sync")
        if not sync_ok:
            self.log("WARNING: [DPU {}] Failed to persist boot selection for '{}': {}".format(
                dpu_ip, image, sync_err.strip()))
            return False

        list_ok, _, next_image = self.get_installed_images(ssh, dpu_ip)
        if not list_ok or next_image != image:
            self.log("WARNING: [DPU {}] Persistent boot target is '{}' instead of '{}'".format(
                dpu_ip, next_image, image))
            return False
        return True

    def install_image_on_dpu(self, ssh, dpu_ip):
        """Transfer the image from NPU to DPU via SCP and install it."""
        self.log("[DPU {}] Step: Install image".format(dpu_ip))

        # Clean up any previous download
        self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DPU_IMAGE_PATH))

        # Transfer image from NPU to DPU
        if not self.scp_image_to_dpu(dpu_ip):
            return False

        # Skip install if /host lacks room for the extracted image, failing safe instead of bricking the DPU
        _, curr_image, _ = self.get_installed_images(ssh, dpu_ip)
        cur_dir = "/host/image-{}".format(curr_image.replace("SONiC-OS-", "")) if curr_image else ""
        proxy_mb = self.get_host_path_size_mb(ssh, dpu_ip, cur_dir) if cur_dir else None
        avail_mb = self.get_host_avail_mb(ssh, dpu_ip)
        if proxy_mb is None or avail_mb is None:
            self.log("WARNING: [DPU {}] Could not determine /host free space or image footprint; "
                     "skipping install to avoid a corrupt image".format(dpu_ip))
            self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DPU_IMAGE_PATH))
            return False
        required_mb = proxy_mb + DPU_INSTALL_MARGIN_MB
        if avail_mb < required_mb:
            self.log("WARNING: [DPU {}] Insufficient /host space: {}M free < {}M required "
                     "({}M image + {}M margin); skipping install to avoid a corrupt image".format(
                         dpu_ip, avail_mb, required_mb, proxy_mb, DPU_INSTALL_MARGIN_MB))
            self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DPU_IMAGE_PATH))
            return False
        self.log("[DPU {}] /host free {}M >= required {}M".format(dpu_ip, avail_mb, required_mb))

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

        list_ok, curr_image, next_image = self.get_installed_images(ssh, dpu_ip)
        if not (list_ok and next_image):
            self.log("WARNING: [DPU {}] Could not read image list after install; "
                     "failing safe (not rebooting into an unverified image)".format(dpu_ip))
            return False
        img_dir = "/host/image-{}".format(next_image.replace("SONiC-OS-", ""))
        _, initrd_out, _ = self.execute_command(
            ssh, dpu_ip,
            "sudo sh -c 'stat -c %s {}/boot/initrd.img-* 2>/dev/null | sort -n | tail -1'".format(img_dir))
        try:
            initrd_bytes = int(initrd_out.strip() or "0")
        except ValueError:
            initrd_bytes = 0
        if initrd_bytes < DPU_MIN_INITRD_BYTES:
            self.log("WARNING: [DPU {}] Post-install check FAILED for '{}': initrd missing/truncated "
                     "({} bytes); not rebooting into a corrupt image".format(dpu_ip, next_image, initrd_bytes))
            self.restore_boot_to_current(ssh, dpu_ip, curr_image, next_image)
            return False
        self.log("[DPU {}] Post-install check OK for '{}': initrd {} bytes".format(
            dpu_ip, next_image, initrd_bytes))

        if not self.prepare_image_for_reboot(ssh, dpu_ip, next_image):
            self.log("WARNING: [DPU {}] Boot selection verification failed; not rebooting".format(dpu_ip))
            self.restore_boot_to_current(ssh, dpu_ip, curr_image, next_image)
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

    def is_module_transition_in_progress(self, dpu_index):
        """Return True if the DPU chassis module has a state transition in progress."""
        dpu_name = "DPU{}".format(dpu_index)
        cmd = 'sonic-db-cli STATE_DB HGET "CHASSIS_MODULE_TABLE|{}" transition_in_progress'.format(dpu_name)
        with self._cli_lock:
            rc, out, err = self.module.run_command(cmd)
        if rc != 0:
            self.log("WARNING: [DPU{}] Failed to read transition_in_progress (rc={}): {}".format(
                dpu_index, rc, err.strip()))
            return False
        return out.strip().lower() == "true"

    def wait_for_module_transition_done(self, dpu_index, settle=0,
                                        timeout=MODULE_TRANSITION_TIMEOUT):
        """Wait until the DPU chassis-module state transition has cleared (True) or timeout (False)."""
        if settle:
            time.sleep(settle)
        elapsed = 0
        while elapsed < timeout:
            if not self.is_module_transition_in_progress(dpu_index):
                return True
            time.sleep(MODULE_TRANSITION_POLL_INTERVAL)
            elapsed += MODULE_TRANSITION_POLL_INTERVAL
            if elapsed % 60 == 0:
                self.log("[DPU{}] Still waiting for module transition to clear... {}s/{}s".format(
                    dpu_index, elapsed, timeout))
        self.log("WARNING: [DPU{}] Module state transition still in progress after {}s".format(
            dpu_index, timeout))
        return False

    def reboot_dpu(self, dpu_index):
        """Reboot DPU by shutting down and starting it via NPU chassis module commands."""
        dpu_name = "DPU{}".format(dpu_index)
        self.log("[DPU{}] Step: Rebooting via chassis module shutdown/startup".format(dpu_index))

        # A prior transition must clear first or the shutdown CLI is a no-op (rc=0).
        if not self.wait_for_module_transition_done(dpu_index):
            self.log("WARNING: [DPU{}] Prior transition did not clear; aborting reboot".format(dpu_index))
            return False

        with self._cli_lock:
            rc, out, err = self.module.run_command("config chassis modules shutdown {}".format(dpu_name))
        if rc != 0:
            self.log("WARNING: [DPU{}] shutdown failed (rc={}): stdout={} stderr={}".format(
                dpu_index, rc, out.strip(), err.strip()))
            return False
        # shutdown returns rc=0 even when it no-ops mid-transition, so detect that here
        if "transition is already in progress" in (out or "").lower():
            self.log("WARNING: [DPU{}] shutdown ignored, transition still in progress: {}".format(
                dpu_index, out.strip()))
            return False

        # Wait for the shutdown transition to clear (startup no-ops while a transition is in progress)
        self.log("[DPU{}] Shutdown issued, waiting for module transition to clear".format(dpu_index))
        if not self.wait_for_module_transition_done(dpu_index, settle=MODULE_TRANSITION_SETTLE):
            self.log("WARNING: [DPU{}] Transition still in progress; startup may be ignored".format(
                dpu_index))

        with self._cli_lock:
            rc, out, err = self.module.run_command("config chassis modules startup {}".format(dpu_name))
        if rc != 0:
            self.log("WARNING: [DPU{}] startup failed (rc={}): stdout={} stderr={}".format(
                dpu_index, rc, out.strip(), err.strip()))
            return False

        # startup returns rc=0 even when it no-ops mid-transition, so detect that here
        if "transition is already in progress" in (out or "").lower():
            self.log("WARNING: [DPU{}] startup ignored, transition still in progress: {}".format(
                dpu_index, out.strip()))
            return False

        self.log("[DPU{}] Startup issued successfully".format(dpu_index))
        return True

    def remove_known_host(self, dpu_ip):
        """Remove DPU entry from SSH known_hosts on the NPU after reboot."""
        self.log("Removing {} from SSH known_hosts for root and admin".format(dpu_ip))
        with self._cli_lock:
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
            if not self.reduce_installed_images(ssh, dpu_ip):
                self.log("WARNING: [DPU{}] FAILED: Could not safely clean installed images".format(dpu_index))
                return False
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

    def _resolve_worker_count(self, num_dpus):
        """Determine how many DPUs to upgrade concurrently.

        max_parallel_dpus < 0 (default) upgrades all targeted DPUs in parallel; a
        positive value caps concurrency; 1 restores fully sequential behavior.
        """
        if num_dpus <= 0:
            return 1
        if self.max_parallel_dpus is None or self.max_parallel_dpus < 0:
            return num_dpus
        return max(1, min(self.max_parallel_dpus, num_dpus))

    def get_admin_up_dpu_indices(self, dpu_indices):
        """Return targeted DPUs whose CONFIG_DB admin status is up."""
        admin_up_dpus = []
        skipped_dpus = []

        for dpu_index in dpu_indices:
            dpu_name = "DPU{}".format(dpu_index)
            cmd = 'sonic-db-cli CONFIG_DB HGET "CHASSIS_MODULE|{}" admin_status'.format(dpu_name)
            with self._cli_lock:
                rc, out, err = self.module.run_command(cmd)

            if rc != 0:
                self.module.fail_json(
                    msg="Failed to read admin status for {}: rc={}, err={}".format(
                        dpu_name, rc, err.strip()))

            admin_status = out.strip().lower()
            if admin_status == "up":
                admin_up_dpus.append(dpu_index)
            elif admin_status == "down":
                skipped_dpus.append(dpu_index)
                self.log("[DPU{}] Skipping upgrade because admin_status is down".format(dpu_index))
            else:
                self.module.fail_json(
                    msg="Invalid or missing admin status '{}' for {}".format(
                        admin_status, dpu_name))

        return admin_up_dpus, skipped_dpus

    def upgrade_dpus(self):
        """Upgrade admin-up targeted DPUs and return success, failure, and skipped counts."""
        if self.target_dpu_index >= 0:
            if self.target_dpu_index >= self.dpu_num:
                self.module.fail_json(
                    msg="target_dpu_index {} out of range (dpu_num={})".format(
                        self.target_dpu_index, self.dpu_num))
            dpu_indices = [self.target_dpu_index]
        else:
            dpu_indices = list(range(self.dpu_num))

        dpu_indices, skipped_dpus = self.get_admin_up_dpu_indices(dpu_indices)
        total = len(dpu_indices)
        if total == 0:
            self.log("No admin-up DPUs targeted for upgrade; skipped {} admin-down DPU(s)".format(
                len(skipped_dpus)))
            return 0, 0, skipped_dpus

        required = max(1, int(total * SUCCESS_THRESHOLD))
        success_count = 0
        failure_count = 0
        results_per_dpu = {}

        self.download_image_on_npu()

        self.log("===== DPU upgrade: {} DPU(s) to upgrade, {} required for success =====".format(
            total, required))

        workers = self._resolve_worker_count(len(dpu_indices))
        self.log("Upgrading {} DPU(s) with up to {} in parallel".format(total, workers))

        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_idx = {
                    executor.submit(self.upgrade_single_dpu, idx): idx
                    for idx in dpu_indices
                }
                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        succeeded = future.result()
                    except Exception as e:
                        succeeded = False
                        self.log("WARNING: [DPU{}] Exception during parallel upgrade: {}".format(idx, str(e)))
                    if succeeded:
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
                skipped_dpus=skipped_dpus,
                messages=self.messages)

        return success_count, failure_count, skipped_dpus

    def run(self):
        success_count, failure_count, skipped_dpus = self.upgrade_dpus()
        total = success_count + failure_count

        if total == 0:
            msg = "No admin-up DPUs to upgrade (skipped {} admin-down DPU(s))".format(
                len(skipped_dpus))
        elif failure_count == 0:
            msg = "Successfully upgraded all {} DPU(s)".format(success_count)
        else:
            msg = ("Upgraded {} of {} DPU(s) ({} failures, "
                   "met success threshold)").format(success_count, total, failure_count)
        if total > 0 and skipped_dpus:
            msg += "; skipped {} admin-down DPU(s)".format(len(skipped_dpus))

        self.module.exit_json(
            changed=success_count > 0,
            msg=msg,
            success_count=success_count,
            failure_count=failure_count,
            total_dpus=total,
            skipped_dpus=skipped_dpus,
            messages=self.messages)


def main():
    module = UpgradeDpuSonicImageModule()
    module.run()


if __name__ == '__main__':
    main()
