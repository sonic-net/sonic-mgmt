#!/usr/bin/python

import paramiko
import os
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.misc_utils import wait_for_path
from ansible.module_utils.smartswitch_utils import smartswitch_hwsku_config

DPU_HOST_IP_BASE = "169.254.200.{}"
SRC_DPU_CONFIG_FILE = "/tmp/dpu_extra.json"
DST_DPU_CONFIG_FILE = "/tmp/dpu_extra.json"
DST_FULL_CONFIG_FILE = "/tmp/dpu_full.json"
DEFAULT_CONFIG_FILE = "/etc/sonic/config_db.json"
GEN_FULL_CONFIG_CMD = "jq -s '.[0] * .[1]' {} {} > {}".format(
    DEFAULT_CONFIG_FILE, DST_DPU_CONFIG_FILE, DST_FULL_CONFIG_FILE)
CONFIG_RELOAD_CMD = "sudo config reload {} -y -f".format(DST_FULL_CONFIG_FILE)
CONFIG_SAVE_CMD = "sudo config save -y"
# Need to add retry for Cisco SS since DPU takes longer to admin up
MAX_RETRIES = 5
RETRY_DELAY = 60  # sec

# Set to 1.0 for requiring all DPUs to succeed (after HW issues are resolved)
SUCCESS_THRESHOLD = 0.5


class LoadExtraDpuConfigModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                hwsku=dict(type='str', required=True),
                host_username=dict(type='str', required=True),
                host_passwords=dict(type='list', elements='str', required=True, no_log=True)
            ),
            supports_check_mode=False
        )

        self.hwsku = self.module.params['hwsku']
        self.host_username = self.module.params['host_username']
        self.host_passwords = self.module.params['host_passwords']

        try:
            self.hwsku_config = smartswitch_hwsku_config[self.hwsku]
            self.dpu_num = self.hwsku_config.get('dpu_num', 0)

            if self.dpu_num == 0:
                self.module.fail_json(msg="No DPUs defined for hwsku: {}".format(self.hwsku))
        except KeyError:
            self.module.fail_json(msg="No DPU configuration found for hwsku: {}".format(self.hwsku))

    def wait_for_dpu_path(self, ssh, dpu_ip, path_to_check):
        try:
            wait_for_path(ssh, dpu_ip, path_to_check, empty_ok=False, tries=MAX_RETRIES, delay=RETRY_DELAY)
        except FileNotFoundError:
            return False
        return True

    def connect_to_dpu(self, dpu_ip):
        """Establish an SSH connection to the DPU with retry"""
        retry_count = 0
        last_exception = None

        while retry_count < MAX_RETRIES:
            for password in self.host_passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(dpu_ip, username=self.host_username, password=password, timeout=30)
                    return ssh
                except Exception as e:
                    last_exception = e
                    continue

            retry_count += 1
            if retry_count < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

        self.module.warn("Failed to connect to DPU {} after {} retries: {}".format(
            dpu_ip, MAX_RETRIES, str(last_exception)))
        return None

    def transfer_to_dpu(self, ssh, dpu_ip):
        """Transfer the configuration file to the DPU"""
        try:
            with ssh.open_sftp() as sftp:
                sftp.put(SRC_DPU_CONFIG_FILE, DST_DPU_CONFIG_FILE)
            return True
        except Exception as e:
            self.module.warn("Failed to transfer file to DPU {}: {}".format(dpu_ip, str(e)))
            return False

    def execute_command(self, ssh, dpu_ip, command):
        """Execute a command on the DPU"""
        try:
            _, stdout, stderr = ssh.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                self.module.warn("{} failed on DPU {} with exit status {}: {}".format(
                    command, dpu_ip, exit_code, stderr.read().decode('utf-8')))
                return False
            return True
        except Exception as e:
            self.module.warn("Exception executing command '{}' on DPU {}: {}".format(
                command, dpu_ip, str(e)))
            return False

    def configure_dpus(self):
        """Configure all DPUs based on the hardware SKU configuration"""
        if not os.path.isfile(SRC_DPU_CONFIG_FILE):
            self.module.fail_json(msg="DPU config file not found: {}".format(SRC_DPU_CONFIG_FILE))

        success_count = 0
        failure_count = 0
        required_success_count = int(self.dpu_num * SUCCESS_THRESHOLD)

        # Ensure at least 1 success is required when threshold < 1.0
        if SUCCESS_THRESHOLD < 1.0 and required_success_count == 0:
            required_success_count = 1

        # Wait for DHCP server to be ready and at least required_success_count DPUs to have DHCP leases
        if not self.wait_for_dhcp_readiness():
            self.module.fail_json(
                msg="DHCP server is not ready on switch after {} retries".format(
                    MAX_RETRIES
                )
            )
        if not self.wait_for_dhcp_leases_dpu_count(required_success_count):
            self.module.fail_json(
                msg="DHCP leases are not ready on switch (required {}) after {} retries.".format(
                    required_success_count, MAX_RETRIES
                )
            )

        self.module.log("Configuring {} DPUs, requiring at least {} successful configurations".format(
            self.dpu_num, required_success_count))

        for i in range(0, self.dpu_num):
            dpu_ip = DPU_HOST_IP_BASE.format(i + 1)

            self.module.log("Attempting to configure DPU {} at {}".format(i + 1, dpu_ip))

            ssh = self.connect_to_dpu(dpu_ip)
            if not ssh:
                self.module.warn("Failed to connect to DPU {}, skipping".format(dpu_ip))
                failure_count += 1
                continue

            try:
                # Attempt each step and track success
                if (self.transfer_to_dpu(ssh, dpu_ip) and
                        self.wait_for_dpu_path(ssh, dpu_ip, DEFAULT_CONFIG_FILE) and
                        self.execute_command(ssh, dpu_ip, GEN_FULL_CONFIG_CMD) and
                        self.execute_command(ssh, dpu_ip, CONFIG_RELOAD_CMD) and
                        self.execute_command(ssh, dpu_ip, CONFIG_SAVE_CMD) and
                        self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DST_DPU_CONFIG_FILE)) and
                        self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DST_FULL_CONFIG_FILE))):
                    success_count += 1
                    self.module.log("Successfully configured DPU {} at {}".format(i + 1, dpu_ip))
                else:
                    failure_count += 1
                    self.module.warn("Failed to configure DPU {} at {}".format(i + 1, dpu_ip))

            except Exception as e:
                failure_count += 1
                self.module.warn("Exception configuring DPU {} at {}: {}".format(i + 1, dpu_ip, str(e)))
            finally:
                ssh.close()

        self.module.run_command("sudo rm -f {}".format(SRC_DPU_CONFIG_FILE))

        self.module.log("Configuration completed: {} successful, {} failed out of {} total DPUs".format(
            success_count, failure_count, self.dpu_num))

        if success_count < required_success_count:
            self.module.fail_json(
                msg="Failed to meet success threshold: {} successful configs required, "
                    "but only {} succeeded out of {} DPUs. "
                    "Failures: {}".format(
                        required_success_count, success_count, self.dpu_num, failure_count))

        return success_count, failure_count

    def get_dchp_readiness(self):
        # look for the bridge-midplane interface in the output
        rc, out, err = self.module.run_command("show dhcp_server ipv4 info")
        if rc != 0:
            return False
        # need to find the line with "bridge-midplane" and "enabled" in it
        for line in out.split("\n"):
            if "bridge-midplane" in line and "enabled" in line:
                return True
        return False

    def wait_for_dhcp_readiness(self):
        retry_count = 0
        while retry_count < MAX_RETRIES:
            if self.get_dchp_readiness():
                return True
            time.sleep(RETRY_DELAY)
            retry_count += 1
        return False

    def get_dhcp_leases_dpu_count(self):
        # check the output for the number of DPU leases
        rc, out, err = self.module.run_command("show dhcp_server ipv4 lease")
        if rc != 0:
            return 0
        lease_count = 0
        for line in out.split("\n"):
            if "bridge-midplane|dpu" in line:
                lease_count += 1
        return lease_count

    def wait_for_dhcp_leases_dpu_count(self, required_count):
        retry_count = 0
        while retry_count < MAX_RETRIES:
            if self.get_dhcp_leases_dpu_count() >= required_count:
                return True
            time.sleep(RETRY_DELAY)
            retry_count += 1
        return False

    def run(self):
        success_count, failure_count = self.configure_dpus()

        if failure_count == 0:
            msg = "Successfully configured all {} DPUs".format(success_count)
        else:
            msg = "Successfully configured {} out of {} DPUs ({} failures, but met success threshold)".format(
                success_count, self.dpu_num, failure_count)

        self.module.exit_json(changed=True, msg=msg,
                              success_count=success_count,
                              failure_count=failure_count,
                              total_dpus=self.dpu_num)


def main():
    dpu_config_module = LoadExtraDpuConfigModule()
    dpu_config_module.run()


if __name__ == '__main__':
    main()
