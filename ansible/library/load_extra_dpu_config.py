#!/usr/bin/python

import paramiko
import os
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.smartswitch_utils import smartswitch_hwsku_config

DPU_HOST_IP_BASE = "169.254.200.{}"
SRC_DPU_CONFIG_FILE = "/tmp/dpu_extra.json"
DST_DPU_CONFIG_FILE = "/tmp/dpu_extra.json"
DST_FULL_CONFIG_FILE = "/tmp/dpu_full.json"
DEFAULT_CONFIG_FILE = "/etc/sonic/config_db.json"
GEN_FULL_CONFIG_CMD = "jq -s '.[0] * .[1]' {} {} > {}".format(
    DEFAULT_CONFIG_FILE, DST_DPU_CONFIG_FILE, DST_FULL_CONFIG_FILE)
CONFIG_RELOAD_CMD = "sudo config reload {} -y".format(DST_FULL_CONFIG_FILE)
CONFIG_SAVE_CMD = "sudo config save -y"
# Need to add retry for Cisco SS since DPU takes longer to admin up
MAX_RETRIES = 5
RETRY_DELAY = 60  # sec


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

        self.module.fail_json(msg="Failed to connect to DPU {} after {} retries: {}".format(
            dpu_ip, MAX_RETRIES, str(last_exception)))
        return None

    def transfer_to_dpu(self, ssh, dpu_ip):
        """Transfer the configuration file to the DPU"""
        try:
            with ssh.open_sftp() as sftp:
                sftp.put(SRC_DPU_CONFIG_FILE, DST_DPU_CONFIG_FILE)
        except Exception as e:
            self.module.fail_json(msg="Failed to transfer file to DPU {}: {}".format(dpu_ip, str(e)))

    def execute_command(self, ssh, dpu_ip, command):
        """Execute a command on the DPU"""
        _, stdout, stderr = ssh.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            self.module.fail_json(msg="{} failed on DPU {} with exit status {}: {}".format(
                command, dpu_ip, exit_code, stderr.read().decode('utf-8')))

    def configure_dpus(self):
        """Configure all DPUs based on the hardware SKU configuration"""
        if not os.path.isfile(SRC_DPU_CONFIG_FILE):
            self.module.fail_json(msg="DPU config file not found: {}".format(SRC_DPU_CONFIG_FILE))

        for i in range(0, self.dpu_num):
            dpu_ip = DPU_HOST_IP_BASE.format(i + 1)

            ssh = self.connect_to_dpu(dpu_ip)
            if not ssh:
                self.module.fail_json(msg="Failed to ssh to DPU: {}".format(dpu_ip))

            try:
                self.transfer_to_dpu(ssh, dpu_ip)
                self.execute_command(ssh, dpu_ip, GEN_FULL_CONFIG_CMD)
                self.execute_command(ssh, dpu_ip, CONFIG_RELOAD_CMD)
                self.execute_command(ssh, dpu_ip, CONFIG_SAVE_CMD)
                self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DST_DPU_CONFIG_FILE))
                self.execute_command(ssh, dpu_ip, "sudo rm -f {}".format(DST_FULL_CONFIG_FILE))
            except Exception as e:
                self.module.fail_json(msg="Failed to configure DPU {}: {}".format(dpu_ip, str(e)))
            finally:
                ssh.close()

        self.module.run_command("sudo rm -f {}".format(SRC_DPU_CONFIG_FILE))

    def run(self):
        self.configure_dpus()
        self.module.exit_json(changed=True, msg="Successfully configured all DPUs")


def main():
    dpu_config_module = LoadExtraDpuConfigModule()
    dpu_config_module.run()


if __name__ == '__main__':
    main()
