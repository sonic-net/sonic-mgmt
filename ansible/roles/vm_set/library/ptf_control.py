#!/usr/bin/python

import json
import logging
import traceback

import docker

from ansible.module_utils.debug_utils import config_module_logging
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
---
module: ptf_control
version_added: "0.1"
author: Xin Wang (xiwang5@microsoft.com)
short_description: Control PTF container
description: For controlling PTF container, for example killing processes running in PTF container before stopping it.

Parameters:
    - ctn_name: Name of the PTF container
    - command: Command to run, currently only support "kill"

'''

EXAMPLES = '''
- name: Kill exabgp and ptf_nn_agent processes in PTF container
  ptf_control:
    ctn_name: "ptf_vms6-1"
    command: kill
'''


class PtfControl(object):
    """This class is for controlling PTF container
    """

    def __init__(self, module, ctn_name):
        self.module = module
        self.ctn_name = ctn_name

        self.pid = PtfControl.get_pid(self.ctn_name)

    def cmd(self, cmdline, use_unsafe_shell=False, ignore_failure=False, verbose=True):
        rc, out, err = self.module.run_command(cmdline, use_unsafe_shell=use_unsafe_shell)
        if verbose:
            msg = {
                'cmd': cmdline,
                'rc': rc,
                'stdout_lines': out.splitlines(),
                'stderr_lines': err.splitlines()
            }
            logging.debug('***** RUN CMD:\n%s' % json.dumps(msg, indent=2))

        if rc != 0 and not ignore_failure:
            raise Exception("Failed to run command: %s, rc=%d, out=%s, err=%s" % (cmdline, rc, out, err))
        return rc, out, err

    @staticmethod
    def get_pid(ctn_name):
        cli = docker.from_env()
        try:
            ctn = cli.containers.get(ctn_name)
            if ctn.status == 'running':
                return ctn.attrs['State']['Pid']
        except Exception as e:
            logging.debug("Failed to get pid for container %s: %s" % (ctn_name, str(e)))

        return None

    def get_process_pids(self, process):
        cmd = 'docker exec -t {} bash -c "pgrep -f \'{}\'"'.format(self.ctn_name, process)
        _, out, _ = self.cmd(cmd, ignore_failure=True)
        return [int(pid.strip()) for pid in out.splitlines()]

    def get_supervisord_processes(self):
        _, out, _ = self.cmd(
            'docker exec -t {} bash -c "supervisorctl status"'.format(self.ctn_name), ignore_failure=True
        )
        processes = [line.strip().split()[0] for line in out.splitlines() if "sshd" not in line]
        return processes

    def kill_process(self, pid):
        self.cmd('docker exec -t {} bash -c "kill -9 {}"'.format(self.ctn_name, pid), ignore_failure=True)

    def kill_processes(self):
        supervisord_processes = self.get_supervisord_processes()
        self.cmd('docker exec -t {} bash -c "ps -ef"'.format(self.ctn_name))
        for i in range(3):
            logging.info("=== Attempt %d ===" % (i + 1))
            logging.info("=== Use supervisorctl to stop processes ===")
            for process in supervisord_processes:
                self.cmd(
                    'docker exec -t {} bash -c "supervisorctl stop {}"'.format(self.ctn_name, process),
                    ignore_failure=True
                )
            self.cmd(
                'docker exec -t {} bash -c "ps -ef"'.format(self.ctn_name)
            )

            for pattern in [
                "/usr/share/exabgp/http_api.py",
                "/usr/local/bin/exabgp",
                "ptf_nn_agent.py"
            ]:
                logging.info("=== Kill process %s ===" % pattern)
                for pid in self.get_process_pids(pattern):
                    self.kill_process(pid)

            self.cmd('docker exec -t {} bash -c "ps -ef"'.format(self.ctn_name))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            ctn_name=dict(required=True, type='str'),
            command=dict(required=True, type='str')
        ),
        supports_check_mode=False)

    ctn_name = module.params['ctn_name']
    command = module.params['command']
    if command not in ['kill']:
        module.fail_json(msg="command %s is not supported" % command)

    config_module_logging('ptf_control_' + ctn_name)

    try:
        ptf = PtfControl(module, ctn_name)
        if command == "kill":
            if ptf.pid is not None:
                ptf.kill_processes()
    except Exception as error:
        logging.error(traceback.format_exc())
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
