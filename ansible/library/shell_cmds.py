#!/usr/bin/env python
# This ansible module is for running multiple commands by /bin/sh on remote device.
#
# The ansible builtin module "command" and "shell" can run a single command on the remote device and get its output.
# This module is to support running multiple commands in sequential and return the results of these commands. This
# enhancement can reduce some overhead of establishing connection with the remote host when we want to run multiple
# commands.
#
# Example of module output:
# {
#   "end": "2020-09-23 09:18:58.252273",
#   "_ansible_no_log": false,
#   "start": "2020-09-23 09:18:58.243835",
#   "changed": false,
#   "results": [
#     {
#       "stderr_lines": [],
#       "stderr": "",
#       "stdout": "admin\n",
#       "stdout_lines": [
#         "admin"
#       ],
#       "cmd": "ls /home",
#       "cmd_with_timeout": "",
#       "rc": 0,
#       "timeout": 0,
#       "err_msg": ""
#     },
#     {
#       "stderr_lines": [],
#       "stderr": "",
#       "stdout": "/home/admin\n",
#       "stdout_lines": [
#         "/home/admin"
#       ],
#       "cmd": "pwd",
#       "cmd_with_timeout": "",
#       "rc": 0,
#       "timeout": 0,
#       "err_msg": ""
#     }
#   ],
#   "cmds": [
#     "ls /home",
#     "pwd"
#   ],
#   "failed": false,
#   "delta": "0:00:00.008438",
#   "invocation": {
#     "module_args": {
#       "cmds": [
#         "ls /home",
#         "pwd"
#       ],
#       "continue_on_fail": false
#     }
#   }
# }

import datetime

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: shell_cmds
version_added: "1.0"
author: Xin Wang (xiwang5@microsoft.com)
short_description: Run multiple commands on remote host.
description:
    - Run multiple commands by /bin/sh on remote host.
options:
    cmds: List of commands. Each command should be a string.
    continue_on_fail: Bool. Specify whether to continue running rest of the commands if any of the command failed.
    timeout: Integer. Specify time limit (in second) for each command. 0 means no limit. Default value is 0.
'''

EXAMPLES = r'''
# Run multiple commands
- name: Run multiple commands on remote host
  shell_cmds:
    cmds:
        - ls /home
        - pwd
    continue_on_fail: False
    timeout: 30
'''


def run_cmd(module, cmd, timeout):
    cmd_with_timeout = ''
    err_msg = ''

    if int(timeout) != 0 and "'" in cmd:
        err_msg = "[WARNING] timeout is not supported for command contains single quote, ran without time limit"
        timeout = 0

    if int(timeout) == 0:
        rc, out, err = module.run_command(cmd, use_unsafe_shell=True)
    else:
        cmd_with_timeout = "echo '{}' | timeout --preserve-status {} bash".format(cmd, timeout)
        rc, out, err = module.run_command(cmd_with_timeout, use_unsafe_shell=True)

    result = dict(
        cmd=cmd,
        cmd_with_timeout=cmd_with_timeout,
        err_msg=err_msg,
        rc=rc,
        stdout=out,
        stderr=err,
        stdout_lines=out.splitlines(),
        stderr_lines=err.splitlines(),
        timeout=timeout
    )
    return result


def main():

    module = AnsibleModule(
        argument_spec=dict(
            cmds=dict(type='list', required=True),
            continue_on_fail=dict(type='bool', default=True),
            timeout=dict(type='int', default=0)
        )
    )

    cmds = module.params['cmds']
    continue_on_fail = module.params['continue_on_fail']
    timeout = module.params['timeout']

    startd = datetime.datetime.now()

    results = []
    failed_cmds = []
    for cmd in cmds:
        result = run_cmd(module, cmd, timeout)
        results.append(result)
        if result['rc'] != 0:
            failed_cmds.append(cmd)
            if not continue_on_fail:
                break

    endd = datetime.datetime.now()
    delta = endd - startd

    output = dict(
        cmds=cmds,
        results=results,
        start=str(startd),
        end=str(endd),
        delta=str(delta),
        failed=any(result['rc'] != 0 for result in results)
    )

    if output['failed']:
        for idx in len(failed_cmds):
            print("Running command failed: {}!".format(failed_cmds))
        module.fail_json(
            msg='At least running one of the commands failed', **output)

    module.exit_json(**output)


if __name__ == '__main__':
    main()
