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
#       "rc": 0
#     },
#     {
#       "stderr_lines": [],
#       "stderr": "",
#       "stdout": "/home/admin\n",
#       "stdout_lines": [
#         "/home/admin"
#       ],
#       "cmd": "pwd",
#       "rc": 0
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
#       ]
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
'''

EXAMPLES = r'''
# Run multiple commands
- name: Run multiple commands on remote host
  shell_cmds:
    cmds:
        - ls /home
        - pwd
'''

def run_cmd(module, cmd):

    rc, out, err = module.run_command(cmd, use_unsafe_shell=True)
    result = dict(
        cmd=cmd,
        rc=rc,
        stdout=out,
        stderr=err,
        stdout_lines=out.splitlines(),
        stderr_lines=err.splitlines()
    )
    return result

def main():

    module = AnsibleModule(argument_spec=dict(
            cmds=dict(type='list')
        )
    )

    cmds = module.params['cmds']

    startd = datetime.datetime.now()

    results = []
    for cmd in cmds:
        results.append(run_cmd(module, cmd))

    endd = datetime.datetime.now()
    delta = endd - startd

    output = dict(
        cmds=cmds,
        results=results,
        start=str(startd),
        end=str(endd),
        delta=str(delta),
        failed=any(result['rc']!=0 for result in results)
    )

    if output['failed']:
        module.fail_json(msg='At least running one of the commands failed', **output)
    module.exit_json(**output)


if __name__ == '__main__':
    main()
