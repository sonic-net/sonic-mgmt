#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import operator
try:
    import psutil
except ImportError:
    HAS_PSUTIL = False
else:
    HAS_PSUTIL = True
import re
import time
from ansible.module_utils.basic import AnsibleModule

NOT_AVAILABLE = "N/A"

DOCUMENTATION = """
module: get_mountpoint
short_description: retrieve mountpoints on a device
description:
    - Retrieve mountpoint, fstype
version_added: "2.8"
options:
    mountpoint:
        description:
            - The mountpoint of interest
        required: True
"""

def get_mounts(module, mountpoint):

    partition = {'mountpoint': NOT_AVAILABLE, 'fstype': NOT_AVAILABLE }

    def _get_mount_via_psutil(mountpoint):

        diskpartitions = psutil.disk_partitions(all=True)
        for part in diskpartitions:
            if part.mountpoint == mountpoint:
                break

        partition['mountpoint'] = part.mountpoint
        partition['fstype'] = part.fstype

    def _get_mount_via_mount(module, mountpoint):

        cmd = "mount"
        rc, stdout, _ = module.run_command(args=cmd)

        if rc == 0:
            mount_results = stdout.splitlines()
            for line in mount_results:
                if line.split()[2] == mountpoint:
                    partition['mountpoint'] = line.split()[2]
                    partition['fstype'] = line.split()[0]
                    break


    if HAS_PSUTIL:
        _get_mount_via_psutil(mountpoint)
    else:
        _get_mount_via_mount(module, mountpoint)

    return partition

def main():
    module = AnsibleModule(
        argument_spec=dict(
            mountpoint=dict(required=True, type='str')
        )
    )

    mountpoint = module.params['mountpoint']
    module.exit_json(
        mountpoint_results=get_mounts(module, mountpoint),
        changed=False
        )

if __name__ == "__main__":
    main()
