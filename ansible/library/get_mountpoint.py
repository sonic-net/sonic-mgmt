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
    - Retrieve mountpoint, fstype, opts, maxname and maxpath info
version_added: "2.8"
options:
    mountpoint:
        description:
            - The mountpoint of interest
        required: True
"""

def get_mounts(module, mountpoint):

    partition = {'mountpoint': NOT_AVAILABLE, 'fstype': NOT_AVAILABLE, 'opts': NOT_AVAILABLE, 'maxfile': NOT_AVAILABLE, 'maxpath': NOT_AVAILABLE }

    def _get_mount_via_psutil(mountpoint):

        diskpartitions = psutil.disk_partitions(all=True)
        for part in diskpartitions:
            if part.mountpoint == mountpoint:
                break

        partition['mountpoint'] = part.mountpoint
        partition['fstype'] = part.fstype
        partition['opts'] = part.opts
        partition['maxfile'] = part.maxfile
        partition['maxpath'] = part.maxpath

    def _get_mount_via_mount(module, mountpoint):

        cmd = "mount"
        rc, stdout, _ = module.run_command(args=cmd)

        if rc == 0:
            mount_results = stdout.decode('utf-8').splitlines()
            for line in mount_results:
                if line.split()[2] == mountpoint:
                    partition['mountpoint'] = line.split()[2]
                    partition['fstype'] = line.split()[0]
                    partition['opts'] = line.split()[-1][1:-1]
                    partition['maxfile'] = os.pathconf(mountpoint, 'PC_NAME_MAX')
                    partition['maxpath'] = os.pathconf(mountpoint, 'PC_PATH_MAX')
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
