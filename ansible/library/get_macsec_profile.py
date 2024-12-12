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

def get_macsec_profile(module, macsec_profile):
    with open('/tmp/profile.json') as f:
        macsec_profiles = json.load(f)
        for k, v in list(macsec_profiles.items()):
            if k == self.macsec_profile:
                profile = v
                # Update the macsec profile name in the profile context
                profile['macsec_profile'] = k
                break
   return profile

def main():
    module = AnsibleModule(
        argument_spec=dict(
            macsec_profile=dict(required=True, type='str')
        )
    )

    macsec_profile = module.params['macsec_profile']
    module.exit_json(
        profile=get_macsec_profile(module, macsec_profile),
        changed=False
        )

if __name__ == "__main__":
    main()
