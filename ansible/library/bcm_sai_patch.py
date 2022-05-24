#!/usr/bin/env python
# This ansible module is for gathering VLAN related facts from SONiC device.

from ansible.module_utils.basic import *
from collections import defaultdict
import os
import re
import shutil

DOCUMENTATION = '''
---
module: brm_sao_patch
version_added: "1.0"
author: Bing Wang (bingwang@microsoft.com)
short_description: Patch config.bcm to add sai_remap_prio_on_tnl_egress=1.
description:
    - A hot fix until the issue is fixed in SAI
options:
    N/A
'''

EXAMPLES = ''

def sonic_cfggen_cmd(module, cmd):
    CMD = 'sonic-cfggen -d -v \"{}\"'.format(cmd)
    rc, stdout, stderr = module.run_command(CMD)
    if rc != 0:
        module.fail_json(msg='Failed to retrieve attribute with sonic-cfggen cmd=%s rc=%s, stdout=%s, stderr=%s' % (CMD, rc, stdout, stderr))
        return ""
    return stdout.strip('\r\n').strip('\n')

def sai_patch(module):
    subtype = sonic_cfggen_cmd(module, "DEVICE_METADATA.localhost.subtype")
    if subtype != "DualToR":
        return

    platform = sonic_cfggen_cmd(module, "DEVICE_METADATA.localhost.platform")
    if "arista" not in platform.lower():
        return

    rc, release_version, stderr = module.run_command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version")
    if rc != 0:
        module.fail_json(msg='Failed to get release version, rc=%s, stderr=%s' % (rc, stderr))
    if "master" not in release_version:
        return

    hwsku = sonic_cfggen_cmd(module, "DEVICE_METADATA.localhost.hwsku")

    hwsku_dir = "/usr/share/sonic/device/" + platform + "/" + hwsku
    
    def _find_bcm_config():
        BCM_CONFIG_SUFFIX = ".config.bcm"
        for item in os.listdir(hwsku_dir):
            if os.path.isfile(os.path.join(hwsku_dir, item)) and item.endswith(BCM_CONFIG_SUFFIX):
                return os.path.join(hwsku_dir, item)
        return None
    
    bcm_config = _find_bcm_config()

    need_patch = True
    PATTERN='sai_remap_prio_on_tnl_egress=1'
    reg = re.compile("^{}$".format(PATTERN))
    if bcm_config is not None:
        lines = []
        with open(bcm_config, "r") as f:
            for line in f:
                lines.append(line.strip('\n'))
                if reg.match(line):
                    need_patch = False
                    break

        if need_patch:
            shutil.copy(bcm_config, bcm_config+".bak")
            lines.insert(2, PATTERN)
            with open(bcm_config, "w") as f:
                f.write("\n".join(lines))

def main():
    module = AnsibleModule(argument_spec=dict())
    sai_patch(module)
    module.exit_json(ansible_facts={'stats': "OK"})

if __name__ == '__main__':
    main()
