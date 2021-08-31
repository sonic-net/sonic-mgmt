#!/usr/bin/python

import json
import sys
from ansible.module_utils.basic import *
from ansible.module_utils.multi_asic_utils import load_db_config
try:
    from sonic_py_common import multi_asic
    NAMESPACE_LIST = multi_asic.get_namespace_list()
except ImportError:
    NAMESPACE_LIST = ['']
DOCUMENTATION = '''
---
module: lag_facts
Ansible_version_added: "2.0.0.2"
Sonic_version: "2.0"
short_description: Retrieve lag(LACP) information from a device 
description:
    - Retrieved facts will be inserted to:
        lag_facts:
          - 'names': [list all portchannel names] 
          - 'lags':  {portchannel: detailed portchannel information }
'''

EXAMPLES = '''
# Gather lab facts
 - name: Gather lag info
   lag_facts:  host=10.255.0.200 
 - name: display lag information
   debug: var=lag_facts
'''

class LagModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                host=dict(required=True),
            ),
            supports_check_mode=False,
        )
        self.lag_names = {}
        self.lags = {}
        return

    def run(self):
        '''
            Main method of the class
        '''
        self.get_po_names()
        for po,ns in self.lag_names.items():
            self.lags[po] = {}
            if 'sonic_py_common' in sys.modules:
                ns_id = multi_asic.get_asic_id_from_name(ns) if ns else ''
            else:
                ns_id = ''
            self.lags[po]['po_stats'] = self.get_po_status(po, ns_id)
            self.lags[po]['po_config'] = self.get_po_config(po, ns_id)
            self.lags[po]['po_intf_stat'] = self.get_po_intf_stat(po, ns)
            self.lags[po]['po_namespace_id'] = ns_id
        self.module.exit_json(ansible_facts={'lag_facts': {'names': self.lag_names, 'lags': self.lags}})
        return

    def get_po_names(self):
        '''
            Collect configured lag interface names
        '''
        # load db config
        load_db_config()
        for ns in NAMESPACE_LIST:
            rt, out, err = self.module.run_command("sonic-cfggen -m /etc/sonic/minigraph.xml {} -v \"PORTCHANNEL.keys() | join(' ')\"".format('-n ' + ns if ns else ''))
            if rt != 0:
                fail_msg="Command to retrieve portchannel names failed return=%d, out=%s, err=%s" %(rt, out, err)
                self.module.fail_json(msg=fail_msg)
            else:
                for po in out.split():
                    if 'sonic_py_common' in sys.modules and multi_asic.is_port_channel_internal(po):
                        continue
                    self.lag_names[po] = ns
        return

    def get_po_status(self, po_name, ns):
        '''
            Collect lag information by command docker teamdctl
        '''
        rt, out, err = self.module.run_command("docker exec -i teamd{} teamdctl ".format(ns) +po_name+" state dump")
        if rt != 0:
            fail_msg="failed dump port channel %s status return=%d, out=%s, err=%s" %(po_name, rt, out, err)
            self.module.fail_json(msg=fail_msg)
        json_info = json.loads(out)
        return json_info

    def get_po_config(self, po_name, ns):
        '''
            Collect lag information by command docker teamdctl
        '''
        rt, out, err = self.module.run_command("docker exec -i teamd{} teamdctl ".format(ns) +po_name+" config dump")
        if rt != 0:
            fail_msg="failed dump port channel %s config return=%d, out=%s, err=%s" %(po_name, rt, out, err)
            self.module.fail_json(msg=fail_msg)
        json_info = json.loads(out)
        return json_info

    def get_po_intf_stat(self, po_name, ns):
        '''
            Collect lag information by command docker teamdctl
        '''
        rt, out, err = self.module.run_command("sudo ip {} link show ".format('-n ' + ns if ns else '') + po_name)
        if rt != 0:
            fail_msg="failed show interface status of %s return=%d, out=%s, err=%s" %(po_name, rt, out, err)
            self.module.fail_json(msg=fail_msg)
        if 'NO-CARRIER' in out:
            return 'Down'
        else:
            return 'Up'

def main():
    lags = LagModule()
    lags.run()

if __name__ == '__main__':
    main()
