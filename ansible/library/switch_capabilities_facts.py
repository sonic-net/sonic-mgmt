#!/usr/bin/python

from sonic_py_common import multi_asic
DOCUMENTATION = '''
module:         switch_capability_facts
version_added:  "1.0"
author:         Stepan Blyschak (stepanb@mellanox.com)
short_description: Retrieve switch capability information
'''

# swsssdk will be deprecate after 202205
try:
    from swsssdk import SonicDBConfig, SonicV2Connector
except ImportError:
    from swsscommon.swsscommon import SonicDBConfig, SonicV2Connector

EXAMPLES = '''
- name: Get switch capability facts
  switch_capability_facts:
'''


class SwitchCapabilityModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
            ),
            supports_check_mode=True)

        self.out = None
        self.facts = {}

        return

    def run(self):
        """
            Main method of the class
        """
        self.facts['switch_capabilities'] = {}
        namespace_list = multi_asic.get_namespace_list()

        SonicDBConfig.load_sonic_global_db_config()
        conn = SonicV2Connector(namespace=namespace_list[0])
        conn.connect(conn.STATE_DB)
        keys = conn.keys(conn.STATE_DB, 'SWITCH_CAPABILITY|*')

        for key in keys:
            capab = conn.get_all(conn.STATE_DB, key)
            self.facts['switch_capabilities'][key.split('|')[-1]] = capab

        self.module.exit_json(ansible_facts=self.facts)


def main():
    SwitchCapabilityModule().run()


from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
