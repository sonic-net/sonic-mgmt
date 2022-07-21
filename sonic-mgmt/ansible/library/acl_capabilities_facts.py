#!/usr/bin/python

from sonic_py_common import multi_asic
DOCUMENTATION = '''
module:         acl_capabilities_facts
version_added:  "1.0"
author:         Stepan Blyschak (stepanb@nvidia.com)
short_description: Retrieve ACL capability information
'''

# swsssdk will be deprecate after 202205
try:
    from swsssdk import SonicDBConfig, SonicV2Connector
except ImportError:
    from swsscommon.swsscommon import SonicDBConfig, SonicV2Connector

EXAMPLES = '''
- name: Get ACL capability facts
  acl_capabilities_facts:
'''


class AclCapabilityModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(),
            supports_check_mode=True)

        self.out = None
        self.facts = {}

        return

    def run(self):
        """
        Run ACL capabilities facts collection.
        """
        self.facts['acl_capabilities'] = {}
        namespace_list = multi_asic.get_namespace_list()

        SonicDBConfig.load_sonic_global_db_config()
        conn = SonicV2Connector(namespace=namespace_list[0])
        conn.connect(conn.STATE_DB)
        keys = conn.keys(conn.STATE_DB, 'ACL_STAGE_CAPABILITY_TABLE|*') or []

        for key in keys:
            capab = conn.get_all(conn.STATE_DB, key)
            self.facts['acl_capabilities'][key.split('|')[-1]] = capab

        self.module.exit_json(ansible_facts=self.facts)


def main():
    AclCapabilityModule().run()


from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()

