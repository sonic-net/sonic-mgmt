#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
module:         sysfs_facts
version_added:  "1.0"
author:         Junchao Chen (junchao@nvidia.com)
short_description: Collect sysfs information from switch
description:
    - Collect sysfs information from switch
'''

EXAMPLES = '''
- name: Get sysfs information from switch
  sysfs_facts:
    config: ${a list of check items}
'''

# Example of input config
'''
sysfs_facts accept a list of check item configuration.

Single check item config:
{
    'name': 'item_name',
    'type': 'single',
    'properties': [
        {
            'name': 'prop_name',
            'cmd_pattern': 'some command'
        }
    ]
}

User can get the item property value by:
ansible_facts['item_name']['prop_name']

Command rc/stderr for each property is returned as sysfs_metadata with the same key layout:
sysfs_metadata['item_name']['prop_name'] -> {'rc': <int>, 'stderr': <str>}

Increment check item config:
{
    'name': 'item_name',
    'start': 1,
    'count': 10,
    'type': 'increment',
    'properties': [
        {
            'name': 'prop1_name',
            'cmd_pattern': 'some command {}',
        },
        {
            'name': 'prop2_name',
            'cmd_pattern': 'some command {}',
        }
    ]
}

User can get the first property of the first item value by:
ansible_facts['item_name'][1]['prop1_name']
sysfs_metadata['item_name'][1]['prop1_name'] -> {'rc': <int>, 'stderr': <str>}

A example that using this facts is at tests/platform_tests/mellanox/check_sysfs.py
'''


class SysfsModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                config=dict(required=True, type='list')
            ),
            supports_check_mode=True)
        self.config = self.module.params['config']
        self.facts = {}
        self.metadata = {}

    def run(self):
        for item in self.config:
            if 'type' not in item:
                self.module.fail_json(
                    msg='Check item must have a type field: {}'.format(item))

            if item['type'] == 'single':
                self.collect_single_item(item)
            elif item['type'] == 'increment':
                self.collect_increment_item(item)
            else:
                self.module.fail_json(
                    msg='Unsupported check item type {}'.format(item['type']))

        self.module.exit_json(ansible_facts=self.facts, sysfs_metadata=self.metadata)

    def collect_single_item(self, item):
        facts = {}
        metadata = {}
        for prop in item['properties']:
            prop_name = prop['name']
            rc, out, err = self.run_command(prop['cmd_pattern'])
            facts[prop_name] = out
            metadata[prop_name] = {'rc': rc, 'stderr': err}

        name = item['name']
        self.facts[name] = facts
        self.metadata[name] = metadata

    def collect_increment_item(self, item):
        facts = {}
        metadata = {}
        start = item['start']
        count = item['count']
        for index in range(start, start + count):
            facts[index] = {}
            metadata[index] = {}
            for prop in item['properties']:
                prop_name = prop['name']
                cmd = prop['cmd_pattern'].format(index)
                rc, out, err = self.run_command(cmd)
                facts[index][prop_name] = out
                metadata[index][prop_name] = {'rc': rc, 'stderr': err}

        name = item['name']
        self.facts[name] = facts
        self.metadata[name] = metadata

    def run_command(self, command):
        try:
            rc, out, err = self.module.run_command(
                command, executable='/bin/bash', use_unsafe_shell=True)
        except Exception as e:
            self.module.fail_json(
                msg='command {} failed with exception {}'.format(command, e))

        return rc, out.strip(), (err or '').strip()


def main():
    m = SysfsModule()
    m.run()


if __name__ == "__main__":
    main()
