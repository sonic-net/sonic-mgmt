#!/usr/bin/python
import os
from ansible.module_utils.basic import *


class SysfsModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                config=dict(required=True, type='list')
            ),
            supports_check_mode=True)
        self.config = self.module.params['config']
        self.facts = {}

    def run(self):
        for item in self.config:
            if 'type' not in item:
                self.module.fail_json(msg='Check item must have a type field: {}'.format(item))

            if item['type'] == 'single':
                self.collect_single_item(item)
            elif item['type'] == 'increment':
                self.collect_increment_item(item)
            else:
                self.module.fail_json(msg='Unsupported check item type {}'.format(item['type']))

        self.module.exit_json(ansible_facts=self.facts)

    def collect_single_item(self, item):
        facts = {}
        for prop in item['properties']:
            prop_name = prop['name']
            facts[prop_name] = self.run_command(prop['cmd_pattern'])

        name = item['name']
        self.facts[name] = facts

    def collect_increment_item(self, item):
        facts = {}
        start = item['start']
        count = item['count']
        for index in range(start, start + count):
            facts[index] = {}
            for prop in item['properties']:
                prop_name = prop['name']
                cmd = prop['cmd_pattern'].format(index)
                facts[index][prop_name] = self.run_command(cmd)

        name = item['name']
        self.facts[name] = facts

    def run_command(self, command):
        try:
            rc, out, err = self.module.run_command(command, executable='/bin/bash', use_unsafe_shell=True)
        except Exception as e:
            self.module.fail_json(msg='command {} failed with exception {}'.format(command, e))

        return out.strip()


def main():
    m = SysfsModule()
    m.run()


if __name__ == "__main__":
    main()
