#!/usr/bin/env python

from ansible.module_utils.basic import *
import re
import json
from pprint import pprint


DOCUMENTATION = '''
---
module: counter_facts
version_added: "1.0"
short_description: Retrieve DUT counters.
description:
    - Retrieve DUT counters by parsing specific CLI commands output. Module can be extended
      to support more counters.
options:
    flex_counters:
      description:
        - Execute 'counterpoll show' CLI command on the DUT. Parse and return output
          in dictionary format.
          Will be executed only when specified, no value required.
      default: null
    interfaces_counters: 
      description:
        - Execute 'show interfaces counters' CLI command on the DUT. Parse and return output
          in dictionary format.
          Will be executed only when specified, no value required.
      default: null
'''

EXAMPLES = '''
# Gather counters from 'counterpoll show' CLI command
- name: Get counters from 'counterpoll show' command
  counter_facts:
    flex_counters:

# Gather counters from 'show interfaces counters' CLI command
- name: Get interfaces counters
  counter_facts:
    interfaces_counters: 
'''


def get_flex_counters(module):
    """
    @summary: Parse output of "counterpoll show" command and convert it to the dictionary.
              Composed dictionary example:
              {'PG_WATERMARK_STAT': {'Interval': '10000', 'Status': 'enable'},
              'PORT_STAT': {'Interval': '10000', 'Status': 'enable'},
              'QUEUE_STAT': {'Interval': '10000', 'Status': 'enable'},
              'QUEUE_WATERMARK_STAT': {'Interval': '10000', 'Status': 'enable'}}

              CLI output example:
              Type                  Interval (in ms)    Status
              --------------------  ------------------  --------
              QUEUE_STAT            default (10000)     enable
              PORT_STAT             default (1000)      enable
              QUEUE_WATERMARK_STAT  default (10000)     enable
              PG_WATERMARK_STAT     default (10000)     enable
    @param module: The AnsibleModule object
    @return: Return dictionary of parsed counters
    """
    result = {}
    cli_cmd = "counterpoll show"
    skip_lines = 2

    rc, stdout, stderr = module.run_command(cli_cmd)
    if rc != 0:
        module.fail_json(msg="Failed to run {}, rc={}, stdout={}, stderr={}".format(cli_cmd, rc, stdout, stderr))

    try:
        for line in stdout.splitlines()[skip_lines:]:
            if line:
                key = line.split()[0]
                matched = re.search("{}.*(enable|disable)".format(key), line)
                if matched:
                    counter_line = matched.group(0).split()
                    result[key] = {}
                    # Output line will contain 4 columns if default was not changed
                    # And 3 columns if default was changed
                    index = 2 if len(counter_line) % 3 else 1
                    result[key]["Interval"] = counter_line[index].strip("(|)")
                    result[key]["Status"] = counter_line[-1]
    except Exception as e:
        module.fail_json(msg="Failed to parse output of '{}', err={}".format(cli_cmd, str(e)))

    return result


def get_interfaces_counters(module):
    """
    @summary: Parse output of "show interfaces counters" command and convert it to the dictionary.
    @param module: The AnsibleModule object
    @return: Return dictionary of parsed counters
    """
    cli_cmd = "portstat -j"
    rc, stdout, stderr = module.run_command(cli_cmd)
    if rc != 0:
        module.fail_json(msg="Failed to run {}, rc={}, stdout={}, stderr={}".format(cli_cmd, rc, stdout, stderr))

    match = re.search("Last cached time was.*\n", stdout)
    if match:
        stdout = re.sub("Last cached time was.*\n", "", stdout)

    try:
        return json.loads(stdout)
    except Exception as e:
        module.fail_json(msg="Failed to parse output of '{}', err={}".format(cli_cmd, str(e)))


def main():
    CMD_MAP = {"flex_counters": get_flex_counters,
               "interfaces_counters": get_interfaces_counters}

    module = AnsibleModule(argument_spec=dict(
        flex_counters=dict(required=False, type='str'),
        interfaces_counters=dict(required=False, type='str')
    ))
    m_args = module.params
    ansible_output = {}

    for key, value in m_args.items():
        if value is not None:
            ansible_output[key] = CMD_MAP[key](module)

    module.exit_json(ansible_facts=ansible_output)

if __name__ == '__main__':
    main()
