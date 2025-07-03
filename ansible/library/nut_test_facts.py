#!/usr/bin/python

from typing import Any
from ansible.module_utils.basic import AnsibleModule
import traceback
import yaml

from collections import defaultdict

DOCUMENTATION = '''
module: nut_test_facts.py
version_added:  1.0.0.0
short_description: get lab network under test (NUT) testbed information
options:
    - testbed_file:
      Description: The YAML file name which describe all testbeds
      Default: NUT_TESTBED_FILE
      required: False
    - testbed_name:
      Description: the unique name of one testbed topology specified in the first column of each row of CSV file
      Default: None
      Required: False
'''

EXAMPLES = '''
    Testbed YAML File Example:

        - name: testbed-nut-1
          test_tags: [ snappi-capacity ]
          duts:
            - switch-t0-1
            - ...
          dut_templates:
            - name: ".*-t0-.*"
              type: "ToRRouter"
              loopback_v4: "100.1.0.0/24"
              loopback_v6: "2064:100:0:0::/64"
              asn_base: 64001
              p2p_v4: "10.0.0.0/16"
              p2p_v6: "fc0a::/64"
              extra_meta:
                cloudtype: "Public"
                ...
            - ....
          tgs:
            - tg-1
            - ...
          tg_template: { type: "Server", asn_base: 60001, p2p_v4: "10.0.0.0/16", p2p_v6: "fc0a::/64" }
          inv_name: lab
          auto_recover: 'True'
          comment: "Testbed for NUT with multi-tier topology"

    To use it:
    - name: gather all predefined testbed topology information
      nut_test_facts:

    - name: get testbed-nut-1 topology information
      nut_test_facts: testbed_name="{{ testbed_name }}" testbed_file="{{ testbed_file }}"
'''

RETURN = '''
    Ansible_facts:
        "testbed_facts": {
            "testbed-nut-1": {
                "name": "testbed-nut-1",
                "test_tags": [ "snappi-capacity" ],
                "duts": [ "switch-t0-1", ... ],
                "dut_templates": [{
                    "name": ".*-t0-.*"
                    "type": "ToRRouter"
                    "loopback_v4": "100.1.0.0/24"
                    "loopback_v6": "2064:100:0:0::/64"
                    "asn_base": 64001
                    "p2p_v4": "10.0.0.0/16"
                    "p2p_v6": "fc0a::/64",
                    "extra_meta": { "cloudtype": "Public", ... }
                }, ...]
                "tgs": [ "tg-1", ... ],
                "tg_template": {
                    "type": "Server",
                    "asn_base": 60001,
                    "p2p_v4": "10.0.0.0/16",
                    "p2p_v6": "fc0a::/64"
                }
            }
            ....
        }
'''

# Default testbed file name
NUT_TESTBED_FILE = '../ansible/testbed.nut.yaml'


class ParseTestbedInfo():
    """Parse the testbed file used to describe whole testbed info"""

    def __init__(self, testbed_file: str):
        self.testbed_filename = testbed_file
        self.testbeds = defaultdict()

    def read_testbeds(self):
        """Read yaml testbed info file."""
        with open(self.testbed_filename) as f:
            tb_list = yaml.safe_load(f)
            for tb in tb_list:
                self.testbeds[tb["name"]] = tb

    def get_testbed_info(self, testbed_name: str) -> Any:
        if testbed_name:
            return self.testbeds[testbed_name]
        else:
            return self.testbeds


def main():
    module = AnsibleModule(
        argument_spec=dict(
            testbed_name=dict(required=False, default=None),
            testbed_file=dict(required=False, default=NUT_TESTBED_FILE),
        ),
        supports_check_mode=True
    )

    m_args = module.params
    testbed_file = m_args['testbed_file']
    testbed_name = m_args['testbed_name']

    try:
        # Read all testbed info from the YAML file
        testbeds = ParseTestbedInfo(testbed_file)
        testbeds.read_testbeds()

        # Get the specific testbed info
        testbed = testbeds.get_testbed_info(testbed_name)

        module.exit_json(ansible_facts={'testbed_facts': testbed})
    except (IOError, OSError):
        module.fail_json(msg="Can not find lab testbed file: " + testbed_file + ".")
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
