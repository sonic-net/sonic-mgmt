#!/usr/bin/python

import os
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
          topo: nut-2tiers
          duts:
            - switch-t0-1
            - ...
          tgs:
            - tg-1
            - ...
          inv_name: lab
          auto_recover: 'True'
          comment: "Testbed for NUT with multi-tier topology"

    NUT topo file example:

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
        tg_template: { type: "Server", asn_base: 60001, p2p_v4: "10.0.0.0/16", p2p_v6: "fc0a::/64" }

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
                "topo": {
                    "name": "nut-2tiers",
                    "type": "nut",
                    "properties": {
                        "dut_templates": [{
                            "name": ".*-t0-.*"
                            "type": "ToRRouter"
                            "loopback_v4": "100.1.0.0/24"
                            "loopback_v6": "2064:100:0:0::/64"
                            "asn_base": 64001
                            "p2p_v4": "10.0.0.0/16"
                            "p2p_v6": "fc0a::/64",
                        }, ...],
                        "tg_template": {
                            "type": "Server",
                            "asn_base": 60001,
                            "p2p_v4": "10.0.0.0/16",
                            "p2p_v6": "fc0a::/64"
                        }
                    }
                },
                "duts": [ "switch-t0-1", ... ],
                "tgs": [ "tg-1", ... ],
            }
            ....
        }
'''

# Default testbed file name
NUT_TESTBED_FILE = '../ansible/testbed.nut.yaml'
NUT_TOPO_DIR = '../ansible/vars/nut_topos/'
LEGACY_TOPO_DIR = '../ansible/vars/'
is_legacy_testbed_file = False


class ParseTestbedInfo():
    """Parse the testbed file used to describe whole testbed info"""

    def __init__(self, testbed_file: str):
        self.testbed_filename = testbed_file
        self.testbeds = defaultdict()
        if not testbed_file.endswith("nut.yaml"):
            global is_legacy_testbed_file
            is_legacy_testbed_file = True

    def read_testbeds(self):
        """Read yaml testbed info file."""
        with open(self.testbed_filename) as f:
            tb_list = yaml.safe_load(f)
            for tb in tb_list:
                normalised_tb = self.normalise_tb_fields(tb)
                self.testbeds[tb["name"]] = normalised_tb

    def normalise_tb_fields(self, tb):
        """Normalise to the same field set name of both legacy and nut testbed file"""
        fields_map = {
            'dut': 'duts',
            'conf-name': 'name'
        }

        for field in fields_map:
            if field not in tb:
                continue

            tb[fields_map[field]] = tb[field]
            del tb[field]

        return tb

    def get_testbed_info(self, testbed_name: str) -> Any:
        if testbed_name:
            return self.testbeds[testbed_name]
        else:
            return self.testbeds


def load_topo_info(testbed: dict):
    """Load topology info for the testbed."""
    topo_name = testbed.get("topo", None)
    if not topo_name:
        raise ValueError(f"Testbed '{testbed['name']}' does not have a valid topology defined.")

    # Load DUT templates
    topo_dir = NUT_TOPO_DIR

    if is_legacy_testbed_file:
        topo_dir = LEGACY_TOPO_DIR
        topo_name = "topo_" + topo_name

    with open(os.path.join(topo_dir, topo_name + '.yml')) as f:
        topo_data = yaml.safe_load(f)
        topo = {"name": topo_name, "type": "nut", "properties": topo_data}
        testbed["topo"] = topo


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
        load_topo_info(testbed)

        module.exit_json(ansible_facts={'testbed_facts': testbed})
    except (IOError, OSError):
        module.fail_json(msg="Can not find lab testbed file: " + testbed_file + ".")
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
