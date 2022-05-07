#!/usr/bin/env python
import os.path
import sys
import traceback
import yaml

from ansible.module_utils.basic import *

try:
    from ansible.module_utils.dualtor_utils import generate_mux_cable_facts
except ImportError:
    # Add parent dir for using outside Ansible
    sys.path.append('..')
    from ansible.module_utils.dualtor_utils import generate_mux_cable_facts


DOCUMENTATION = """
module: mux_cable_facts.py
version_added:  2.0.0.2
short_description: get mux cable information
options:
    - topo_name:
      Description: the topology name
      required: False
    - topology:
      Description: the topology dict defined in topo .yml file
      require: False
"""


def load_topo_file(topo_name):
    """Load topo definition yaml file."""
    topo_file = "vars/topo_%s.yml" % topo_name
    if not os.path.exists(topo_file):
        raise ValueError("Topo file %s not exists" % topo_file)
    with open(topo_file) as fd:
        return yaml.safe_load(fd)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            topo_name=dict(required=False, type="str"),
            topology=dict(required=False, type="dict"),
        ),
        mutually_exclusive=[["topo_name", "topology"]],
        required_one_of=[["topo_name", "topology"]]
    )
    args = module.params
    if args["topo_name"]:
        topo_name = args["topo_name"]
        topology = load_topo_file(topo_name)["topology"]
    else:
        topology = args["topology"]

    try:
        mux_cable_facts = generate_mux_cable_facts(topology=topology)
        module.exit_json(ansible_facts={"mux_cable_facts": mux_cable_facts})
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
