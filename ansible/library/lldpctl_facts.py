#!/usr/bin/env python
# This ansible module is for gathering lldp facts from SONiC device.
# It takes two argument 
# asic_instance_id :- Used to specify LLDP Instance in Multi-asic platforms
# skip_interface_pattern_list:- Used to specify interface pattern list to be skip for gathering lldp facts.
import re
from ansible.module_utils.basic import AnsibleModule

def gather_lldp(module, lldpctl_docker_cmd, skip_interface_pattern_list):
    _, output, _ = module.run_command(lldpctl_docker_cmd)
    output_dict = {}
    current_dict = {}
    
    if not output:
        return output_dict
    lldp_entries = output.splitlines()
    skip_interface_pattern_str = "(?:% s)" % '|'.join(skip_interface_pattern_list) if skip_interface_pattern_list else None
    for entry in lldp_entries:
        if entry.startswith("lldp"):
            path, value = entry.strip().split("=", 1)
            path = path.split(".")
            if skip_interface_pattern_list and re.match(skip_interface_pattern_str, path[1]):
                continue
            path_components, final = path[:-1], path[-1]
        else:
            value = current_dict[final] + '\n' + entry

        current_dict = output_dict
        for path_component in path_components:
            current_dict[path_component] = current_dict.get(path_component, {})
            current_dict = current_dict[path_component]
        current_dict[final] = value
    return output_dict


def main():
    module = AnsibleModule(argument_spec=dict(
             asic_instance_id = dict(required = False, type='int', default=None),
             skip_interface_pattern_list = dict(required = False, type='list', default=None)
             ),
             supports_check_mode=False)

    m_args = module.params
    lldpctl_docker_cmd = "docker exec -i {} lldpctl -f keyvalue".format("lldp" + (str(m_args["asic_instance_id"]) if m_args["asic_instance_id"] is not None else ""))
    lldp_output = gather_lldp(module, lldpctl_docker_cmd, m_args["skip_interface_pattern_list"])
    try:
        data = {"lldpctl": lldp_output["lldp"] if lldp_output else lldp_output }
        module.exit_json(ansible_facts=data)
    except TypeError:
        module.fail_json(msg="lldpctl command failed")


if __name__ == '__main__':
    main()
