## This script gets all of the calls made to dut/ptf and lists them along with their definition from their readmes
## Any methods that do not have corresponding documentation will be listed first, and if you're a contributor, feel free to add them!

import os

# Modules in this list should not be documented. Add any module that is clearly intended only for
# use in playbooks. If you are unsure, see if it is ever called outside of a YAML file
ansible_ignore = ["vmhost_server_info", "combine_list_to_dict", "switch_tables", "tunnel_config", "vlan_config", "test_facts", "topo_facts", "testbed_vm_info", "testing_port_ip_facts", "ptf_portchannel", "ip_route", "interface_up_down_data_struct_facts", "configure_vms", "dual_tor_facts", "counter_facts", "fabric_info", "get_interface"]

to_print = []

print("## UNDOCUMENTED ANSIBLE METHODS ##\n")
to_print.append(["\n## DOCUMENTED ANSIBLE METHODS ##\n", []])
## Get Ansible Modules
for file in os.listdir("./ansible/library/"):
    method_name = file[:-3]
    if method_name.startswith("_") or method_name in ansible_ignore or not file.endswith(".py"):
            continue
    file_path = "./docs/api_wiki/ansible_methods/{}.md".format(method_name)
    if os.path.isfile(file_path):
        definition = ""
        with open(file_path) as f:
            next = False
            for line in f.readlines():
                if next:
                    definition = line
                    break
                if "## Overview" in line:
                    next = True
        to_print[-1][1].append("{} - {}".format(method_name, definition))
    else:
        print(method_name)


def get_methods(name, doc_name):
    # Gets all methods given a path to a file

    file_path = "./tests/common/devices/{}.py".format(name)
    methods = []

    with open(file_path) as f:
        to_print.append(["\n## DOCUMENTED {} METHODS ##\n".format(name.upper()), []])
        print("\n## UNDOCUMENTED {} METHODS ##\n".format(name))
        for line in f.readlines():
            line = line.strip()
            if line.startswith("def "):
                methods.append(line[4:line.index("(")])
    
    for method_name in methods:
        if method_name.startswith("_"):
            continue
        file_path = "./docs/api_wiki/{}_methods/{}.md".format(doc_name, method_name)
        if os.path.isfile(file_path):
            definition = ""
            with open(file_path) as f:
                next = False
                for line in f.readlines():
                    if next:
                        definition = line
                        break
                    if "## Overview" in line:
                        next = True
            to_print[-1][1].append("{} - {}".format(method_name, definition))
        else:
            print(method_name)

# List of devices that methods should be extracted for
devices = ["sonic", "sonic_asic", "multi_asic", "ptf"]
doc_names = ["sonichost", "sonic_asic", "multi_asic", "ptfhost"]

# Extracts methods from specified devices
for dev, doc_name in zip(devices, doc_names):
    get_methods(dev, doc_name)

for doced in to_print:
    print(doced[0])
    for item in doced[1]:
        print(item)