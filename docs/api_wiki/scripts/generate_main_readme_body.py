# This script generates the bottom portion for the wiki README so contributors do not have to manually add to it
# Mainly just for me since I don't want to write it...

import os

def get_section(title, path):
    # Prints a section of the body

    name = path.split("/")[-1]

    ret_list = ["## {}\n".format(title)]

    for entry in os.listdir(path):
        definition = ""
        next = False
        with open("{}/{}".format(path, entry)) as f:
            for line in f.readlines():
                if next:
                    if len(line) == 1:
                        continue
                    definition = line
                    break
                if "## Overview" in line:
                    next = True

        ret_list.append("- [{}]({}/{}) - {}".format(entry[:-3], name, entry, definition))

    return "\n".join(ret_list)

print("\n\n".join([get_section("Ansible Modules", "docs/api_wiki/ansible_methods"),
                 get_section("Sonichost Methods", "docs/api_wiki/sonichost_methods"),
                 get_section("Multi ASIC Methods", "docs/api_wiki/multi_asic_methods"),
                 get_section("Sonic ASIC Methods", "docs/api_wiki/sonic_asic_methods"), 
                 get_section("Ptfhost Methods", "docs/api_wiki/ptfhost_methods"), 
                 get_section("Preconfigured Function Arguments", "docs/api_wiki/preconfigured")]))
