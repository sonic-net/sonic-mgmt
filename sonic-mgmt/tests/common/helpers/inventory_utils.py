import logging
import re

import yaml

from tests.common.helpers.yaml_utils import BlankNone

logger = logging.getLogger(__name__)


def trim_inventory(inv_files, tbinfo):
    """
    Trim the useless topology neighbor the inv_files according to testbed to speed up ansible inventory initialization.

    For every test server, we pre-define ~100 ansible_hosts for the neighbors.
    We put all of the ansible_hosts of test servers into one inventory file.
    The inventory file contains thousands of ansible_hosts, but most of them are useless to the selected testbed,
    Because the testbed only need the definition of the neighbor for its neighbor server.

    During the establishment of the ansible_host, it iterate and compute the ansible_host one by one,
    The useless ansible_host extremely slow down the initialization.

    Hence, will trim and generate a temporary inventory file, for example:
    ['../ansible/veos', '../ansible/inv1'] -> ['../ansible/veos_kvm-t0_trim_tmp', '../ansible/inv1']
    Then pytest will use the light inventory file '../ansible/veos_kvm-t0_trim_tmp' to initialize the ansible_hosts.

    Args:
        inv_files: inventory file list, sample: ['../ansible/veos', '../ansible/inv1']
        tbinfo: tbinfo

    Returns:
        Direct update inv_files and return nothing
    """

    vm_base = tbinfo.get("vm_base", None)
    tb_name = tbinfo.get("conf-name", None)
    pattern = r'VM\d{3,7}'
    logger.info(f"Start to trim inventory, tb[{tb_name}] vm_base [{vm_base}], inv file {inv_files}")

    # Find a key in all the levels of a dict,
    # Return the val of the key and the vm_base_path of the key
    def find_key(d: dict, target_key: str = None, regex: str = None):
        # Stack to keep track of dictionaries and their paths
        stack = [(d, [])]
        while stack:
            current_dict, path = stack.pop()
            for key, value in current_dict.items():
                # If regex is passed, use regex to match
                if regex and re.match(regex, key):
                    return value, path + [key]
                # If regex is None, exact match
                if key == target_key:
                    return value, path + [key]
                if isinstance(value, dict):
                    stack.append((value, path + [key]))
        return None, []

    # Remove all the matched
    for idx in range(len(inv_files)):
        inv_file = inv_files[idx]
        with open(inv_file, 'r') as file:
            inv = yaml.safe_load(file)
            # If the vm_base is found in the inv_file,
            # then other useless topology neighbor definition are in it,
            # that's the inventory to be trimmed
            _, vm_base_path = find_key(d=inv, target_key=vm_base)
            if vm_base_path:
                keys_to_del = set()
                logger.info(f"Find vm_base {vm_base} in inv file {inv_file}, path: {vm_base_path}")

                for root_key in inv.keys():
                    neighbor_val, neighbor_path = find_key(d=inv[root_key], regex=pattern)
                    if neighbor_path:
                        # Keep the neighbor server for the testbed
                        if root_key == vm_base_path[0]:
                            logger.info(f"vm_base[{vm_base}] located in {root_key}, inv file {inv_file}, keep it")
                        # Remove all the useless neighbor server ansible_hosts
                        else:
                            logger.info(f"Attempt to remove {root_key} in inv file {inv_file}")
                            keys_to_del.add(root_key)

                for key_to_del in keys_to_del:
                    del inv[key_to_del]

                # dump and replace trimmed inventory file
                trimmed_inventory_file_name = f"{inv_file}_{tb_name}_trim_tmp"
                with BlankNone(), open(trimmed_inventory_file_name, 'w') as f:
                    yaml.dump(inv, f)

                inv_files[idx] = trimmed_inventory_file_name
