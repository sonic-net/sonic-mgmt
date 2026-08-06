import logging
import re

import yaml

from tests.common.helpers.yaml_utils import BlankNone

logger = logging.getLogger(__name__)


def trim_inventory(inv_files, tbinfo, target_hostname):
    """
    Trim the useless topology neighbor the inv_files according to testbed to speed up ansible inventory initialization.

    For every test server, we pre-define ~100 ansible_hosts for the neighbors.
    We put all of the ansible_hosts of test servers into one inventory file.
    The inventory file contains thousands of ansible_hosts, but most of them are useless to the selected testbed,
    Because the testbed only need the definition of the neighbor for its neighbor server.

    During the establishment of the ansible_host, it iterate and compute the ansible_host one by one,
    The useless ansible_host extremely slow down the initialization.

    Hence, will trim and generate a temporary inventory file, for example:
    ['../ansible/veos', '../ansible/lab1'] -> ['../ansible/veos_kvm-t0_trim_tmp', '../ansible/lab1_kvm-t0_trim_tmp']
    Then pytest will use the light inventory files '../ansible/veos_kvm-t0_trim_tmp' and
    '../ansible/lab1_kvm-t0_trim_tmp' to initialize the ansible_hosts.

    Args:
        inv_files: inventory file list, sample: ['../ansible/veos', '../ansible/lab1']
        tbinfo: tbinfo
        target_hostname: target_hostname, will be None if parallel run is disabled

    Returns:
        Direct update inv_files and return nothing
    """

    vm_base = tbinfo.get("vm_base", None)
    tb_name = tbinfo.get("conf-name", None)
    ptf = tbinfo.get("ptf", None)
    inv_name = tbinfo.get("inv_name", None)
    duts = tbinfo.get("duts", None)

    pattern = r'VM\d{3,7}'

    # TODO: Trim fanout hosts and PDU hosts. Currently blocked by https://github.com/sonic-net/sonic-mgmt/issues/17347
    logger.info(f"Start to trim inventory, inv_files: {inv_files}, vm_base: {vm_base}, tb_name: {tb_name}, "
                f"ptf: {ptf}, inv_name: {inv_name}, duts: {duts}")

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

    def get_value_by_key_path(d: dict, key_path: list):
        for k in key_path:
            d = d[k]

        return d

    def dump_trimmed_inv_to_file(trimmed_inv, trimmed_inventory_file_name):
        with BlankNone(), open(trimmed_inventory_file_name, 'w') as f:
            yaml.dump(trimmed_inv, f)

    # Remove all the unnecessary nodes in the inventory file(s)
    for idx in range(len(inv_files)):
        inv_file = inv_files[idx]
        if target_hostname is not None:
            trimmed_inv_file_name = f"{inv_file}_{tb_name}_{target_hostname}_trim_tmp"
        else:
            trimmed_inv_file_name = f"{inv_file}_{tb_name}_trim_tmp"

        with open(inv_file, 'r') as file:
            inv = yaml.safe_load(file)
            if inv_file.split('/')[-1] == inv_name:

                def trim_value_of_key_path(key_path, keys_to_keep):
                    original_val = get_value_by_key_path(d=inv, key_path=key_path)
                    all_keys = set(original_val.keys())
                    for key in all_keys:
                        if key not in keys_to_keep:
                            del original_val[key]

                vars_to_trim = ["ptf", "hwsku"]
                for var in vars_to_trim:
                    if var == "ptf" and ptf:
                        _, ptf_key_path = find_key(d=inv, target_key=ptf)
                        if ptf_key_path:
                            logger.info(f"Keep PTF host {ptf} and trim the rest PTF hosts")
                            trim_value_of_key_path(ptf_key_path[:-1], {ptf})
                    elif var == "hwsku" and duts:
                        # We have all the user-defined HwSKUs as the root keys of this inv file, and these
                        # HwSKUs combined should be a subset of the keys under the sonic.children node.
                        # We want to keep the active HwSKU(s) based on the DUTs info and trim the rest.
                        # Besides, we should also trim the DUT hosts under active HwSKU(s) based on DUTs info.
                        # Note: if we find an active DUT's HwSKU is somehow not a value under sonic.children node,
                        # we will skip the HwSKU trimming to avoid potential data loss.
                        all_hwskus = set(inv["sonic"]["children"].keys())
                        should_trim_hwsku = True
                        hwskus_to_keep = dict()
                        for dut in duts:
                            _, dut_key_path = find_key(d=inv, target_key=dut)
                            curr_hwksu = dut_key_path[0] if dut_key_path else None
                            if not curr_hwksu or curr_hwksu in hwskus_to_keep:
                                continue

                            if curr_hwksu in all_hwskus:
                                hwskus_to_keep[curr_hwksu] = dut_key_path
                            else:
                                logger.warning(
                                    f"DUT {dut}'s hwsku is not a value under sonic.children node, skip trimming hwsku"
                                )

                                should_trim_hwsku = False
                                break

                        if should_trim_hwsku:
                            for hwsku in all_hwskus:
                                if hwsku in hwskus_to_keep:
                                    trim_value_of_key_path(hwskus_to_keep[hwsku][:-1], set(duts))
                                else:
                                    del inv["sonic"]["children"][hwsku]
                                    if hwsku in inv:
                                        logger.info(f"Attempt to delete {hwsku} in inv file {inv_file}")
                                        del inv[hwsku]
                    else:
                        logger.warning(f"Unknown or invalid var {var} to trim")

                dump_trimmed_inv_to_file(inv, trimmed_inv_file_name)
                inv_files[idx] = trimmed_inv_file_name
            else:
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

                    dump_trimmed_inv_to_file(inv, trimmed_inv_file_name)
                    inv_files[idx] = trimmed_inv_file_name
