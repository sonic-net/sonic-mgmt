#!/usr/bin/env python3
import os
import logging
import sys
import json
import argparse
try:
    from ansible.parsing.dataloader import DataLoader
    from ansible.inventory.manager import InventoryManager
    has_ansible = True
except ImportError:
    # ToDo: Support running without Ansible
    has_ansible = False
from devutil.conn_graph_helper import load_source

ANSIBLE_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(ANSIBLE_DIR)
TESTBED_FILE = 'testbed.yaml'
SONIC_TESTBED_HEALTH_FILE = 'testbed_ping.json'
SERVER_INVENTORY = "veos"
GROUPS = ['str', 'str2', 'strsvc']

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

server_host_map = {}


def get_testbeds_dict():
    """Return a dictionary containing mapping from dut hostname to testbed name."""
    testbed = load_source('testbed', os.path.join(
        SONIC_MGMT_DIR, 'tests/common/testbed.py'))
    testbeds_dict = testbed.TestbedInfo(TESTBED_FILE).testbed_topo
    return testbeds_dict


def _get_admin_down_dpu_hostnames(tbinfo):
    """Return the set of DPU hostnames administratively down for a testbed.

    Mirrors ``tests.common.helpers.dut_utils.get_admin_down_dpu_hostnames`` but
    kept self-contained so this ansible-side script has no dependency on the
    pytest tree.

    A DPU hostname has the form ``<npu_hostname>-dpu-<index>``. The testbed.yaml
    ``enabled_dpus`` mapping lists the DPU indices that should be admin-up for
    each NPU; any DPU index missing from that list is treated as admin-down.

    If ``enabled_dpus`` is absent for the testbed, returns an empty set
    (legacy behavior).
    """
    admin_down = set()
    if not tbinfo:
        return admin_down

    enabled_dpus = tbinfo.get('enabled_dpus')
    if not enabled_dpus:
        return admin_down

    duts = tbinfo.get('duts', []) or []
    for npu_host, dpu_entries in enabled_dpus.items():
        enabled_indices = set()
        for entry in (dpu_entries or []):
            if isinstance(entry, dict) and 'dpu_index' in entry:
                try:
                    enabled_indices.add(int(entry['dpu_index']))
                except (TypeError, ValueError):
                    continue
            else:
                try:
                    enabled_indices.add(int(entry))
                except (TypeError, ValueError):
                    continue

        prefix = "{}-dpu-".format(npu_host)
        for dut in duts:
            if not dut.startswith(prefix):
                continue
            suffix = dut[len(prefix):]
            try:
                idx = int(suffix)
            except ValueError:
                continue
            if idx not in enabled_indices:
                admin_down.add(dut)

    return admin_down


def get_server_host(inventory_files, server):
    if not has_ansible:
        raise Exception("Ansible is needed for this module")
    dataloader = DataLoader()
    inv_mgr = InventoryManager(loader=dataloader, sources=inventory_files)

    hosts = inv_mgr.get_hosts(pattern=server)

    for host in hosts:
        if "vm_host" in [group.name for group in host.groups]:
            server_host_map[server] = host.name.lower()
            return host.name.lower()
    logging.error("Can't find host for server {}".format(server))
    return


def parse_ping_result(ping_dict, testbeds_dict, skip_testbeds):
    """
    Parse ping results of devutils to kusto table data format.
    The final data looks like this:
    [
        {
            "TestbedName": "vms1-1",
            "DutIP": "10.10.10.10",
            "ServerName": "server-1",
            "ServerIcmpReachability": 1,
            "DutName": "str-1",
            "DutIcmpReachability": 1,
            "PtfIP": "20.20.20.20",
            "ServerIP": "30.30.30.30",
            "DutConsoleReachability": null,
            "PtfName": "ptf-1",
            "DutSshReachability": null,
            "PtfIcmpReachability": 1
        }
    ]
    """
    final_results = []
    for testbed_name, tbinfo in testbeds_dict.items():
        admin_down_dpus = _get_admin_down_dpu_hostnames(tbinfo)
        for duthost in tbinfo['duts']:
            # Skip DPU hostnames that are administratively down per testbed.yaml
            # `enabled_dpus` mapping. These DPUs are intentionally offline and
            # should not affect testbed health reporting.
            if duthost in admin_down_dpus:
                logging.debug(
                    "Skipping admin-down DPU %s in testbed %s",
                    duthost, testbed_name)
                continue
            device_result = {}
            # skip defined testbeds
            if skip_testbeds and skip_testbeds != '' and testbed_name in skip_testbeds:
                continue
            device_result['TestbedName'] = testbed_name
            server = tbinfo['server']
            if server in server_host_map:
                logging.debug("Server {} has already found.".format(server))
                server_host = server_host_map[server]
            else:
                server_host = get_server_host(SERVER_INVENTORY, server)
            ptf = tbinfo['ptf']
            if duthost in ping_dict:
                device_result['DutName'] = ping_dict[duthost]['Host']
                device_result['DutIcmpReachability'] = 1 if ping_dict[duthost]['Ping result'] == 'Success' else 0
                device_result['DutIP'] = ping_dict[duthost]['Hostname']
                # TODO Currently, ConsoleReachability and SshReachability is not used.
                device_result['DutConsoleReachability'] = None
                device_result['DutSshReachability'] = None
            if server_host and server_host in ping_dict:
                device_result['ServerName'] = ping_dict[server_host]['Host']
                device_result['ServerIcmpReachability'] = 1 if ping_dict[server_host]['Ping result'] == 'Success' else 0
                device_result['ServerIP'] = ping_dict[server_host]['Hostname']
            if ptf and ptf in ping_dict:
                device_result['PtfName'] = ping_dict[ptf]['Host']
                device_result['PtfIcmpReachability'] = 1 if ping_dict[ptf]['Ping result'] == 'Success' else 0
                device_result['PtfIP'] = ping_dict[ptf]['Hostname']

            final_results.append(device_result)
    return final_results


def run_devutils(skip_testbeds):
    """Run devutils to check icmp reachability for testbeds"""

    health_results = []
    ping_results = []
    testbeds_dict = get_testbeds_dict()

    for group in GROUPS:
        input_file_name = 'ping_{}.json'.format(group)
        command_dut = './devutils -i {} -a ping -j > {}'.format(
            group, input_file_name)
        logging.info('Start running command %s', command_dut)

        returncode = os.system(command_dut)
        if returncode == 0:
            logging.info('Finish running devutils for group {}'.format(group))
        else:
            logging.error('Fail to run devutils for group {}'.format(group))

        with open(input_file_name) as input_file:
            results = json.load(input_file)

        ping_results.extend(results)

    # reconstruct ping results data to dictionary, set Host as key
    ping_dict = {}
    for item in ping_results:
        ping_dict.update({item['Host']: item})

    health_results = parse_ping_result(ping_dict, testbeds_dict, skip_testbeds)

    with open(SONIC_TESTBED_HEALTH_FILE, 'w') as fp:
        json.dump(health_results, fp, indent=4)
        logging.info("Save results into file {}".format(
            SONIC_TESTBED_HEALTH_FILE))
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get testbed health status.')
    # skip-testbeds is seperated by ","
    parser.add_argument('--skip-testbeds', default='',
                        type=str, required=False, help='testbeds to skip')
    parser.add_argument('--log-level', choices=['debug', 'info', 'warn',
                        'error', 'critical'], default='info', help='logging output level')
    args = parser.parse_args()

    skip_testbeds = args.skip_testbeds
    log_level = args.log_level

    handler.setLevel(getattr(logging, log_level.upper()))
    if skip_testbeds or skip_testbeds != '':
        skip_testbeds = skip_testbeds.split(',')

    run_devutils(skip_testbeds)
