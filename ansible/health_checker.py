import imp
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
    testbed = imp.load_source('testbed', os.path.join(SONIC_MGMT_DIR, 'tests/common/testbed.py'))
    testbeds_dict = testbed.TestbedInfo(TESTBED_FILE).testbed_topo
    return testbeds_dict

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
        for duthost in tbinfo['duts']:
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
        input_file_name ='ping_{}.json'.format(group)
        command_dut = './devutils -i {} -a ping -j > {}'.format(group, input_file_name)
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
        logging.info("Save results into file {}".format(SONIC_TESTBED_HEALTH_FILE))
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get testbed health status.')
    # skip-testbeds is seperated by ","
    parser.add_argument('--skip-testbeds', default='', type=str, required=False, help='testbeds to skip')
    parser.add_argument('--log-level', choices=['debug', 'info', 'warn', 'error', 'critical'], default='info', help='logging output level')
    args = parser.parse_args()

    skip_testbeds = args.skip_testbeds
    log_level = args.log_level

    handler.setLevel(getattr(logging, log_level.upper()))
    if skip_testbeds or skip_testbeds != '':
        skip_testbeds = skip_testbeds.split(',')

    run_devutils(skip_testbeds)
