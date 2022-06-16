import imp
import os
import logging
import sys
import json
import argparse


ANSIBLE_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(ANSIBLE_DIR)
TESTBED_FILE = 'testbed.yaml'
SONIC_TESTBED_HEALTH_FILE = 'testbed_ping.json'

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

def get_dut_tbname_map():
    """Return a dictionary containing mapping from dut hostname to testbed name."""
    testbed = imp.load_source('testbed', os.path.join(SONIC_MGMT_DIR, 'tests/common/testbed.py'))
    dut_tbname_map = {}
    for tbname, tb in testbed.TestbedInfo(TESTBED_FILE).testbed_topo.items():
        for duthost in tb['duts']:
            dut_tbname_map[duthost] = tbname

    return dut_tbname_map

def parse_ping_result(ping_results, dut_tbname_map, skip_testbeds):
    """Parse ping results of devutils to kusto table data format."""
    final_results = []
    for dut_ping_result in ping_results:
        dut_result = {}
        dut_result['DeviceName'] = dut_ping_result['Host']
        dut_result['IP'] = dut_ping_result['Hostname']
        dut_result['IcmpReachability'] = 1 if dut_ping_result['Ping result'] == 'Success' else 0
        # TODO Currently, ConsoleReachability and SshReachability is not used.
        dut_result['ConsoleReachability'] = None
        dut_result['SshReachability'] = None
        if dut_result['DeviceName'] in dut_tbname_map:
            testbed_name = dut_tbname_map[dut_result['DeviceName']]
            if skip_testbeds and skip_testbeds != '' and testbed_name in skip_testbeds:
                continue
            dut_result['TestbedName'] = testbed_name
        else:
            logging.error("Didn't find the match testbed name for host {}".format(dut_result['DeviceName']))

        final_results.append(dut_result)
    return final_results

def run_devutils(skip_testbeds):
    """Run devutils to check icmp reachability for testbeds"""
    groups = ['str', 'str2', 'strsvc']

    health_results = []
    dut_tbname_map = get_dut_tbname_map()

    for group in groups:
        input_file_name ='ping_{}.json'.format(group)
        command = './devutils -i {} -a ping -g sonic -j > {}'.format(group, input_file_name)
        logging.info('Start running command %s', command)

        returncode = os.system(command)

        if returncode == 0:
            logging.info('Finish running devutils')
        else:
            logging.error('Fail to run devutils')

        with open(input_file_name) as input_file:
            ping_results = json.load(input_file)

        results = parse_ping_result(ping_results, dut_tbname_map, skip_testbeds)
        health_results.extend(results)
 

    with open(SONIC_TESTBED_HEALTH_FILE, 'w') as fp:
        json.dump(health_results, fp, indent=4)
        logging.info("Save results into file {}".format(SONIC_TESTBED_HEALTH_FILE))
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get testbed health status.')
    parser.add_argument('--skip-testbeds', default='', type=str, required=False, help='testbeds to skip')
    parser.add_argument('--log-level', choices=['debug', 'info', 'warn', 'error', 'critical'], default='info', help='logging output level')
    args = parser.parse_args()

    skip_testbeds = args.skip_testbeds
    log_level = args.log_level

    handler.setLevel(getattr(logging, log_level.upper()))
    if skip_testbeds or skip_testbeds != '':
        skip_testbeds = skip_testbeds.split(',')
    run_devutils(skip_testbeds)
