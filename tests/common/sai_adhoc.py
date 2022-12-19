"""
This script is providing an API for SAI testing initialization via Ansible module
"""
from __future__ import print_function
import json
import subprocess
import logging
import argparse
import yaml
from yaml.loader import SafeLoader

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
logger.addHandler(handler)


def get_info_helper(conf_name):
    """
        Return corresponding dut name, ptf name and inventory file name from testbed.yaml
        param: 
            conf_name : configuration name in testbed.yaml
    """
    with open('./ansible/testbed.yaml') as f:
        testbed_infos = yaml.load(f, Loader=SafeLoader)
        for testbed_info in testbed_infos:
            if(testbed_info['conf-name'] == conf_name):
                #to do: please consider dualtor scenario
                return testbed_info['dut'][0], testbed_info['ptf'], testbed_info['inv_name']
    logger.error("Failed to find testbed {}".format(conf_name))


def get_raw_output(ansible_cmd, param_cmd):
    """
        Return raw output from Ansible ad-hoc command 
        param: 
            ansible_cmd : original Ansible ad-hoc command
            param_cmd : customized command
    """
    try:
        logger.info("running ad-hoc command: {} {}".format(ansible_cmd, param_cmd))
        final_cmd = ansible_cmd.split()
        final_cmd.append(param_cmd)
        raw_output = subprocess.check_output(final_cmd).decode('utf-8')
    except Exception as e:
        logger.error('Failed to run command, exception: {}'.format(repr(e)))

    return raw_output



def run_command(host, inv_file, cmd):
    """
    Run 'command' Ansible customized ad-hoc command implemented under ansible/library
    param: 
        host: either DUT hostname or PTF hostname
        inv_file : inventory
        cmd : customized command"
    """
    results = []
    try:
        ansible_cmd = 'ansible -m shell -i ./ansible/{} {} -o -a'.format(inv_file, host)
        raw_output = get_raw_output(ansible_cmd, cmd)
        output_fields = raw_output.split('(stdout)', 1)[-1].strip()
        output_fields = output_fields.split('\n', 1)[0]
        print(output_fields)
        results = output_fields
    except Exception as e:
        logger.error('Failed to run command, exception: {}'.format(repr(e)))

    logger.info(results)
    return results

def run_copy(host, inv_file, cmd):
    """
        Run 'copy' Ansible ad-hoc command
        param: 
            host: either DUT hostname or PTF hostname
            inv_file : inventory
            cmd : must in format of "src=<path> dest=<path>"
    """
    try:
        ansible_cmd = 'ansible -m copy -i ./ansible/{} {} -o -a'.format(inv_file, host)
        raw_output = get_raw_output(ansible_cmd, cmd)

        output_fields = ""
        if 'CHANGED =>' in raw_output:
            output_fields = raw_output.split('CHANGED =>', 1)
        elif 'SUCCESS =>' in raw_output:
            output_fields = raw_output.split('SUCCESS =>', 1)
        else:
            raise Exception("Failed copying file")

        file_dest = json.loads(output_fields[1].strip())["dest"]
        logger.info("Copying to {}".format(file_dest))
    except Exception as e:
        logger.error('Failed to run command, exception: {}'.format(repr(e)))


def run_fetch(host, inv_file, cmd):
    """
        Run 'fetch' Ansible ad-hoc command
        param: 
            host: either DUT hostname or PTF hostname
            inv_file : inventory
            cmd : must in format of "src=<path> dest=<path> flat=<true or false>"
    """
    try:
        ansible_cmd = 'ansible -m fetch -i ./ansible/{} {} -o -a'.format(inv_file, host)
        raw_output = get_raw_output(ansible_cmd, cmd)

        output_fields = ""
        if 'CHANGED =>' in raw_output:
            output_fields = raw_output.split('CHANGED =>', 1)
        else:
            raise Exception("Failed copying file")

        file_dest = json.loads(output_fields[1].strip())["dest"]
        logger.info("Fetching file to {}".format(file_dest))
    except Exception as e:
        logger.error('Failed to run command, exception: {}'.format(repr(e)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""
        Taking different parameters for running command on either DUT or PTF during SAI testing.
        """
    )

    parser.add_argument("--type", type=str, dest="host_type", choices=["dut", "ptf"], help="host type", required=True)
    parser.add_argument("-t", dest="exe_type", type=str, choices=["cmd", "copy", "fetch"], help="execution type", required=True)
    parser.add_argument("-n", dest="host_name", type=str, help="host name", required=True)
    parser.add_argument("-c", dest="command", type=str, help="command")

    args = parser.parse_args()
    
    dut, ptf, inv_name = get_info_helper(args.host_name)

    if args.host_type =='dut':
        host = dut
    elif args.host_type =='ptf':
        host = ptf

    if args.exe_type == "cmd":
        run_command(host, inv_name, args.command)
    elif args.exe_type == "copy":
        run_copy(host, inv_name, args.command)
    elif args.exe_type == "fetch":
        run_fetch(host, inv_name, args.command)
    else:
        print("Error: Execution type does not match, which can only be [cmd|copy|fetch].")
