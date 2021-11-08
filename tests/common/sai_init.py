"""
This script is providing an API for SAI testing initialization via Ansible module
"""
from __future__ import print_function
import json
import logging
import subprocess
import argparse

logger = logging.getLogger(__name__)

def get_raw_output(ansible_cmd, param_cmd):
    """
    Return raw output from Ansible ad-hoc command 
    param: 
        ansible_cmd : original Ansible ad-hoc command
        param_cmd : customized commands
    """
    try:
        logger.info("running ad-hoc command: {} {}".format(ansible_cmd, param_cmd))
        final_cmds = ansible_cmd.split()
        final_cmds.append(param_cmd)
        raw_output = subprocess.check_output(final_cmds).decode('utf-8')
    except Exception as e:
        logger.error('Failed to run commands, exception: {}'.format(repr(e)))

    return raw_output


def run_command(host, inv_file, cmds):
    """
    Run 'shell_cmds' Ansible customized ad-hoc command implemented under ansible/library
    param: 
        host: either DUT hostname or PTF hostname
        inv_file : inventory
        cmds : customized commands, seperate them with comma and no space between cmds if multiple input. e.g "who,ls /tmp"
    """
    results = []
    try:
        cmds_list = 'cmds={{' + str(cmds.split(",")) + '}}'
        ansible_cmd = 'ansible -m shell_cmds -i ../ansible/{} {} -o -a'.format(inv_file, host)
        raw_output = get_raw_output(ansible_cmd, cmds_list)

        output_fields = raw_output.split('SUCCESS =>', 1)
        if len(output_fields) >= 2:
            results = json.loads(output_fields[1].strip(), strict=False)['results']
    except Exception as e:
        logger.error('Failed to run commands, exception: {}'.format(repr(e)))

    logger.info(results)


def run_copy(host, inv_file, cmds):
    """
    Run 'copy' Ansible ad-hoc command
    param: 
        host: either DUT hostname or PTF hostname
        inv_file : inventory
        cmds : must in format of "src=<path> dest=<path>"
    """
    try:
        ansible_cmd = 'ansible -m copy -i ../ansible/{} {} -o -a'.format(inv_file, host)
        raw_output = get_raw_output(ansible_cmd, cmds)

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
        logger.error('Failed to run commands, exception: {}'.format(repr(e)))


def run_fetch(host, inv_file, cmds):
    """
    Run 'fetch' Ansible ad-hoc command
    param: 
        host: either DUT hostname or PTF hostname
        inv_file : inventory
        cmds : must in format of "src=<path> dest=<path> flat=<true or false>"
    """
    try:
        ansible_cmd = 'ansible -m fetch -i ../ansible/{} {} -o -a'.format(inv_file, host)
        raw_output = get_raw_output(ansible_cmd, cmds)

        output_fields = ""
        if 'CHANGED =>' in raw_output:
            output_fields = raw_output.split('CHANGED =>', 1)
        else:
            raise Exception("Failed copying file")

        file_dest = json.loads(output_fields[1].strip())["dest"]
        logger.info("Fetching file to {}".format(file_dest))
    except Exception as e:
        logger.error('Failed to run commands, exception: {}'.format(repr(e)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""
        Taking different parameters for running commands on either DUT or PTF during SAI testing.
        """
    )

    host = parser.add_mutually_exclusive_group(required=True)
    host.add_argument("--ptf", type=str, dest="ptf_name", help="ptf name")
    host.add_argument("--dut", type=str, dest="dut_name", help="dut name")

    parser.add_argument("-c", dest="commands", type=str, help="commands, seprate with comma if multiple")
    parser.add_argument("-t", dest="exe_type", type=str, choices=["cmds", "copy", "fetch"], help="execution type", required=True)
    parser.add_argument("-i", dest="inv_file", type=str, help="inventory file", required=True)

    args = parser.parse_args()
    host = args.ptf_name or args.dut_name

    if args.exe_type == "cmds":
        run_command(host, args.inv_file, args.commands)
    elif args.exe_type == "copy":
        run_copy(host, args.inv_file, args.commands)
    elif args.exe_type == "fetch":
        run_fetch(host, args.inv_file, args.commands)
    else:
        pass
