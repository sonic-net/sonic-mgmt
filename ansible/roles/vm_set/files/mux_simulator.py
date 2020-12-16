#!/usr/bin/env python
"""This script is to simulate mux on test server.

It exposes HTTP API for external parties to query and switch mux active/standby status. When the APIs
are called, it use ovs commands to get and set the OVS bridge for simulating mux behavior.

This script should be started keep running in background when a topology is created by 'testbed-cli.sh add-topo'.
"""
from __future__ import print_function
import json
import os
import re
import subprocess
import sys

from collections import defaultdict

from flask import Flask, request, jsonify


app = Flask(__name__)


def run_cmd(cmdline):
    """Use subprocess to run a command line with shell=True

    Args:
        cmdline (string): The command line to be executed.

    Raises:
        Exception: If return code of running command line is not zero, an exception is raised.

    Returns:
        string: The stdout of running the command line.
    """
    process = subprocess.Popen(
        cmdline.split(),                          # lgtm [py/command-line-injection]
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    ret_code = process.returncode

    if ret_code != 0:
        raise Exception('ret_code={}, error message="{}". cmd={}'.format(ret_code, stderr, cmdline))

    return stdout.decode('utf-8')


def get_mux_connections(vm_set, port_index):
    """Use the 'ovs-ofctl show' command to get details of the bridge and interfaces simulating mux.

    Example bridge name: 'mbr-vms17-8-0'. In the bridge name, 'vms17-8' is vm_set. '0' is port_index.

    Example output of 'ovs-ofctl show' command:
      azure@str2-acs-serv-17:~$ sudo ovs-ofctl --names show mbr-vms17-8-0
      OFPT_FEATURES_REPLY (xid=0x2): dpid:000098039b0322d9
      n_tables:254, n_buffers:0
      capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
      actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
       1(muxy-vms17-8-0): addr:f2:3d:28:15:99:37
           config:     0
           state:      0
           current:    10GB-FD COPPER
           speed: 10000 Mbps now, 0 Mbps max
       2(enp59s0f1.3216): addr:98:03:9b:03:22:d9
           config:     0
           state:      0
           current:    AUTO_NEG
           advertised: 10GB-FD AUTO_NEG AUTO_PAUSE
           supported:  10GB-FD AUTO_NEG AUTO_PAUSE
           speed: 0 Mbps now, 10000 Mbps max
       3(enp59s0f1.3272): addr:98:03:9b:03:22:d9
           config:     0
           state:      0
           current:    AUTO_NEG
           advertised: 10GB-FD AUTO_NEG AUTO_PAUSE
           supported:  10GB-FD AUTO_NEG AUTO_PAUSE
           speed: 0 Mbps now, 10000 Mbps max
       LOCAL(mbr-vms17-8-0): addr:98:03:9b:03:22:d9
           config:     0
           state:      0
           speed: 0 Mbps now, 0 Mbps max
      OFPT_GET_CONFIG_REPLY (xid=0x4): frags=normal miss_send_len=0

    Example result or parsing the output using regex:
      >>> re.findall(r'(\d|LOCAL)\((\S+)\):\s+addr:[0-9a-f:]{17}', out)
      [('1', 'muxy-vms17-8-0'), ('2', 'enp59s0f1.3216'), ('3', 'enp59s0f1.3272'), ('LOCAL', 'mbr-vms17-8-0')]

    Args:
        vm_set (string): The vm_set of test setup.
        port_index (int or string): Index of the port.

    Returns:
        dict: Returns the mux connection details in a dictionary. Example:
            {
                "bridge": "mbr-vms17-8-0",
                "vm_set": "vms17-8",
                "port_index": 0,
                "ports": {
                    "nic": "muxy-vms17-8-0",
                    "tor_a": "enp59s0f1.3216",
                    "tor_b": "enp59s0f1.3272"
                },
                "active_side": "tor_a"
            }
    """
    cmdline = 'ovs-ofctl --names show mbr-{}-{}'.format(vm_set, port_index)
    out = run_cmd(cmdline)

    parsed = re.findall(r'(\d|LOCAL)\((\S+)\):\s+addr:[0-9a-f:]{17}', out)
    # Example of 'parsed':

    mux_status = defaultdict(dict)
    mux_status['vm_set'] = vm_set
    mux_status['port_index'] = port_index
    mux_status['ports']['nic'] = parsed[0][1]
    mux_status['ports']['tor_a'] = parsed[1][1]
    mux_status['ports']['tor_b'] = parsed[2][1]
    mux_status['bridge'] = parsed[3][1]
    return mux_status


def get_flows(vm_set, port_index):
    """Use the 'ovs-ofctl dump-flows' command to get the open flow details of a bridge simulating mux.

    Example output of the 'ovs-ofctl dump-flows' command:
      azure@str2-acs-serv-17:~$ sudo ovs-ofctl --names dump-flows mbr-vms17-8-0
       cookie=0x0, duration=86737.831s, table=0, n_packets=446, n_bytes=44412, in_port="muxy-vms17-8-0" actions=output:"enp59s0f1.3216",output:"enp59s0f1.3272"
       cookie=0x0, duration=86737.819s, table=0, n_packets=10251, n_bytes=1179053, in_port="enp59s0f1.3216" actions=output:"muxy-vms17-8-0"

    Example result of parsing the output using regex:
      >>> re.findall(r'in_port="(\S+)"\s+actions=(\S+)', out)
      [('muxy-vms17-8-0', 'output:"enp59s0f1.3216",output:"enp59s0f1.3272"'), ('enp59s0f1.3216', 'output:"muxy-vms17-8-0"')]

    Args:
        vm_set (string): The vm_set of test setup.
        port_index (int or string): Index of the port.

    Returns:
        dict: Return the result in dict. Example:
            {
                "muxy-vms17-8-0":
                [
                    {
                        "action": "output",
                        "out_port": "enp59s0f1.3216"
                    },
                    {
                        "action": "output",
                        "out_port": "enp59s0f1.3272"
                    }
                ],
                "enp59s0f1.3216":
                [
                    {
                        "action": "output",
                        "out_port": "muxy-vms17-8-0"
                    }
                ]
            }
    """

    cmdline = 'ovs-ofctl --names dump-flows mbr-{}-{}'.format(vm_set, port_index)
    out = run_cmd(cmdline)

    parsed = re.findall(r'in_port="(\S+)"\s+actions=(\S+)', out)

    flows = {}
    for in_port, actions_desc in parsed:
        actions = []
        for field in actions_desc.split(','):
            action, out_port = re.search(r'(\S+):"(\S+)"', field).groups()
            actions.append({'action': action, 'out_port': out_port})
        flows[in_port] = actions

    return flows


def get_active_port(flows):
    """Find the active port name based on knowledge that down stream traffic is only output to the 'nic' interface.

    Args:
        flows (dict): Open flow details of the mux, result returned from function get_flows

    Returns:
        string or None: Name of the active port or None if something is wrong.
    """
    for in_port, actions in flows.items():
        if len(actions) == 1:
            return in_port
    return None


def get_mux_status(vm_set, port_index):
    """Use other functions to get overall status of the mux.

    Args:
        vm_set (string): The vm_set of test setup.
        port_index ([type]): Index of the port.

    Raises:
        Exception: If no active port is found, raise an exception.

    Returns:
        dict: A dictionary contains full mux status, including connection details, open flow details and active side
        information. Example:
            {
                "bridge": "mbr-vms17-8-0",
                "vm_set": "vms17-8",
                "port_index": 0,
                "ports": {
                    "nic": "muxy-vms17-8-0",
                    "tor_a": "enp59s0f1.3216",
                    "tor_b": "enp59s0f1.3272"
                },
                "active_side": "tor_a",
                "flows": {
                    "muxy-vms17-8-0":
                    [
                        {
                            "action": "output",
                            "out_port": "enp59s0f1.3216"
                        },
                        {
                            "action": "output",
                            "out_port": "enp59s0f1.3272"
                        }
                    ],
                    "enp59s0f1.3216":
                    [
                        {
                            "action": "output",
                            "out_port": "muxy-vms17-8-0"
                        }
                    ]
                }
            }
    """

    mux_status = get_mux_connections(vm_set, port_index)
    flows = get_flows(vm_set, port_index)
    mux_status['flows'] = flows
    active_port = get_active_port(flows)
    if not active_port:
        raise Exception('Unable to find active port. flows: {}'.format(json.dumps(flows)))
    for side, port in mux_status['ports'].items():
        if port == active_port:
            mux_status['active_side'] = side
    return mux_status


def set_active_side(vm_set, port_index, new_active_side):
    """Change the open flow configurations to set the active side to the value specified by argument 'new_active_side'.

    Args:
        vm_set (string): The vm_set of test setup.
        port_index ([type]): Index of the port.
        new_active_side (string): Either "tor_a" or "tor_b".

    Returns:
        dict: Return the new full mux status in a dictionary.
    """
    mux_status = get_mux_status(vm_set, port_index)
    if mux_status['active_side'] == new_active_side:
        return mux_status

    flows = get_flows(vm_set, port_index)
    active_port = get_active_port(flows)
    nic_port = mux_status['ports']['nic']
    new_active_port = mux_status['ports'][new_active_side]
    run_cmd('ovs-ofctl --names del-flows mbr-{}-{} in_port="{}"'.format(vm_set, port_index, active_port))
    run_cmd('ovs-ofctl --names add-flow  mbr-{}-{} in_port="{}",actions=output:"{}"'
        .format(vm_set, port_index, new_active_port, nic_port))
    mux_status['active_side'] = new_active_side
    return mux_status


def _validate_param(vm_set, port_index=None):
    """Validate the vm_set and port_index argument.

    Args:
        vm_set (string): The vm_set of test setup.
        port_index ([type]): Index of the port.

    Returns:
        tuple: Return the result in a tuple. The first item is either True or False. The second item is extra message.
    """
    pattern = 'mbr-{}'.format(vm_set)
    if port_index:
        pattern += '-{}'.format(port_index)
    if any([intf.startswith(pattern) for intf in os.listdir('/sys/class/net')]):
        return True, ''
    else:
        return False, 'No interface matches {}'.format(pattern)


def _validate_posted_data(data):
    """Validate json data in POST request.

    Args:
        data (dict): Data included in the POST request.

    Returns:
        tuple: Return the result in a tuple. The first item is either True or False. The second item is extra message.
    """
    if 'active_side' in data and data['active_side'] in ['tor_a', 'tor_b']:
        return True, ''
    return False, 'Bad posted data, expected: {"active_side": "tor_a|tor_b"}'


@app.route('/mux/<vm_set>/<port_index>', methods=['GET', 'POST'])
def mux_cable(vm_set, port_index):
    """Handler for requests to /mux/<vm_set>/<port_index>.

    For GET request, return detailed status of mux specified by vm_set and port_index.
    For POST request, set mux active side to the one specified in the posted json data.

    Args:
        vm_set (string): The vm_set of test setup. Parsed by flask from request URL.
        port_index (string): Index of the port. Parsed by flask from request URL.

    Returns:
        object: Return a flask response object.
    """
    valid, msg = _validate_param(vm_set, port_index)
    if not valid:
        return jsonify({'err_msg': msg}), 400

    if request.method == 'GET':
        # Get mux status
        try:
            mux_status = get_mux_status(vm_set, port_index)
            return jsonify(mux_status)
        except Exception as e:
            return jsonify({'err_msg': 'Get mux status failed: {}'.format(repr(e))}), 500
    else:
        # Set the active side of mux
        data = request.get_json()
        valid, msg = _validate_posted_data(data)
        if not valid:
            return jsonify({'err_msg': msg}), 400

        try:
            mux_status = set_active_side(vm_set, port_index, data['active_side'])
            return jsonify(mux_status)
        except Exception as e:
            return jsonify({'err_msg': 'Set active side failed: {}'.format(repr(e))}), 500


def get_mux_bridges(vm_set):
    """List all the mux bridges of specified vm_set.

    Args:
        vm_set (string): The vm_set of test setup.

    Returns:
        list: List of all the bridge names of specified vm_set.
    """
    bridge_prefix = 'mbr-{}-'.format(vm_set)
    mux_bridges = [intf for intf in os.listdir('/sys/class/net') if intf.startswith(bridge_prefix)]

    return mux_bridges


@app.route('/mux/<vm_set>', methods=['GET'])
def all_mux_status(vm_set):
    """Handler for requests to /mux/<vm_set>.

    For GET request, return detailed status of all the mux Y cables belong to the specified vm_set.

    Args:
        vm_set (string): The vm_set of test setup.

    Returns:
        object: Return a flask response object.
    """
    bridge_prefix = 'mbr-{}-'.format(vm_set)
    try:
        mux_bridges = get_mux_bridges(vm_set)
        all_mux_status = {}
        for bridge in mux_bridges:
            port_index = int(bridge.replace(bridge_prefix, ''))
            all_mux_status[bridge] = get_mux_status(vm_set, port_index)
        return jsonify(all_mux_status)
    except Exception as e:
        return jsonify({'err_msg': 'Get all mux status failed, vm_set: {}, exception: {}'.format(vm_set, repr(e))}), 500


if __name__ == '__main__':
    usage = '''
    Start mux simulator server at specified port.
    $ sudo python <prog> <port>
    '''
    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)
    print('Mux simulator listening at port {}'.format(sys.argv[1]))
    app.run(host='0.0.0.0', port=sys.argv[1])
