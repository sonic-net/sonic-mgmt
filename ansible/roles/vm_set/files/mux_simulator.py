#!/usr/bin/env python
"""This script is to simulate mux on test server.

It exposes HTTP API for external parties to query and switch mux active/standby status. When the APIs
are called, it use ovs commands to get and set the OVS bridge for simulating mux behavior.

This script should be started keep running in background when a topology is created by 'testbed-cli.sh add-topo'.
"""
import json
import logging
import os
import random
import re
import shlex
import subprocess
import sys

from logging.handlers import RotatingFileHandler
from collections import defaultdict

from flask import Flask, request, jsonify
from flask.logging import default_handler

app = Flask(__name__)


UPPER_TOR = 'upper_tor'
LOWER_TOR = 'lower_tor'
NIC = 'nic'


def run_cmd(cmdline):
    """Use subprocess to run a command line with shell=True

    Args:
        cmdline (string): The command to be executed.

    Raises:
        Exception: If return code of running command line is not zero, an exception is raised.

    Returns:
        string: The stdout of running the command line.
    """
    app.logger.debug(cmdline)
    process = subprocess.Popen(
        shlex.split(cmdline),                          # lgtm [py/command-line-injection]
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    ret_code = process.returncode

    msg = 'cmd={}, ret_code={}, stdout={}, stderr={}'.format(cmdline, ret_code, stdout, stderr)
    app.logger.debug(msg)

    if ret_code != 0:
        raise Exception(msg)

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
                    "upper_tor": "enp59s0f1.3216",
                    "lower_tor": "enp59s0f1.3272"
                },
                "active_side": "upper_tor"
            }
    """
    cmdline = 'ovs-ofctl --names show mbr-{}-{}'.format(vm_set, port_index)
    out = run_cmd(cmdline)

    parsed = re.findall(r'(\d|LOCAL)\((\S+)\):\s+addr:[0-9a-f:]{17}', out)
    # Example of 'parsed':

    mux_status = defaultdict(dict)
    mux_status['vm_set'] = vm_set
    mux_status['port_index'] = port_index
    mux_status['ports'][NIC] = parsed[0][1]
    mux_status['ports'][UPPER_TOR] = parsed[1][1]
    mux_status['ports'][LOWER_TOR] = parsed[2][1]
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
            action, out_port = re.search(r'([^:]+)(?:\:"(\S+)")?', field).groups()
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
    for in_port in flows.keys():
        if not in_port.startswith('muxy-'):
            return in_port
    return None


def get_mux_status(vm_set, port_index):
    """Use other functions to get overall status of the mux.

    Args:
        vm_set (string): The vm_set of test setup.
        port_index (int or string): Index of the port.

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
                    "upper_tor": "enp59s0f1.3216",
                    "lower_tor": "enp59s0f1.3272"
                },
                "active_side": "upper_tor",
                "active_port": "enp59s0f1.3216",
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
            mux_status['active_port'] = port
    return mux_status


def set_active_side(vm_set, port_index, new_active_side):
    """Change the open flow configurations to set the active side to the value specified by argument 'new_active_side'.

    Args:
        vm_set (string): The vm_set of test setup.
        port_index (int or string): Index of the port.
        new_active_side (string): One of: 'upper_tor', 'lower_tor', 'toggle', 'random'. If new_active_side is 'toggle',
            always toggled the active side. If new_active_side is 'random', randomly choose new side from 'upper_tor'
            and 'lower_tor'.

    Returns:
        dict: Return the new full mux status in a dictionary.
    """
    mux_status = get_mux_status(vm_set, port_index)

    if new_active_side == 'random':
        new_active_side = random.choice([UPPER_TOR, LOWER_TOR])

    if mux_status['active_side'] == new_active_side:
        # Current active side is same as new active side, no need to change.
        return mux_status

    # Need to toggle active side anyway
    flows = get_flows(vm_set, port_index)
    active_port = get_active_port(flows)
    if new_active_side == 'toggle':
        new_active_side = UPPER_TOR if mux_status['active_side'] == LOWER_TOR else LOWER_TOR

    new_active_port = mux_status['ports'][new_active_side]
    run_cmd('ovs-ofctl --names del-flows mbr-{}-{} in_port="{}"'.format(vm_set, port_index, active_port))
    actions = []
    for action in flows[active_port]:
        action_desc = action['action']
        if action['out_port']:
            action_desc += ':"{}"'.format(action['out_port'])
        actions.append(action_desc)
    run_cmd('ovs-ofctl --names add-flow  mbr-{}-{} in_port="{}",actions={}'
        .format(vm_set, port_index, new_active_port, ','.join(actions)))
    new_flows = get_flows(vm_set, port_index)
    mux_status['flows'] = new_flows
    mux_status['active_side'] = new_active_side
    mux_status['active_port'] = new_active_port
    return mux_status


def _validate_param(vm_set, port_index=None):
    """Validate the vm_set and port_index argument.

    Args:
        vm_set (string): The vm_set of test setup.
        port_index (int or string): Index of the port.

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
    if 'active_side' in data and data['active_side'] in [UPPER_TOR, LOWER_TOR, 'toggle', 'random']:
        return True, ''
    return False, 'Bad posted data, expected: {"active_side": "upper_tor|lower_tor|toggle|random"}'


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
        app.logger.error('{} {} {}'.format(request.method, request.url, msg))
        return jsonify({'err_msg': msg}), 400

    if request.method == 'GET':
        # Get mux status
        try:
            mux_status = get_mux_status(vm_set, port_index)
            return jsonify(mux_status)
        except Exception as e:
            err_msg = 'Get mux status failed: {}'.format(repr(e))
            app.logger.error('{} {} {}'.format(request.method, request.url, err_msg))
            return jsonify({'err_msg': err_msg}), 500
    else:
        # Set the active side of mux
        data = request.get_json()
        valid, msg = _validate_posted_data(data)
        if not valid:
            app.logger.error('{} {} {}'.format(request.method, request.url, msg))
            return jsonify({'err_msg': msg}), 400

        try:
            mux_status = set_active_side(vm_set, port_index, data['active_side'])
            return jsonify(mux_status)
        except Exception as e:
            err_msg = 'Set active side failed: {}'.format(repr(e))
            app.logger.error('{} {} {}'.format(request.method, request.url, err_msg))
            return jsonify({'err_msg': err_msg}), 500


def get_mux_bridges(vm_set):
    """List all the mux bridges of specified vm_set.

    Args:
        vm_set (string): The vm_set of test setup.

    Returns:
        list: List of all the bridge names of specified vm_set.
    """
    bridge_prefix = 'mbr-{}-'.format(vm_set)
    mux_bridges = [intf for intf in os.listdir('/sys/class/net') if intf.startswith(bridge_prefix)]
    valid_mux_bridges = []
    for mux_bridge in mux_bridges:
        out = run_cmd('ovs-vsctl list-ports {}'.format(mux_bridge))
        if len(out.splitlines()) ==3:
            valid_mux_bridges.append(mux_bridge)

    return valid_mux_bridges


def get_all_mux_status(vm_set):
    bridge_prefix = 'mbr-{}-'.format(vm_set)
    mux_bridges = get_mux_bridges(vm_set)
    all_mux_status = {}
    for bridge in mux_bridges:
        port_index = int(bridge.replace(bridge_prefix, ''))
        all_mux_status[bridge] = get_mux_status(vm_set, port_index)
    return all_mux_status


def update_all_active_side(all_mux_status, new_active_side):
    new_all_mux_status = {}
    for bridge, mux_status in all_mux_status.items():
        vm_set = mux_status['vm_set']
        port_index = mux_status['port_index']
        new_all_mux_status[bridge] = set_active_side(vm_set, port_index, new_active_side)
    return new_all_mux_status


@app.route('/mux/<vm_set>', methods=['GET', 'POST'])
def all_mux_status(vm_set):
    """Handler for requests to /mux/<vm_set>.

    For GET request, return detailed status of all the mux Y cables belong to the specified vm_set.
    For POST request, update mux active side according to poseted data. Posted data format:
        {"active_side": "upper_tor|upper_tor|random"}
    The value of "active_side" must be one of "upper_tor", "lower_tor", "toggle" or "random".

    Args:
        vm_set (string): The vm_set of test setup.

    Returns:
        object: Return a flask response object.
    """

    try:
        all_mux_status = get_all_mux_status(vm_set)
        if request.method == 'GET':
            return jsonify(all_mux_status)
        else:
            data = request.get_json()
            valid, msg = _validate_posted_data(data)
            if not valid:
                app.logger.error('{} {} {}'.format(request.method, request.url, msg))
                return jsonify({'err_msg': msg}), 400
            new_all_mux_status = update_all_active_side(all_mux_status, data['active_side'])
            return jsonify(new_all_mux_status)
    except Exception as e:
        err_msg = 'GET/POST all mux status failed, vm_set: {}, exception: {}'.format(vm_set, repr(e))
        app.logger.error('{} {} {}'.format(request.method, request.url, err_msg))
        return jsonify({'err_msg': err_msg}), 500


def _validate_out_ports(data):
    """Validate the posted data for updating flow action.

    Args:
        data (dict): Posted json data. Expected:
                {"out_ports": [<port>, <port>, ...]}
            where <port> could be "nic", "upper_tor" or "lower_tor".

    Returns:
        tuple: Return the result in a tuple. The first item is either True or False. The second item is extra message.
    """
    supported_out_ports = [NIC, UPPER_TOR, LOWER_TOR]
    try:
        assert 'out_ports' in data, 'Missing "out_ports" field'
        for port in data['out_ports']:
            assert port in supported_out_ports, 'Unsupported port: "{}", supported: {}'.format(port, supported_out_ports)
        return True, ''
    except Exception as e:
        return False, 'Validate out_ports {} failed with exception: {}'.format(json.dumps(data), repr(e))


def update_flow_action_to_nic(mux_status, action):
    """Update the action for the flow to "nic".

    Args:
        mux_status (dict): Current mux status.
        action (string): The action to be applied to flow. Either "output" or "drop".

    Returns:
        dict: The new mux status.
    """
    in_port = mux_status['active_port']
    out_port = mux_status['ports'][NIC] if action == 'output' else None
    action_desc = '{}:"{}"'.format(action, out_port) if out_port else action
    cmdline = 'ovs-ofctl --name mod-flows {} \'in_port="{}" actions={}\''.format(
        mux_status['bridge'],
        in_port,
        action_desc)
    run_cmd(cmdline)
    new_flows = get_flows(mux_status['vm_set'], mux_status['port_index'])
    mux_status['flows'] = new_flows
    return mux_status


def update_flow_action_to_tor(mux_status, action, tor_ports):
    """Update the action for the flow to "upper_tor" and/or "lower_tor".

    Args:
        mux_status (dict): Current mux status.
        action (string): The action to be applied to flow. Either "output" or "drop".
        tor_ports (list): A list like ["upper_tor", "lower_tor"].

    Returns:
        dict: The new mux status.
    """
    nic_port = mux_status['ports'][NIC]       # muxy-<vm_set>-<port_index>
    old_output_tor_ports = set([item['out_port'] \
        for item in mux_status['flows'][nic_port] if item['action'] == 'output'])

    update_output_tor_ports = set(mux_status['ports'][tor_port] for tor_port in tor_ports)

    if action == 'output':
        output_tor_ports = old_output_tor_ports.union(update_output_tor_ports)
    else:
        output_tor_ports = old_output_tor_ports - update_output_tor_ports

    if output_tor_ports == old_output_tor_ports:    # No need to update
        return mux_status

    if len(output_tor_ports) == 0:
        action_desc='drop'
    else:
        action_desc=','.join(['output:"{}"'.format(port) for port in output_tor_ports])

    cmdline = 'ovs-ofctl --name mod-flows {} \'in_port="{}" actions={}\''.format(
        mux_status['bridge'],
        nic_port,
        action_desc)
    run_cmd(cmdline)
    new_flows = get_flows(mux_status['vm_set'], mux_status['port_index'])
    mux_status['flows'] = new_flows
    return mux_status


def update_flow_action(vm_set, port_index, action, data):
    """Update action of flows.

    Args:
        vm_set (string): The vm_set of test setup. Parsed by flask from request URL.
        port_index (string): Index of the port. Parsed by flask from request URL.
        action (string): The action to be applied to flow. Either "output" or "drop".
        data (dict): Posted json data. Expected:
                {"out_ports": [<port>, <port>, ...]}
            where <port> could be "nic", "upper_tor" or "lower_tor".

    Returns:
        dict: The new mux status.
    """
    mux_status = get_mux_status(vm_set, port_index)
    tor_ports = []
    for out_port in data['out_ports']:
        if out_port == NIC:
            mux_status = update_flow_action_to_nic(mux_status, action)
        elif out_port == UPPER_TOR or out_port == LOWER_TOR:
            tor_ports.append(out_port)
    if tor_ports:
        mux_status = update_flow_action_to_tor(mux_status, action, tor_ports)
    return mux_status


@app.route('/mux/<vm_set>/<port_index>/<action>', methods=['POST'])
def mux_cable_flow_update(vm_set, port_index, action):
    """Handler for changing flow action.

    Args:
        vm_set (string): The vm_set of test setup. Parsed by flask from request URL.
        port_index (string): Index of the port. Parsed by flask from request URL.
        action (string): The action to be applied to flow. Either "output" or "drop".

    Returns:
        object: Return a flask response object.
    """
    if action not in ["output", "drop"]:
        err_msg = 'In "/mux/<vm_set>/<port_index>/<action>", action must be "output" or "drop".'
        app.logger.error('{} {} {}'.format(request.method, request.url, err_msg))
        return jsonify({'err_msg': err_msg}), 404

    valid, msg = _validate_param(vm_set, port_index)
    if not valid:
        app.logger.error('{} {} {}'.format(request.method, request.url, msg))
        return jsonify({'err_msg': msg}), 400

    data = request.get_json()
    valid, msg = _validate_out_ports(data)
    if not valid:
        app.logger.error('{} {} {}'.format(request.method, request.url, msg))
        return jsonify({'err_msg': msg}), 400

    try:
        mux_status = update_flow_action(vm_set, port_index, action, data)
        return jsonify(mux_status)
    except Exception as e:
        err_msg = 'Update flow action failed: {}'.format(repr(e))
        app.logger.error('{} {} {}'.format(request.method, request.url, err_msg))
        return jsonify({'err_msg': err_msg}), 500


def config_logging():
    rfh = RotatingFileHandler(
        '/tmp/mux_simulator.log',
        maxBytes=1024*1024,
        backupCount=5)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    rfh.setFormatter(fmt)
    rfh.setLevel(logging.INFO)
    app.logger.addHandler(rfh)
    app.logger.removeHandler(default_handler)


if __name__ == '__main__':
    usage = '''
    Start mux simulator server at specified port.
    $ sudo python <prog> <port>
    '''
    config_logging()

    if '-v' in sys.argv:
        app.logger.setLevel(logging.DEBUG)
        for handler in app.logger.handlers:
            handler.setLevel(logging.DEBUG)

    if len(sys.argv) < 2:
        app.logger.error(usage)
        sys.exit(1)

    app.logger.info('Mux simulator listening at port {}'.format(sys.argv[1]))
    app.run(host='0.0.0.0', port=sys.argv[1])
