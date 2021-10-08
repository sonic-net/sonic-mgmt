
from __future__ import print_function

import json
import logging
import os
import random
import re
import shlex
import subprocess
import sys
import threading
import traceback

from collections import defaultdict
from logging.handlers import RotatingFileHandler

from flask import Flask, request, abort
from flask.logging import default_handler
from werkzeug.exceptions import HTTPException

UPPER_TOR = 'upper_tor'
LOWER_TOR = 'lower_tor'
NIC = 'nic'
MUX_BRIDGE_TEMPLATE = 'mbr-%s-%d'

LIST_PORTS_CMD = 'ovs-vsctl list-ports {}'
DUMP_FLOW_CMD = 'ovs-ofctl --names dump-flows {}'
DEL_FLOW_CMD = 'ovs-ofctl --names del-flows {} in_port="{}"'
ADD_FLOW_CMD = 'ovs-ofctl --names add-flow {} in_port="{}",actions={}'
MOD_FLOW_CMD = 'ovs-ofctl --names mod-flows {} in_port="{}",actions={}'

RANDOM = 'random'
TOGGLE = 'toggle'

MUX_BRIDGE_PREFIX = 'mb'   # With adaptive name, MUX Bridge could be: mbr-vms21-1-12, mb-vms121-1-121
MUX_NIC_PREFIX = 'mu'      # With adaptive name, MUX NIC could be: muxy-vms21-1-12, mux-vms21-1-121, mu-vms121-1-121

OUTPUT = 'output'
DROP = 'drop'

app = Flask(__name__)

g_muxes = None              # Global variable holding instance of the class Muxes

################################################## Error Handlers ####################################################

@app.errorhandler(Exception)
def handle_exception(e):
    """Register exception handler.

    For simplicity, we don't use too much try...except in code. Any uncaught exception will be handled by this function.

    Exceptions handled by this hander:
        * 4XX HTTP client side issue
        * 5XX HTTP server side issue
        * Any exceptions unhandled by views and models.
    """
    res = {'err_msg': '{} {}'.format(repr(e), str(e))}
    tb = traceback.format_exc()

    app.logger.error('Exception: {}, traceback:\n{}'.format(str(e), tb))

    if isinstance(e, HTTPException):
        err_code = e.code
    else:
        err_code = 500

    if app.config['VERBOSE']:
        res.update({'traceback': tb.splitlines()})
    return res, err_code

###################################################### Utils #########################################################

def adaptive_name(template, vm_set, index):
    """
    A helper function for interface/bridge name calculation.
    Since the name of interface must be less than 15 bytes. This util is to adjust the template automatically
    according to the length of vm_set name and port index. The leading characters (inje, muxy, mbr) will be shorten if necessary
    e.g.
    port 21 on vms7-6 -> inje-vms7-6-21
    port 121 on vms21-1 -> inj-vms21-1-121
    port 121 on vms121-1 -> in-vms121-1-121
    """
    MAX_LEN = 15
    host_index_str = '-%s-%d' % (vm_set, int(index))
    leading_len = MAX_LEN - len(host_index_str)
    leading_characters = template.split('-')[0][:leading_len]
    rendered_name = leading_characters + host_index_str
    return rendered_name


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

    msg = {
        'cmd': cmdline,
        'ret_code': ret_code,
        'stdout': stdout.decode('utf-8').splitlines(),
        'stderr': stderr.decode('utf-8').splitlines()
    }
    app.logger.debug(json.dumps(msg, indent=2))

    if ret_code != 0:
        raise Exception(msg)

    return stdout.decode('utf-8')


def config_logging(http_port):
    """Configure log to rotating file

    * Remove the default handler from app.logger.
    * Add RotatingFileHandler to the app.logger.
        File size: 10MB
        File number: 3
    * The Werkzeug handler is untouched.
    """
    rfh = RotatingFileHandler(
        '/tmp/mux_simulator_{}.log'.format(http_port),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)s #%(lineno)d: %(message)s')
    rfh.setFormatter(fmt)
    rfh.setLevel(logging.DEBUG)
    app.logger.addHandler(rfh)
    app.logger.removeHandler(default_handler)

###################################################### Models ########################################################

class Mux(object):
    '''Object represents a single mux bridge

    All operations related with a single mux bridge is encapsulated in this class.
    '''

    def __init__(self, vm_set, port_index):
        # Flag for skipping bridge without ports attached to it.
        # Workaround for uncleaned mbr-xx bridges on server
        self.isvalid = True

        # The flask server could be running in multi-threaded mode. This means that getting mux status and changing
        # mux flow configuration could interleave with each other. The operation of updating flow configuration is
        # not atomic, sometimes it needs to run a command to remove flow, then run a command to add a new flow.
        # If a request of getting mux status come in in the middle of such flow configuration change, the mux
        # status returned may not match the actual flow status. Purpose of the lock is to workaround such conflicts.
        # All the operations of updating mux config and getting mux status must acquire the lock firstly.
        self.lock = threading.Lock()

        self.vm_set = vm_set

        self.port_index = port_index
        self.bridge = adaptive_name(MUX_BRIDGE_TEMPLATE, vm_set, port_index)

        self._init_ports()

        # If the mux does not have valid ports attahed, it is invalid
        if not self._get_ports():
            self.isvalid = False
            return

        # Initilize the flows configured on the mux bridge
        self._init_flows()
        self._get_flows()

        self.flap_counter = 0

    def debug(self, msg):
        app.logger.debug('bridge={}, {}'.format(self.bridge, msg))

    def info(self, msg):
        app.logger.info('bridge={}, {}'.format(self.bridge, msg))

    def error(self, msg):
        app.logger.error('bridge={}, {}'.format(self.bridge, msg))

    def _init_ports(self):
        self.ports = {
            NIC: None,
            UPPER_TOR: None,
            LOWER_TOR: None
        }
        self.sides = {}

    def _get_ports(self):
        """Use the 'ovs-vsctl list-ports' command to get the ports attached to the mux bridge.

        Example bridge name: 'mbr-vms17-8-0'. In the bridge name, 'vms17-8' is vm_set. '0' is port_index.
        Example output of 'ovs-ofctl list-ports' command:

        azure@str2-acs-serv-17:~$ sudo ovs-vsctl list-ports mbr-vms17-8-0
        enp59s0f1.3216
        enp59s0f1.3272
        muxy-vms17-8-0

        Returns:
            boolean: Return False if it is not a valid mux bridge
        """
        out = run_cmd(LIST_PORTS_CMD.format(self.bridge))
        out_lines = out.splitlines()
        if len(out_lines) != 3:
            self.error('unexpected ports, found ports:\n{}'.format(out))
            return False

        tor_ports = []
        nic_port = None
        for port in out_lines:
            if port.startswith(MUX_NIC_PREFIX):
                nic_port = port
            else:
                tor_ports.append(port)

        if len(tor_ports) != 2:
            self.error('Wrong ToR ports, found ports:\n{}'.format(out))
            return False
        if not nic_port:
            self.error('No NIC port, found ports:\n{}'.format(out))
            return False

        # Sort the ToR ports. Assume the upper ToR is assigned with lower VLAN.
        tor_ports.sort()
        self.ports = {
            NIC: nic_port,
            UPPER_TOR: tor_ports[0],
            LOWER_TOR: tor_ports[1]
        }
        self.sides = {
            nic_port: NIC,
            tor_ports[0]: UPPER_TOR,
            tor_ports[1]: LOWER_TOR
        }

        return True

    def _active_standby_state_helper(self, active_side):
        if active_side is None:
            active_side = random.choice([UPPER_TOR, LOWER_TOR])
        standby_side = LOWER_TOR if active_side == UPPER_TOR else LOWER_TOR

        self.active_side = active_side
        self.active_port = self.ports[active_side]
        self.standby_side = standby_side
        self.standby_port = self.ports[standby_side]

    def _init_flows(self):
        self._active_standby_state_helper(None)

        self.flows = {
            'upstream': {
                'in_side': NIC,
                'out_sides': []
            },
            'downstream': {
                'in_side': self.active_side,
                'out_sides': []
            }
        }

    def _get_flows(self):
        """Use the 'ovs-ofctl dump-flows' command to get the open flow details of a bridge simulating mux.

        Example output of the 'ovs-ofctl dump-flows' command:
        azure@str2-acs-serv-17:~$ sudo ovs-ofctl --names dump-flows mbr-vms17-8-0
        cookie=0x0, duration=86737.831s, table=0, n_packets=446, n_bytes=44412, in_port="muxy-vms17-8-0" actions=output:"enp59s0f1.3216",output:"enp59s0f1.3272"
        cookie=0x0, duration=86737.819s, table=0, n_packets=10251, n_bytes=1179053, in_port="enp59s0f1.3216" actions=output:"muxy-vms17-8-0"

        Example result of parsing the output using regex:
        >>> re.findall(r'in_port="(\S+)"\s+actions=(\S+)', out)
        [('muxy-vms17-8-0', 'output:"enp59s0f1.3216",output:"enp59s0f1.3272"'), ('enp59s0f1.3216', 'output:"muxy-vms17-8-0"')]
        """

        # By default, there are only two flows per bridge:
        #   * upstream flow, PTF port (muxy-<vm_set>_<port_index>) -> both UPPER_TOR and LOWER_TOR ports
        #   * downstream flow, UPPER_TOR or LOWER_TOR port -> PTF port.
        # The current TOR port of downstream is active port
        out = run_cmd(DUMP_FLOW_CMD.format(self.bridge))

        # Parse the flows, store result in dict flows[in_port][out_port] = action
        flows = defaultdict(dict)
        parsed = re.findall(r'in_port="(\S+)"\s+actions=(\S+)', out)
        for in_port, actions_desc in parsed:
            for field in actions_desc.split(','):
                action, out_port = re.search(r'([^:]+)(?:\:"(\S+)")?', field).groups()
                # In rare case, the muxy interfaces in PTF docker could be gone. Parsing the output may get None for
                # 'out_port'. This will cause exception and crash mux-simulator server. Since mux-simulator is shared
                # by multiple dualtor setups. Below check is to ensure that bad testbed don't crash mux-simulator
                # and affect the good testbed.
                if in_port is not None and out_port is not None and action in [OUTPUT, DROP]:
                    flows[in_port][out_port] = action
                else:
                    self.debug('in_port={}, out_port={}, action={}'.format(in_port, out_port, action))
        self.debug('Parsed flows on bridge:\n{}'.format(json.dumps(flows, indent=2)))

        # Transform parsed flows to self.flows dict
        for in_port in flows:
            if self.sides[in_port] == NIC:
                # From NIC to TORs, upstream flow
                self.flows['upstream']['in_side'] = NIC
                self.flows['upstream']['out_sides'] = [self.sides[out_port] for out_port, action in flows[in_port].items() if action == OUTPUT]
            else:
                # From TOR to NIC, downstream flow
                self._active_standby_state_helper(self.sides[in_port])
                self.flows['downstream']['in_side'] = self.sides[in_port]
                self.flows['downstream']['out_sides'] = [self.sides[out_port] for out_port, action in flows[in_port].items() if action == OUTPUT]

    @property
    def status(self):
        """Property for statu of the mux bridge.

        Status of the mux bridge is maintained in instance attributes. This property is to gather the attributes and
        return them in a dict.
        """
        with self.lock:
            # Transform mux flows to json expected by mux simulator client
            flows = {}
            flows[self.ports[NIC]] = [
                {'action': OUTPUT, 'out_port': self.ports[out_side]} for out_side in self.flows['upstream']['out_sides']
            ]

            if self.flows['downstream']['in_side'] is not None:
                in_side = self.flows['downstream']['in_side']
                in_port = self.ports[in_side]
                flows[in_port] = [
                    {'action': OUTPUT, 'out_port': self.ports[out_side]} for out_side in self.flows['downstream']['out_sides']
                ]

            healthy = True
            if len(self.flows['downstream']['out_sides']) != 1 or len(self.flows['upstream']['out_sides']) != 2:
                healthy = False

            status = {
                'bridge': self.bridge,
                'vm_set': self.vm_set,
                'port_index': self.port_index,
                'ports': self.ports,
                'active_port': self.active_port,
                'active_side': self.active_side,
                'standby_side': self.standby_side,
                'standby_port': self.standby_port,
                'flows': flows,
                'flap_counter': self.flap_counter,
                'healthy': healthy
            }
            return status

    def set_active_side(self, new_active_side):
        """Set the active side of the mux bridge to the specified side.

        If the specified side is same as the current active side of bridge, no config change is reuqired. Otherwise,
        this method will run ovs-ofctl command to remove flow and add a new flow to switch active side. All the
        related instance attributes are updated after open flow rules are changed.
        """
        with self.lock:
            self.info('>>>>>> updating mux active side from {} to {}'.format(self.active_side, new_active_side))
            if new_active_side == RANDOM:
                new_active_side = random.choice([UPPER_TOR, LOWER_TOR])

            if self.active_side == new_active_side:
                self.info('current active_side={}, new_active_side={}, no need to change. <<<<<<'.format(self.active_side, new_active_side))
                return

            # Need to toggle active side
            if new_active_side == TOGGLE:
                new_active_side = UPPER_TOR if self.active_side == LOWER_TOR else LOWER_TOR

            new_active_port = self.ports[new_active_side]

            if len(self.flows['downstream']['out_sides']) == 1:
                action_desc = '{}:"{}"'.format(OUTPUT, self.ports[NIC])
                run_cmd(DEL_FLOW_CMD.format(
                    self.bridge,
                    self.active_port))
                # Immediately update state after flow config changed to ensure consistency
                self._active_standby_state_helper(None)
                self.flows['downstream']['in_side'] = self.active_side
                self.flows['downstream']['out_sides'] = []

                run_cmd(ADD_FLOW_CMD.format(
                    self.bridge,
                    new_active_port,
                    action_desc))
                # Immediately update state after flow config changed to ensure consistency
                self._active_standby_state_helper(new_active_side)
                self.flows['downstream']['in_side'] = self.active_side
                self.flows['downstream']['out_sides'] = [NIC]

            else:
                # If currently downstream flow action is drop, there should be no downstream flow config.
                # Then no flow config change required, only need to update the state.
                self._active_standby_state_helper(new_active_side)
                self.flows['downstream']['in_side'] = self.active_side
                self.flows['downstream']['out_sides'] = []

            # Increase flap counter
            self.flap_counter += 1

            self.info('updated mux active side to {} <<<<<<'.format(new_active_side))

    def _update_downstream_flow(self, new_action):
        self.debug('updating downstream flow, new_action={}'.format(new_action))

        # No action required for below scenarios
        if new_action == DROP and len(self.flows['downstream']['out_sides']) == 0:
            self.debug('no downstream flow change required')
            return
        elif new_action == OUTPUT and len(self.flows['downstream']['out_sides']) == 1:
            self.debug('no downstream flow change required')
            return

        if new_action == DROP:
            # Update action from OUTPUT to DROP, del-flow
            run_cmd(DEL_FLOW_CMD.format(
                self.bridge,
                self.active_port))
            self.flows['downstream']['out_sides'] = []

        else:
            # Update action from DROP to OUTPUT, add-flow
            action_desc = '{}:"{}"'.format(OUTPUT, self.ports[NIC])
            if self.active_side is None:
                active_side = random.choice([UPPER_TOR, LOWER_TOR])
            else:
                active_side = self.active_side

            run_cmd(ADD_FLOW_CMD.format(
                self.bridge,
                self.ports[active_side],
                action_desc))
            self._active_standby_state_helper(active_side)
            self.flows['downstream']['in_side'] = active_side
            self.flows['downstream']['out_sides'] = [NIC]

        self.debug('updated downstream flow, new_action={}, flows={}'.format(new_action, json.dumps(self.flows, indent=2)))

    def _update_upstream_flow(self, new_action, out_sides=[]):
        """Update upstream flow. Apply new action to sides specified in out_sides.

        The upstream flow has 2 output sides, to UPPER_TOR or LOWER_TOR. This is to update the action (OUTPUT or DROP)
        for the specified output sides.
        """
        self.debug('updating upstream flow, new_action={}, out_sides={}'.format(new_action, out_sides))

        if len(out_sides) == 0:
            # Need to specify sides that need to apply the new OUTPUT or DROP action
            app.logger.debug('no out_sides specified, skip updating upstream flow')
            return

        # Figure out target upstream out_sides
        if new_action == DROP:
            target_out_sides = [out_side for out_side in self.flows['upstream']['out_sides'] if out_side not in out_sides]
        else:
            target_out_sides = list(set(self.flows['upstream']['out_sides'] + out_sides))

        # Based on current out_sides and target out_sides to determine what to do
        if set(self.flows['upstream']['out_sides']) == set(target_out_sides):
            app.logger.debug('target_out_sides same as current out_sides, no upstream flow change required')
            return
        operation = None
        if len(target_out_sides) == 0:
            operation = 'DEL-FLOW'   # Remove the upstream flow
        else:
            if len(self.flows['upstream']['out_sides']) == 0:
                operation = 'ADD-FLOW'   # Need to add upstream flow
            else:
                operation = 'MOD-FLOW'   # Need to modify upstream flow

        if operation == 'DEL-FLOW':
            run_cmd(DEL_FLOW_CMD.format(
                    self.bridge,
                    self.ports[NIC]))
            self.flows['upstream']['out_sides'] = []
        elif operation == 'ADD-FLOW':
            action_desc = ','.join(['{}:"{}"'.format(OUTPUT, self.ports[out_side]) for out_side in target_out_sides])
            run_cmd(ADD_FLOW_CMD.format(
                    self.bridge,
                    self.ports[NIC],
                    action_desc))
            self.flows['upstream']['out_sides'] = target_out_sides
        elif operation == 'MOD-FLOW':
            action_desc = ','.join(['{}:"{}"'.format(OUTPUT, self.ports[out_side]) for out_side in target_out_sides])
            run_cmd(MOD_FLOW_CMD.format(
                    self.bridge,
                    self.ports[NIC],
                    action_desc))
            self.flows['upstream']['out_sides'] = target_out_sides
        self.debug('updated upstream flow, new_action={}, out_sides={}, flows={}'.format(new_action, out_sides, json.dumps(self.flows, indent=2)))

    def update_flows(self, new_action, out_sides):
        """
        Apply new flow action for the sides specified in out_sides.

        Item in out_sides could be any of: 'nic', 'upper_tor', 'lower_tor'.
        """
        with self.lock:
            self.info('>>>>> calling update_flows, new_action={}, out_sides={}, current flow:\n{}'.format(new_action, out_sides, json.dumps(self.flows, indent=2)))
            if NIC in out_sides:
                self._update_downstream_flow(new_action)
            tor_sides = [out_side for out_side in out_sides if out_side != NIC]
            if len(tor_sides) > 0:
                self._update_upstream_flow(new_action, tor_sides)
            self.info('update_flows completed, current flows:\n{} <<<<<<'.format(json.dumps(self.flows, indent=2)))

    def reset_flows(self):
        """Restore all the flows for this mux bridge.
        """
        self.info('>>>>> resetting flows')
        self.update_flows(OUTPUT, [NIC, UPPER_TOR, LOWER_TOR])
        self.info('resetting flows done <<<<<<')

    def clear_flap_counter(self):
        with self.lock:
            self.info('clear flap counter')
            self.flap_counter = 0
            self.info('clear flap counter done')


class Muxes(object):

    def __init__(self, vm_set):
        self.vm_set = vm_set
        self.muxes = {}
        for bridge in self._mux_bridges():
            bridge_fields = bridge.split('-')
            port_index = int(bridge_fields[-1])
            mux = Mux(vm_set, port_index)
            if mux.isvalid:
                self.muxes[bridge] = mux

    def _mux_bridges(self):
        """Only collect bridges belong to self.vm_set

        Returns:
            list: List of bridges belong to self.vm_set
        """
        pattern = '{}[^-]*-{}-[\d]+'.format(MUX_BRIDGE_PREFIX, self.vm_set)
        return [intf for intf in os.listdir('/sys/class/net') if re.search(pattern, intf)]

    def _port_to_mux(self, port_index):
        """Get the mux object by port_index.
        """
        bridge = adaptive_name(MUX_BRIDGE_TEMPLATE, self.vm_set, port_index)
        return self.muxes[bridge]

    def get_mux_status(self, port_index=None):
        if port_index is not None:
            return self._port_to_mux(port_index).status
        else:
            return {mux.bridge: mux.status for mux in self.muxes.values()}

    def set_active_side(self, new_active_side, port_index=None):
        if port_index is not None:
            mux = self._port_to_mux(port_index)
            mux.set_active_side(new_active_side)
            return mux.status
        else:
            [mux.set_active_side(new_active_side) for mux in self.muxes.values()]
            return {mux.bridge: mux.status for mux in self.muxes.values()}

    def update_flows(self, new_action, out_sides, port_index=None):
        if port_index is not None:
            mux = self._port_to_mux(port_index)
            mux.update_flows(new_action, out_sides)
            return mux.status
        else:
            [mux.update_flows(new_action, out_sides) for mux in self.muxes.values()]
            return {mux.bridge: mux.status for mux in self.muxes.values()}

    def reset_flows(self, port_index=None):
        return self.update_flows(OUTPUT, [NIC, UPPER_TOR, LOWER_TOR], port_index=port_index)

    def get_flap_counter(self, port_index=None):
        if port_index is not None:
            mux = self._port_to_mux(port_index)
            return {mux.bridge: mux.status['flap_counter']}
        else:
            return {mux.bridge: mux.status['flap_counter'] for mux in self.muxes.values()}

    def clear_flap_counter(self, port_index=None):
        if port_index is not None:
            mux = self._port_to_mux(port_index)
            mux.clear_flap_counter()
            return {mux.bridge: mux.status['flap_counter']}
        else:
            [mux.clear_flap_counter() for mux in self.muxes.values()]
            return {mux.bridge: mux.status['flap_counter'] for mux in self.muxes.values()}

    def has_mux(self, port_index=None):
        if port_index is not None:
            bridge = adaptive_name(MUX_BRIDGE_TEMPLATE, self.vm_set, port_index)
            return bridge in self.muxes
        else:
            return len(self.muxes) > 0


def create_muxes(vm_set):
    app.logger.info('####################### COLLECTING BRIDGE STATUS #######################')
    global g_muxes
    g_muxes = Muxes(vm_set)
    app.logger.info('####################### COLLECTING BRIDGE STATUS DONE #######################')


###################################################### Views #########################################################

def _validate_posted_data(request):
    """Validate json data in POST request.

    If the request is invalid, abort with 400 BadRequest. Expected data:
        {"active_side": "upper_tor|lower_tor|toggle|random"}

    Args:
        request (obj): The flask request object.

    Returns:
        dict: Return the posted data dict.
    """
    data = request.get_json()
    if not data or not 'active_side' in data or not data['active_side'] in [UPPER_TOR, LOWER_TOR, TOGGLE, RANDOM]:
        msg = 'Bad posted data, expected: {"active_side": "upper_tor|lower_tor|toggle|random"}'
        abort(400, description='remote_addr={} method={} url={} data={} msg={}'.format(
                request.remote_addr,
                request.method,
                request.url,
                json.dumps(data),
                msg
            ))
    return data


def _validate_vm_set(vm_set):
    if g_muxes.vm_set != vm_set:
        abort(404, 'Unknown vm_set "{}"'.format(vm_set))


@app.route('/mux/<vm_set>/<int:port_index>', methods=['GET', 'POST'])
def mux_status(vm_set, port_index):
    """Handler for requests to /mux/<vm_set>/<port_index>.

    For GET request, return detailed status of mux specified by vm_set and port_index.
    For POST request, set mux active side to the one specified in the posted json data.

    Args:
        vm_set (string): The vm_set of test setup. Parsed by flask from request URL.
        port_index (string): Index of the port. Parsed by flask from request URL.

    Returns:
        object: Return a flask response object.
    """
    _validate_vm_set(vm_set)
    if not g_muxes.has_mux(port_index):
        abort(404, 'Unknown bridge, vm_set={}, port_index={}'.format(vm_set, port_index))

    if request.method == 'GET':
        return g_muxes.get_mux_status(port_index)
    elif request.method == 'POST':
        # Set the active side of mux
        data = _validate_posted_data(request)
        app.logger.info('===== {} POST {} with {} ====='.format(request.remote_addr, request.url, json.dumps(data)))
        return g_muxes.set_active_side(data['active_side'], port_index)


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
    _validate_vm_set(vm_set)
    if request.method == 'GET':
        return g_muxes.get_mux_status()
    elif request.method == 'POST':
        # Set the active side for all mux bridges
        data = _validate_posted_data(request)
        app.logger.info('===== {} POST {} with {} ====='.format(request.remote_addr, request.url, json.dumps(data)))
        return g_muxes.set_active_side(data['active_side'])


def _validate_out_sides(request):
    """Validate the posted data for updating flow action.

    Args:
        data (dict): Posted json data. Expected:
                {"out_sides": [<side>, <side>, ...]}
            where <side> could be "nic", "upper_tor" or "lower_tor".

    Returns:
        tuple: Return the result in a tuple. The first item is either True or False. The second item is extra message.
    """
    data = request.get_json()
    supported_out_sides = [NIC, UPPER_TOR, LOWER_TOR]
    msg = 'Invalid posted data: {}, expected: {"out_sides": ["nic|upper_tor|lower_tor", ...]}'
    if not data or not 'out_sides' in data \
        or not isinstance(data['out_sides'], list) \
        or len([port for port in data['out_sides'] if port not in supported_out_sides]) > 0:
        abort(400, description='remote_addr={} method={} url={} data={} msg={}'.format(
            request.remote_addr,
            request.method,
            request.url,
            json.dumps(data),
            msg
        ))

    return data


@app.route('/mux/<vm_set>/<int:port_index>/<action>', methods=['POST'])
def mux_cable_flow_update(vm_set, port_index, action):
    """Handler for changing flow action.

    Args:
        vm_set (string): The vm_set of test setup. Parsed by flask from request URL.
        port_index (string): Index of the port. Parsed by flask from request URL.
        action (string): The action to be applied to flow. Either "output", "drop", or "reset".

    Posted json data should be like:
        {"out_sides": [<side>, <side>, ...]}
    where <side> could be "nic", "upper_tor" or "lower_tor".

    Returns:
        object: Return a flask response object.
    """
    _validate_vm_set(vm_set)
    if action not in ['output', 'drop', 'reset'] or not g_muxes.has_mux(port_index):
        msg = 'Expected url "/mux/<vm_set>/<port_index>/<action>", action must be "output", "drop", or "reset".'
        abort(404, description='remote_addr={} method={} url={} msg={}'.format(
                request.remote_addr,
                request.method,
                request.url,
                msg
            ))

    if action == 'reset':
        app.logger.info('===== {} POST {} ====='.format(request.remote_addr, request.url))
        return g_muxes.reset_flows(port_index)
    else:
        data = _validate_out_sides(request)
        app.logger.info('===== {} POST {} with {} ====='.format(request.remote_addr, request.url, json.dumps(data)))
        return g_muxes.update_flows(action, data['out_sides'], port_index)


@app.route('/mux/<vm_set>/reset', methods=['POST'])
def reset_flow_handler(vm_set):
    _validate_vm_set(vm_set)
    app.logger.info('===== {} POST {} ====='.format(request.remote_addr, request.url))
    return g_muxes.reset_flows()


@app.route('/mux/<vm_set>/<int:port_index>/flap_counter', methods=['GET'])
def flap_counter_port(vm_set, port_index):
    """
    Handler for retrieving flap counter for a given port
    """
    _validate_vm_set(vm_set)
    return g_muxes.get_flap_counter(port_index)


@app.route('/mux/<vm_set>/flap_counter', methods=['GET'])
def flap_counter_all(vm_set):
    """
    Handler for retrieving flap counter for all ports
    """
    _validate_vm_set(vm_set)
    return g_muxes.get_flap_counter()


@app.route('/mux/<vm_set>/clear_flap_counter', methods=['POST'])
def clear_flap_counter_handler(vm_set):
    """
    Handler for clearing flap counter for all ports or a given port
    Data posted should be {"port_to_clear": "0|1..."} or {"port_to_clear": "all"}
    """
    _validate_vm_set(vm_set)
    data = request.get_json()
    msg = 'Invalid posted data: {}, expected: {"port_to_clear": "0|1|2..."} or {"port_to_clear": "all"}'
    if not data or not 'port_to_clear' in data \
        or not (isinstance(data['port_to_clear'], str) or isinstance(data['port_to_clear'], unicode)) \
        or (data['port_to_clear']!='all' and not re.match('^\d+(\|\d+)*$', data['port_to_clear'])):
        abort(400, description='remote_addr={} method={} url={} data={} msg={}'.format(
            request.remote_addr,
            request.method,
            request.url,
            json.dumps(data),
            msg
        ))

    app.logger.info('===== {} POST {} with {} ====='.format(request.remote_addr, request.url, json.dumps(data)))

    if data['port_to_clear'] == "all":
        return g_muxes.clear_flap_counter()
    else:
        ret = {}
        for port_index in data['port_to_clear'].split('|'):
            ret.update(g_muxes.clear_flap_counter(port_index))
        return ret


@app.route('/mux/<vm_set>/reload', methods=['POST'])
def reload_muxes(vm_set):
    """Handler for reloading the mux objects
    """
    _validate_vm_set(vm_set)
    create_muxes(vm_set)
    return g_muxes.get_mux_status()


@app.route('/mux/<vm_set>/log', methods=['POST'])
def log_message(vm_set):
    """
    Handler for logging a supplied message.

    Client can call this API with json data like {"message": "Something to log, eg: <test_case_name>"}. The message
    contained in json data will be logged to mux simulator server's log file. Test cases can call this API before and
    after testing to add start/end markers in mux simulator log. Troubleshooting would be easier with these markers.
    """
    _validate_vm_set(vm_set)
    data = request.get_json()
    if not data or not 'message' in data:
        abort(400, description='remote_addr={} method={} url={} data={} msg={}'.format(
            request.remote_addr,
            request.method,
            request.url,
            json.dumps(data),
            'Expect key "message" in posted json'
        ))
    app.logger.info('***** {} logged: {} *****'.format(request.remote_addr, data['message']))
    return {"success": True}


if __name__ == '__main__':
    usage = '\n'.join([
        'Start mux simulator server at specified port:',
        '  $ sudo python <prog> <port> <vm_set> [-v]',
        'Specify "-v" for DEBUG level logging and enabling traceback in response in case of exception.'])

    if len(sys.argv) < 3:
        print(usage)
        sys.exit(1)

    http_port = sys.argv[1]
    arg_vm_set = sys.argv[2]

    if '-v' in sys.argv:
        app.logger.setLevel(logging.DEBUG)
        app.config['VERBOSE'] = True
    else:
        app.logger.setLevel(logging.INFO)
        app.config['VERBOSE'] = False

    config_logging(http_port)
    MUX_LOGO = '\n'.join([
        '',
        '##     ## ##     ## ##     ##     ######  #### ##     ## ##     ## ##          ###    ########  #######  ########  ',
        '###   ### ##     ##  ##   ##     ##    ##  ##  ###   ### ##     ## ##         ## ##      ##    ##     ## ##     ## ',
        '#### #### ##     ##   ## ##      ##        ##  #### #### ##     ## ##        ##   ##     ##    ##     ## ##     ## ',
        '## ### ## ##     ##    ###        ######   ##  ## ### ## ##     ## ##       ##     ##    ##    ##     ## ########  ',
        '##     ## ##     ##   ## ##            ##  ##  ##     ## ##     ## ##       #########    ##    ##     ## ##   ##   ',
        '##     ## ##     ##  ##   ##     ##    ##  ##  ##     ## ##     ## ##       ##     ##    ##    ##     ## ##    ##  ',
        '##     ##  #######  ##     ##     ######  #### ##     ##  #######  ######## ##     ##    ##     #######  ##     ## ',
        '',
    ])
    app.logger.info(MUX_LOGO)
    app.logger.info('Starting server on port {}'.format(sys.argv[1]))
    create_muxes(arg_vm_set)
    app.logger.info('####################### STARTING HTTP SERVER #######################')
    app.run(host='0.0.0.0', port=http_port, threaded=False)
