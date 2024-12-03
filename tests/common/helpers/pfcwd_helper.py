import datetime
import ipaddress
import sys
import random
import pytest
import contextlib
import time
import logging

from tests.ptf_runner import ptf_runner
from tests.common import constants
from tests.common.cisco_data import is_cisco_device
from tests.common.mellanox_data import is_mellanox_device

# If the version of the Python interpreter is greater or equal to 3, set the unicode variable to the str class.
if sys.version_info[0] >= 3:
    unicode = str

EXPECT_PFC_WD_DETECT_RE = ".* detected PFC storm .*"
VENDOR_SPEC_ADDITIONAL_INFO_RE = {
    "mellanox":
        r"additional info: occupancy:[0-9]+\|packets:[0-9]+\|packets_last:[0-9]+\|pfc_rx_packets:[0-9]+\|"
        r"pfc_rx_packets_last:[0-9]+\|pfc_duration:[0-9]+\|pfc_duration_last:[0-9]+\|timestamp:[0-9]+\.[0-9]+\|"
        r"timestamp_last:[0-9]+\.[0-9]+\|(effective|real)_poll_time:[0-9]+"
    }

EXPECT_PFC_WD_RESTORE_RE = ".*storm restored.*"

logger = logging.getLogger(__name__)


class TrafficPorts(object):
    """ Generate a list of ports needed for the PFC Watchdog test"""
    def __init__(self, mg_facts, neighbors, vlan_nw):
        """
        Args:
            mg_facts (dict): parsed minigraph info
            neighbors (list):  'device_conn' info from connection graph facts
            vlan_nw (string): ip in the vlan range specified in the DUT

        """
        self.mg_facts = mg_facts
        self.bgp_info = self.mg_facts['minigraph_bgp']
        self.port_idx_info = self.mg_facts['minigraph_ptf_indices']
        self.pc_info = self.mg_facts['minigraph_portchannels']
        self.vlan_info = self.mg_facts['minigraph_vlans']
        self.neighbors = neighbors
        self.vlan_nw = vlan_nw
        self.test_ports = dict()
        self.pfc_wd_rx_port = None
        self.pfc_wd_rx_port_addr = None
        self.pfc_wd_rx_neighbor_addr = None
        self.pfc_wd_rx_port_id = None

    def build_port_list(self):
        """
        Generate a list of ports to be used for the test

        For T0 topology, the port list is built parsing the portchannel and vlan info and for T1,
        port list is constructed from the interface info
        """
        if self.mg_facts['minigraph_interfaces']:
            self.parse_intf_list()
        elif self.mg_facts['minigraph_portchannels']:
            self.parse_pc_list()
        elif 'minigraph_vlan_sub_interfaces' in self.mg_facts:
            self.parse_vlan_sub_interface_list()
        if self.mg_facts['minigraph_vlans']:
            self.test_ports.update(self.parse_vlan_list())
        return self.test_ports

    def parse_intf_list(self):
        """
        Built the port info from the ports in 'minigraph_interfaces'

        The constructed port info is a dict with a port as the key (transmit port) and value contains
        all the info associated with this port (its fanout neighbor, receive port, receive ptf id,
        transmit ptf id, neighbor addr etc).  The first port in the list is assumed to be the Rx port.
        The rest of the ports will use this port as the Rx port while populating their dict
        info. The selected Rx port when used as a transmit port will use the next port in
        the list as its associated Rx port
        """
        pfc_wd_test_port = None
        first_pair = False
        for intf in self.mg_facts['minigraph_interfaces']:
            if ipaddress.ip_address(str(intf['addr'])).version != 4:
                continue
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_port = intf['attachto']
                self.pfc_wd_rx_port_addr = intf['addr']
                self.pfc_wd_rx_port_id = self.port_idx_info[self.pfc_wd_rx_port]
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = intf['attachto']
                pfc_wd_test_port_addr = intf['addr']
                pfc_wd_test_port_id = self.port_idx_info[pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for item in self.bgp_info:
                    if ipaddress.ip_address(str(item['addr'])).version != 4:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and item['peer_addr'] == self.pfc_wd_rx_port_addr:
                        self.pfc_wd_rx_neighbor_addr = item['addr']
                    if item['peer_addr'] == pfc_wd_test_port_addr:
                        pfc_wd_test_neighbor_addr = item['addr']

                self.test_ports[pfc_wd_test_port] = {
                    'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'rx_port': [self.pfc_wd_rx_port],
                    'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'peer_device': self.neighbors.get(pfc_wd_test_port, {}).get('peerdevice', ''),
                    'test_port_id': pfc_wd_test_port_id,
                    'rx_port_id': [self.pfc_wd_rx_port_id],
                    'test_port_type': 'interface'
                    }
            # populate info for the first port
            if first_pair:
                self.test_ports[self.pfc_wd_rx_port] = {
                    'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'rx_port': [pfc_wd_test_port],
                    'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'peer_device': self.neighbors.get(self.pfc_wd_rx_port, {}).get('peerdevice', ''),
                    'test_port_id': self.pfc_wd_rx_port_id,
                    'rx_port_id': [pfc_wd_test_port_id],
                    'test_port_type': 'interface'
                    }

            first_pair = False

    def parse_pc_list(self):
        """
        Built the port info from the ports in portchannel

        The constructed port info is a dict with a port as the key (transmit port) and value contains
        all the info associated with this port (its fanout neighbor, receive ports, receive
        ptf ids, transmit ptf ids, neighbor portchannel addr, its own portchannel addr etc).
        The first port in the list is assumed to be the Rx port. The rest
        of the ports will use this port as the Rx port while populating their dict
        info. The selected Rx port when used as a transmit port will use the next port in
        the list as its associated Rx port
        """
        pfc_wd_test_port = None
        first_pair = False
        for item in self.mg_facts['minigraph_portchannel_interfaces']:
            if ipaddress.ip_address(str(item['addr'])).version != 4:
                continue
            pc = item['attachto']
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_portchannel = pc
                self.pfc_wd_rx_port = self.pc_info[pc]['members']
                self.pfc_wd_rx_port_addr = item['addr']
                self.pfc_wd_rx_port_id = [self.port_idx_info[port] for port in self.pfc_wd_rx_port]
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = self.pc_info[pc]['members']
                pfc_wd_test_port_addr = item['addr']
                pfc_wd_test_port_id = [self.port_idx_info[port] for port in pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for bgp_item in self.bgp_info:
                    if ipaddress.ip_address(str(bgp_item['addr'])).version != 4:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and bgp_item['peer_addr'] == self.pfc_wd_rx_port_addr:
                        self.pfc_wd_rx_neighbor_addr = bgp_item['addr']
                    if bgp_item['peer_addr'] == pfc_wd_test_port_addr:
                        pfc_wd_test_neighbor_addr = bgp_item['addr']

                for port in pfc_wd_test_port:
                    self.test_ports[port] = {'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                                             'rx_port': self.pfc_wd_rx_port,
                                             'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                             'peer_device': self.neighbors.get(port, {}).get('peerdevice', ''),
                                             'test_port_id': self.port_idx_info[port],
                                             'rx_port_id': self.pfc_wd_rx_port_id,
                                             'test_portchannel_members': pfc_wd_test_port_id,
                                             'test_port_type': 'portchannel'
                                             }
            # populate info for the first port
            if first_pair:
                for port in self.pfc_wd_rx_port:
                    self.test_ports[port] = {'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                             'rx_port': pfc_wd_test_port,
                                             'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                                             'peer_device': self.neighbors.get(port, {}).get('peerdevice', ''),
                                             'test_port_id': self.port_idx_info[port],
                                             'rx_port_id': pfc_wd_test_port_id,
                                             'test_portchannel_members': self.pfc_wd_rx_port_id,
                                             'test_port_type': 'portchannel'
                                             }

            first_pair = False

    def parse_vlan_list(self):
        """
        Add vlan specific port info to the already populated port info dict.

        Each vlan interface will be the key and value contains all the info associated with this port
        (receive fanout neighbor, receive port receive ptf id, transmit ptf id, neighbor addr etc).

        Args:
            None

        Returns:
            temp_ports (dict): port info constructed from the vlan interfaces
        """
        temp_ports = dict()
        # In Python2, dict.values() returns list object, but in Python3 returns an iterable but not indexable object.
        # So that convert to list explicitly.
        vlan_details = list(self.vlan_info.values())[0]
        # Filter(remove) PortChannel interfaces from VLAN members list
        vlan_members = [port for port in vlan_details['members'] if 'PortChannel' not in port]

        vlan_type = vlan_details.get('type')
        vlan_id = vlan_details['vlanid']
        rx_port = self.pfc_wd_rx_port if isinstance(self.pfc_wd_rx_port, list) else [self.pfc_wd_rx_port]
        rx_port_id = self.pfc_wd_rx_port_id if isinstance(self.pfc_wd_rx_port_id, list) else [self.pfc_wd_rx_port_id]
        for item in vlan_members:
            temp_ports[item] = {'test_neighbor_addr': self.vlan_nw,
                                'rx_port': rx_port,
                                'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                'peer_device': self.neighbors.get(item, {}).get('peerdevice', ''),
                                'test_port_id': self.port_idx_info[item],
                                'rx_port_id': rx_port_id,
                                'test_port_type': 'vlan'
                                }
            if hasattr(self, 'pfc_wd_rx_port_vlan_id'):
                temp_ports[item]['rx_port_vlan_id'] = self.pfc_wd_rx_port_vlan_id
            if vlan_type is not None and vlan_type == 'Tagged':
                temp_ports[item]['test_port_vlan_id'] = vlan_id

        return temp_ports

    def parse_vlan_sub_interface_list(self):
        """Build the port info from the vlan sub-interfaces."""
        pfc_wd_test_port = None
        first_pair = False
        for sub_intf in self.mg_facts['minigraph_vlan_sub_interfaces']:
            if ipaddress.ip_address(str(sub_intf['addr'])).version != 4:
                continue
            intf_name, vlan_id = sub_intf['attachto'].split(constants.VLAN_SUB_INTERFACE_SEPARATOR)
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_port = intf_name
                self.pfc_wd_rx_port_addr = sub_intf['addr']
                self.pfc_wd_rx_port_id = self.port_idx_info[self.pfc_wd_rx_port]
                self.pfc_wd_rx_port_vlan_id = vlan_id
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = intf_name
                pfc_wd_test_port_addr = sub_intf['addr']
                pfc_wd_test_port_id = self.port_idx_info[pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for item in self.bgp_info:
                    if ipaddress.ip_address(str(item['addr'])).version != 4:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and item['peer_addr'] == self.pfc_wd_rx_port_addr:
                        self.pfc_wd_rx_neighbor_addr = item['addr']
                    if item['peer_addr'] == pfc_wd_test_port_addr:
                        pfc_wd_test_neighbor_addr = item['addr']

                self.test_ports[pfc_wd_test_port] = {
                    'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'rx_port': [self.pfc_wd_rx_port],
                    'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'peer_device': self.neighbors.get(pfc_wd_test_port, {}).get('peerdevice', ''),
                    'test_port_id': pfc_wd_test_port_id,
                    'rx_port_id': [self.pfc_wd_rx_port_id],
                    'rx_port_vlan_id': self.pfc_wd_rx_port_vlan_id,
                    'test_port_vlan_id': vlan_id,
                    'test_port_type': 'interface'
                    }
            # populate info for the first port
            if first_pair:
                self.test_ports[self.pfc_wd_rx_port] = {
                    'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'rx_port': [pfc_wd_test_port],
                    'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'peer_device': self.neighbors.get(self.pfc_wd_rx_port, {}).get('peerdevice', ''),
                    'test_port_id': self.pfc_wd_rx_port_id,
                    'rx_port_id': [pfc_wd_test_port_id],
                    'rx_port_vlan_id': vlan_id,
                    'test_port_vlan_id': self.pfc_wd_rx_port_vlan_id,
                    'test_port_type': 'interface'
                    }

            first_pair = False


def set_pfc_timers():
    """
    Set PFC timers

    Args:
        None

    Returns:
        pfc_timers (dict)
    """
    pfc_timers = {'pfc_wd_detect_time': 400,
                  'pfc_wd_restore_time': 400,
                  'pfc_wd_restore_time_large': 3000,
                  'pfc_wd_poll_time': 400
                  }
    return pfc_timers


def select_test_ports(test_ports):
    """
    Select a subset of ports from the generated port info

    Args:
        test_ports (dict): Constructed port info

    Returns:
        selected_ports (dict): random port info or set of ports matching seed
    """
    selected_ports = dict()
    rx_ports = set()
    if len(test_ports) > 2:
        modulo = int(len(test_ports)/3)
        seed = int(len(test_ports)/2)
        for port, port_info in test_ports.items():
            rx_port = port_info["rx_port"]
            if isinstance(rx_port, (list, tuple)):
                rx_ports.update(rx_port)
            else:
                rx_ports.add(rx_port)
            if (int(port_info['test_port_id']) % modulo) == (seed % modulo):
                selected_ports[port] = port_info
        # filter out selected ports that also act as rx ports
        selected_ports = {p: pi for p, pi in list(selected_ports.items())
                          if p not in rx_port}
    elif len(test_ports) == 2:
        selected_ports = test_ports

    if not selected_ports:
        random_port = list(test_ports.keys())[0]
        selected_ports[random_port] = test_ports[random_port]

    return selected_ports


def start_wd_on_ports(duthost, port, restore_time, detect_time, action="drop"):
    """
    Starts PFCwd on ports

    Args:
        port (string): single port or space separated list of ports
        restore_time (int): PFC storm restoration time
        detect_time (int): PFC storm detection time
        action (string): PFCwd action. values include 'drop', 'forward'
    """
    duthost.command("pfcwd start --action {} --restoration-time {} {} {}"
                    .format(action, restore_time, port, detect_time))


def fetch_vendor_specific_diagnosis_re(duthost):
    """
    Fetch regular expression of vendor specific diagnosis information
    Args:
        duthost: The duthost object
    """
    unsupported_branches = ['202012', '202205', '202211']
    if duthost.os_version in unsupported_branches or duthost.sonic_release in unsupported_branches:
        return ""

    return VENDOR_SPEC_ADDITIONAL_INFO_RE.get(duthost.facts["asic_type"], "")


@pytest.fixture(scope='class', autouse=False)
def start_background_traffic(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        pfc_queue_idx,
        setup_pfc_test,
        copy_ptftests_directory,
        ptfhost,
        tbinfo
        ):
    """
       This fixutre starts a background traffic during
       the test. This will start a continuous traffic flow from PTF
       exiting the test port.

       This uses a fixture pfc_queue_idx: which *must* be defined in the
       test script before using this fixture.
    """
    if duthosts[enum_rand_one_per_hwsku_frontend_hostname].facts['asic_type'] != "cisco-8000":
        yield
        return

    # This is needed only for cisco-8000
    program_name = "pfcwd_background_traffic"
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dst_dut_intf = list(setup_pfc_test['test_ports'].keys())[0]
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    vlan_ports = []
    for vlan in mg_facts['minigraph_vlans'].keys():
        vlan_ports.extend(mg_facts['minigraph_vlans'][vlan]['members'])
    all_ip_intfs = mg_facts['minigraph_interfaces'] + mg_facts['minigraph_portchannel_interfaces']
    non_vlan_ports = set(list(setup_pfc_test['test_ports'])) - set(vlan_ports) - set([dst_dut_intf])
    src_dut_intf = random.choice(list(non_vlan_ports))
    dest_mac = dut.get_dut_iface_mac(src_dut_intf)
    # Find out if the selected port is a lag member
    # If so, we need to use the neighbor address of the portchannel.
    # else, we need the neighbor address of the interface itself.
    required_intf = dst_dut_intf
    for intf in mg_facts['minigraph_portchannels']:
        if dst_dut_intf in mg_facts['minigraph_portchannels'][intf]['members']:
            required_intf = intf
            break
    # At this point, required_intf is either a portchannel or Ethernet port.
    # It should have a neighbor address or it is an error.
    dst_ip_addr = None
    for intf_obj in all_ip_intfs:
        if intf_obj['attachto'] == required_intf:
            dst_ip_addr = intf_obj['peer_addr']
            break
    if dst_ip_addr is None:
        raise RuntimeError("Could not find the neighbor address for intf:{}".format(required_intf))
    ptf_src_port = mg_facts['minigraph_ptf_indices'][src_dut_intf]
    ptf_dst_port = mg_facts['minigraph_ptf_indices'][dst_dut_intf]
    extra_vars = {
        f'{program_name}_args':
            'dest_mac=u"{}";dst_ip_addr={};ptf_src_port={};ptf_dst_port={};pfc_queue_idx={}'.format(
                dest_mac,
                dst_ip_addr,
                ptf_src_port,
                ptf_dst_port,
                pfc_queue_idx
                )}
    try:
        ptfhost.command('supervisorctl stop {}'.format(program_name))
    except BaseException:
        pass

    ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)
    script_args = \
        '''dest_mac=u"{}";dst_ip_addr="{}";ptf_src_port={};ptf_dst_port={};pfc_queue_idx={}'''.format(
                dest_mac,
                dst_ip_addr,
                ptf_src_port,
                ptf_dst_port,
                pfc_queue_idx)
    supervisor_conf_content = ('''
[program:{program_name}]
command=/root/env-python3/bin/ptf --test-dir /root/ptftests/py3 {program_name}.BG_pkt_sender'''
                               ''' --platform-dir /root/ptftests/ -t'''
                               ''' '{script_args}' --relax  --platform remote
process_name={program_name}
stdout_logfile=/tmp/{program_name}.out.log
stderr_logfile=/tmp/{program_name}.err.log
redirect_stderr=false
autostart=false
autorestart=true
startsecs=1
numprocs=1
'''.format(script_args=script_args, program_name=program_name))
    ptfhost.copy(
        content=supervisor_conf_content,
        dest=f'/etc/supervisor/conf.d/{program_name}.conf')

    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')
    ptfhost.command(f'supervisorctl start {program_name}')

    yield

    try:
        ptfhost.command(f'supervisorctl stop {program_name}')
    except BaseException:
        pass
    ptfhost.command(f'supervisorctl remove {program_name}')


@contextlib.contextmanager
def send_background_traffic(duthost, ptfhost, storm_hndle, selected_test_ports, test_ports_info):
    """Send background traffic, stop the background traffic when the context finish """
    if is_mellanox_device(duthost) or is_cisco_device(duthost):
        background_traffic_params = _prepare_background_traffic_params(duthost, storm_hndle,
                                                                       selected_test_ports,
                                                                       test_ports_info)
        background_traffic_log = _send_background_traffic(ptfhost, background_traffic_params)
        # Ensure the background traffic is running before moving on
        time.sleep(1)
    yield
    if is_mellanox_device(duthost) or is_cisco_device(duthost):
        _stop_background_traffic(ptfhost, background_traffic_log)


def _prepare_background_traffic_params(duthost, queues, selected_test_ports, test_ports_info):
    src_ports = []
    dst_ports = []
    src_ips = []
    dst_ips = []
    for selected_test_port in selected_test_ports:
        selected_test_port_info = test_ports_info[selected_test_port]
        if type(selected_test_port_info["rx_port_id"]) == list:
            src_ports.append(selected_test_port_info["rx_port_id"][0])
        else:
            src_ports.append(selected_test_port_info["rx_port_id"])
        dst_ports.append(selected_test_port_info["test_port_id"])
        dst_ips.append(selected_test_port_info["test_neighbor_addr"])
        src_ips.append(selected_test_port_info["rx_neighbor_addr"])

    router_mac = duthost.get_dut_iface_mac(selected_test_ports[0])
    # Send enough packets to make sure the background traffic is running during the test
    pkt_count = 100000

    ptf_params = {'router_mac': router_mac,
                  'src_ports': src_ports,
                  'dst_ports': dst_ports,
                  'src_ips': src_ips,
                  'dst_ips': dst_ips,
                  'queues': queues,
                  'bidirection': False,
                  'pkt_count': pkt_count}

    return ptf_params


def _send_background_traffic(ptfhost, ptf_params):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/pfc_wd_background_traffic.PfcWdBackgroundTrafficTest.{}.log".format(timestamp)
    ptf_runner(ptfhost, "ptftests", "pfc_wd_background_traffic.PfcWdBackgroundTrafficTest", "/root/ptftests",
               params=ptf_params, log_file=log_file, is_python3=True, async_mode=True)

    return log_file


def _stop_background_traffic(ptfhost, background_traffic_log):
    pids = ptfhost.shell(f"pgrep -f {background_traffic_log}")["stdout_lines"]
    for pid in pids:
        ptfhost.shell(f"kill -9 {pid}", module_ignore_errors=True)


def has_neighbor_device(setup_pfc_test):
    """
    Check if there are neighbor devices present

    Args:
        setup_pfc_test (fixture): Module scoped autouse fixture for PFCwd

    Returns:
        bool: True if there are neighbor devices present, False otherwise
    """
    for _, details in setup_pfc_test['selected_test_ports'].items():
        # 'rx_port' and 'rx_port_id' are expected to be conjugate attributes
        # if one is unset or contains None, the other should be as well
        if (not details.get('rx_port') or None in details['rx_port']) or \
                (not details.get('rx_port_id') or None in details['rx_port_id']):
            return False  # neighbor devices are not present
    return True


def check_pfc_storm_state(dut, port, queue, expected_state):
    """
    Helper function to check if PFC storm is detected/restored on a given queue
    """
    pfcwd_stat = parser_show_pfcwd_stat(dut, port, queue)
    if expected_state == "storm":
        if ("storm" in pfcwd_stat[0]['status']) and \
                int(pfcwd_stat[0]['storm_detect_count']) > int(pfcwd_stat[0]['restored_count']):
            return True
    else:
        if ("storm" not in pfcwd_stat[0]['status']) and \
                int(pfcwd_stat[0]['storm_detect_count']) == int(pfcwd_stat[0]['restored_count']):
            return True
    return False


def parser_show_pfcwd_stat(dut, select_port, select_queue):
    """
    CLI "show pfcwd stats" output:
    admin@bjw-can-7060-1:~$ show pfcwd stats
            QUEUE    STATUS    STORM DETECTED/RESTORED    TX OK/DROP    RX OK/DROP    TX LAST OK/DROP    RX LAST OK/DROP # noqa: E501
    -------------  --------  -------------------------  ------------  ------------  -----------------  ----------------- # noqa: E501
    Ethernet112:4       N/A                        2/2       100/100       100/100              100/0              100/0 # noqa: E501
    admin@bjw-can-7060-1:~$
    """
    logger.info("port {} queue {}".format(select_port, select_queue))
    pfcwd_stat_output = dut.show_and_parse('show pfcwd stat')

    pfcwd_stat = []
    for item in pfcwd_stat_output:
        port, queue = item['queue'].split(':')
        if port != select_port or int(queue) != int(select_queue):
            continue
        storm_detect_count, restored_count = item['storm detected/restored'].split('/')
        tx_ok_count, tx_drop_count = item['tx ok/drop'].split('/')
        rx_ok_count, rx_drop_count = item['rx ok/drop'].split('/')
        tx_last_ok_count, tx_last_drop_count = item['tx last ok/drop'].split('/')
        rx_last_ok_count, rx_last_drop_count = item['rx last ok/drop'].split('/')

        parsed_dict = {
            'port': port,
            'queue': queue,
            'status': item['status'],
            'storm_detect_count': storm_detect_count,
            'restored_count': restored_count,
            'tx_ok_count': tx_ok_count,
            'tx_drop_count': tx_drop_count,
            'rx_ok_count': rx_ok_count,
            'rx_drop_count': rx_drop_count,
            'tx_last_ok_count': tx_last_ok_count,
            'tx_last_drop_count': tx_last_drop_count,
            'rx_last_ok_count': rx_last_ok_count,
            'rx_last_drop_count': rx_last_drop_count
        }
        pfcwd_stat.append(parsed_dict)

    return pfcwd_stat
