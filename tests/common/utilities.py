"""
Utility functions can re-used in testing scripts.
"""
import collections
import contextlib
import inspect
import ipaddress
import json
import logging
import os
import re
import random
import six
import sys
import threading
import time
import traceback
import copy
import tempfile
import uuid
import paramiko
from io import StringIO
from ast import literal_eval
from scapy.all import sniff as scapy_sniff
from paramiko.ssh_exception import AuthenticationException

import pytest
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager

from tests.common import constants
from tests.common.cache import cached
from tests.common.cache import FactsCache
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP
from tests.common.helpers.assertions import pytest_assert
from netaddr import valid_ipv6

logger = logging.getLogger(__name__)
cache = FactsCache()
LA_START_MARKER_SCRIPT = "scripts/find_la_start_marker.sh"
FIND_SYSLOG_MSG_SCRIPT = "scripts/find_log_msg.sh"


def check_skip_release(duthost, release_list):
    """
    @summary: check if need skip current test if any given release keywords are in os_version, match sonic_release.
    @param duthost: The DUT
    @param release_list: A list of incompatible releases
    """
    if any(release in duthost.os_version for release in release_list):
        reason = "DUT has version {} and test does not support {}".format(duthost.os_version, ", ".join(release_list))
        logger.info(reason)
        return (True, reason)

    if any(release == duthost.sonic_release for release in release_list):
        reason = "DUT is release {} and test does not support {}".format(duthost.sonic_release, ", ".join(release_list))
        logger.info(reason)
        return (True, reason)

    return (False, '')


def skip_release(duthost, release_list):
    """
    @summary: Skip current test if any given release keywords are in os_version, match sonic_release.
              skip_release is more robust than skip_version.
    @param duthost: The DUT
    @param release_list: A list of incompatible releases
    """
    (skip, reason) = check_skip_release(duthost, release_list)
    if skip:
        pytest.skip(reason)


def skip_release_for_platform(duthost, release_list, platform_list):
    """
    @summary: Skip current test if any given release keywords are in os_version
              and any given platform keywords are in platform
    @param duthost: The DUT
    @param release_list: A list of incompatible releases
    @param platform_list: A list of incompatible platforms
    """
    if any(release in duthost.os_version for release in release_list) and \
            any(platform in duthost.facts['platform'] for platform in platform_list):
        pytest.skip("DUT has version {} and platform {} and test does not support {} for {}".format(
                    duthost.os_version, duthost.facts['platform'], ", ".join(release_list), ", ".join(platform_list)))


def get_sup_node_or_random_node(duthosts):
    # accomodate for T2 chassis, which only SUP has pdu info
    # try to find sup node in multi-dut
    for dut in duthosts:
        if dut.is_supervisor_node():
            return dut
    # if not chassis, it's dualtor or single-dut, return random node or itself
    if len(duthosts) > 1:
        duthosts = random.sample(list(duthosts), 1)
    logger.info("Randomly select dut {} for testing".format(duthosts[0]))
    return duthosts[0]


def wait(seconds, msg=""):
    """
    @summary: Pause specified number of seconds
    @param seconds: Number of seconds to pause
    @param msg: Optional extra message for pause reason
    """
    logger.info("Pause %d seconds, reason: %s" % (seconds, msg))
    time.sleep(seconds)


def wait_until(timeout, interval, delay, condition, *args, **kwargs):
    """
    @summary: Wait until the specified condition is True or timeout.
    @param timeout: Maximum time to wait
    @param interval: Poll interval
    @param delay: Delay time
    @param condition: A function that returns False or True
    @param *args: Extra args required by the 'condition' function.
    @param **kwargs: Extra args required by the 'condition' function.
    @return: If the condition function returns True before timeout, return True. If the condition function raises an
        exception, log the error and keep waiting and polling.
    """
    logger.debug("Wait until %s is True, timeout is %s seconds, checking interval is %s, delay is %s seconds" %
                 (condition.__name__, timeout, interval, delay))

    if delay > 0:
        logger.debug("Delay for %s seconds first" % delay)
        time.sleep(delay)

    start_time = time.time()
    elapsed_time = 0
    while elapsed_time < timeout:
        logger.debug("Time elapsed: %f seconds" % elapsed_time)

        try:
            check_result = condition(*args, **kwargs)
        except Exception as e:
            exc_info = sys.exc_info()
            details = traceback.format_exception(*exc_info)
            logger.error(
                "Exception caught while checking {}:{}, error:{}".format(
                    condition.__name__, "".join(details), e
                )
            )
            check_result = False

        if check_result:
            logger.debug("%s is True, exit early with True" % condition.__name__)
            return True
        else:
            logger.debug("%s is False, wait %d seconds and check again" % (condition.__name__, interval))
            time.sleep(interval)
            elapsed_time = time.time() - start_time

    if elapsed_time >= timeout:
        logger.debug("%s is still False after %d seconds, exit with False" % (condition.__name__, timeout))
        return False


def wait_tcp_connection(client, server_hostname, listening_port, timeout_s=30):
    """
    @summary: Wait until tcp connection is ready or timeout
    @param client: The tcp client host instance
    @param server_hostname: The tcp server hostname
    @param listening_port: Port server is listening on
    @param timeout: Maximum time to wait (30s in default)
    """
    res = client.wait_for(host=server_hostname,
                          port=listening_port,
                          state='started',
                          timeout=timeout_s,
                          module_ignore_errors=True)
    if 'exception' in res or res.get('failed') is True:
        logger.warn("Failed to establish TCP connection to %s:%d, timeout=%d" %
                    (str(server_hostname), listening_port, timeout_s))
        return False
    return True


class InterruptableThread(threading.Thread):
    """Thread class that can be interrupted by Exception raised."""

    def __init__(self, **kwargs):
        super(InterruptableThread, self).__init__(**kwargs)
        self._e = None

    def set_error_handler(self, error_handler):
        """Add error handler callback that will be called when the thread exits with error."""
        self.error_handler = error_handler

    def set_exit_handler(self, exit_handler):
        """Add exit handler callback that will be called when the thread eixts."""
        self.exit_handler = exit_handler

    def run(self):
        """
        @summary: Run the target function, call `start()` to start the thread
                  instead of directly calling this one.
        """
        try:
            threading.Thread.run(self)
        except Exception:
            self._e = sys.exc_info()
            if getattr(self, "error_handler", None) is not None:
                self.error_handler(*self._e)

        if getattr(self, "exit_handler", None) is not None:
            self.exit_handler()

    def join(self, timeout=None, suppress_exception=False):
        """
        @summary: Join the thread, if `target` raises an exception, reraise it.
        @timeout: Wait timeout for `target` to finish.
        @suppress_exception: Default False, reraise the exception raised in
                             `target`. If True, return the exception instead of
                             raising.
        """
        threading.Thread.join(self, timeout=timeout)
        if self._e:
            if suppress_exception:
                return self._e
            else:
                six.reraise(*self._e)


def join_all(threads, timeout):
    """
    @summary: Join a list of threads with a max wait timeout.
    @param threads: a list of thread objects.
    @param timeout: the maximum time to wait for the threads to finish.
    """
    curr_time = start_time = time.time()
    end_time = start_time + timeout
    threads = collections.deque(threads)
    while curr_time <= end_time:
        for _ in range(len(threads)):
            thread = threads.popleft()
            thread.join(timeout=0)
            if thread.is_alive():
                threads.append(thread)
        if not threads:
            break
        time.sleep(0.1)
        curr_time = time.time()
    else:
        raise RuntimeError("Timeout on waiting threads: %s" %
                           [repr(thread) for thread in threads])


def get_inventory_manager(inv_files):
    return InventoryManager(loader=DataLoader(), sources=inv_files)


def get_variable_manager(inv_files):
    return VariableManager(loader=DataLoader(), inventory=get_inventory_manager(inv_files))


def get_inventory_files(request):
    """Use request.config.getoption('ansible_inventory') to the get list of inventory files.
       The 'ansible_inventory' option could have already been converted to a list by #enchance_inventory fixture.
       Args:
            request: request paramater for pytest.
    """
    if isinstance(request.config.getoption("ansible_inventory"), list):
        # enhance_inventory fixture changes ansible_inventory to a list.
        inv_files = request.config.getoption("ansible_inventory")
    else:
        inv_files = [inv_file.strip() for inv_file in request.config.getoption("ansible_inventory").split(",")]
    return inv_files


def _get_parameter(function, func_args, func_kargs, argname):
    """Get the parameter passed as argname to function."""
    args_binding = inspect.getcallargs(function, *func_args, **func_kargs)
    return args_binding.get(argname) or args_binding.get("kargs").get(argname)


def zone_getter_factory(argname):
    """Create zone getter function used to retrieve parameter as zone."""

    def _zone_getter(function, func_args, func_kargs):
        param = _get_parameter(function, func_args, func_kargs, argname)
        if param is None:
            raise ValueError("Failed to get parameter '%s' from function %s as zone." % (argname, function))
        return param

    return _zone_getter


def _check_inv_files_after_read(facts, function, func_args, func_kargs):
    """Check if inventory file matches after read host variable from cached files."""
    if facts is not FactsCache.NOTEXIST:
        inv_files = _get_parameter(function, func_args, func_kargs, "inv_files")
        if inv_files == facts["inv_files"]:
            return facts["vars"]
    # no facts cached or facts not in the same inventory, return `NOTEXIST`
    # to force calling the decorated function to get facts
    return FactsCache.NOTEXIST


def _mark_inv_files_before_write(facts, function, func_args, func_kargs):
    """Add inventory to the facts before write to cached file."""
    inv_files = _get_parameter(function, func_args, func_kargs, "inv_files")
    return {"inv_files": inv_files, "vars": facts}


@cached(
    "host_vars",
    zone_getter=zone_getter_factory("hostname"),
    after_read=_check_inv_files_after_read,
    before_write=_mark_inv_files_before_write
)
def get_host_vars(inv_files, hostname):
    """Use ansible's InventoryManager to get value of variables defined for the specified host in the specified
    inventory files.

    Args:
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
        hostname (string): Hostname

    Returns:
        dict or None: dict if the host is found, None if the host is not found.
    """
    im = get_inventory_manager(inv_files)
    host = im.get_host(hostname)
    if not host:
        logger.error("Unable to find host {} in {}".format(hostname, str(inv_files)))
        return None
    return host.vars.copy()


@cached(
    "host_visible_vars",
    zone_getter=zone_getter_factory("hostname"),
    after_read=_check_inv_files_after_read,
    before_write=_mark_inv_files_before_write
)
def get_host_visible_vars(inv_files, hostname):
    """Use ansible's VariableManager and InventoryManager to get value of variables visible to the specified host.
    The variable could be defined in host_vars or in group_vars that the host belongs to.

    Args:
        inv_files (list or string): List of inventory file paths, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
            MUST use the inventory file under the ansible folder, otherwise host_vars and group_vars would not be
            visible.
        hostname (string): Hostname

    Returns:
        dict or None: dict if the host is found, None if the host is not found.
    """
    vm = get_variable_manager(inv_files)
    im = vm._inventory
    host = im.get_host(hostname)
    if not host:
        logger.error("Unable to find host {} in {}".format(hostname, str(inv_files)))
        return None
    return vm.get_vars(host=host)


@cached(
    "group_visible_vars",
    zone_getter=zone_getter_factory("group_name"),
    after_read=_check_inv_files_after_read,
    before_write=_mark_inv_files_before_write
)
def get_group_visible_vars(inv_files, group_name):
    """Use ansible's VariableManager and InventoryManager to get value of variables visible to the first host belongs
    to the specified group. The variable could be defined in host_vars of the first host or in group_vars that the host
    belongs to.

    Args:
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
        group_name (string): Name of group in ansible inventory.

    Returns:
        dict or None: dict if the host is found, None if the host is not found.
    """
    vm = get_variable_manager(inv_files)
    im = vm._inventory
    group = im.groups.get(group_name, None)
    if not group:
        logger.error("Unable to find group {} in {}".format(group_name, str(inv_files)))
        return None
    group_hosts = group.get_hosts()
    if len(group_hosts) == 0:
        logger.error("No host in group {}".format(group_name))
        return None
    first_host = group_hosts[0]
    return vm.get_vars(host=first_host)


def get_test_server_host(inv_files, server):
    """Get test server ansible host from the 'server' column in testbed file."""
    vm = get_variable_manager(inv_files)
    im = vm._inventory
    group = im.groups.get(server, None)
    if not group:
        logger.error("Unable to find group {} in {}".format(server, str(inv_files)))
        return None
    for host in group.get_hosts():
        if not re.match(r'VM\d+', host.name):   # This must be the test server host
            return host
    return None


@cached(
    "test_server_vars",
    zone_getter=zone_getter_factory("server"),
    after_read=_check_inv_files_after_read,
    before_write=_mark_inv_files_before_write
)
def get_test_server_vars(inv_files, server):
    """Use ansible's VariableManager and InventoryManager to get value of variables of test server belong to specified
    server group.

    In testbed.csv file, we can get the server name of each test setup under the 'server' column. For example
    'server_1', 'server_2', etc. This server name is indeed a group name in used ansible inventory files. This group
    contains children groups for test server and VMs. This function is try to just return the variables of test servers
    belong to the specified server group.

    Args:
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
        server (string): Server of test setup in testbed.csv file.

    Returns:
        dict or None: dict if the host is found, None if the host is not found.
    """
    host = get_test_server_host(inv_files, server)
    if not host:
        logger.error("Unable to find test server host under group {}".format(server))
        return None
    return host.vars.copy()


@cached(
    "test_server_visible_vars",
    zone_getter=zone_getter_factory("server"),
    after_read=_check_inv_files_after_read,
    before_write=_mark_inv_files_before_write
)
def get_test_server_visible_vars(inv_files, server):
    """Use ansible's VariableManager and InventoryManager to get value of variables visible to the specified server
    group.

    In testbed.csv file, we can get the server name of each test setup under the 'server' column. For example
    'server_1', 'server_2', etc. This server name is indeed a group name in used ansible inventory files. This group
    contains children groups for test server and VMs. This function is try to just return the variables visible to
    the server group.

    Args:
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
        server (string): Server of test setup in testbed.csv file.

    Returns:
        dict or None: dict if the host is found, None if the host is not found.
    """
    test_server_host = get_test_server_host(inv_files, server)
    vm = get_variable_manager(inv_files)
    if not test_server_host:
        logger.error("Unable to find host %s in %s", test_server_host, inv_files)
        return None

    return vm.get_vars(host=test_server_host)


def is_ipv4_address(ip_address):
    """Check if ip address is ipv4."""
    ip_address = ip_address.encode().decode()
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False


def get_mgmt_ipv6(duthost):
    config_facts = duthost.get_running_config_facts()
    mgmt_interfaces = config_facts.get("MGMT_INTERFACE", {})
    mgmt_ipv6 = None

    for mgmt_interface, ip_configs in mgmt_interfaces.items():
        for ip_addr_with_prefix in ip_configs.keys():
            ip_addr = ip_addr_with_prefix.split("/")[0]
            if valid_ipv6(ip_addr):
                mgmt_ipv6 = ip_addr
    return mgmt_ipv6


def compare_crm_facts(left, right):
    """Compare CRM facts

    Args:
        left (dict): crm facts returned by dut.get_crm_facts()
        right (dict): crm facts returned by dut.get_crm_facts()

    Returns:
        list: List of unmatched items.
    """
    unmatched = []

    for k, v in list(left['resources'].items()):
        lv = v
        rv = right['resources'][k]
        if lv['available'] != rv['available'] or lv['used'] != rv['used']:
            unmatched.append({'left': {k: lv}, 'right': {k: rv}})

    left_acl_group = {}
    for ag in left['acl_group']:
        key = '{}|{}|{}'.format(ag['resource name'], ag['bind point'], ag['stage'])
        left_acl_group[key] = {
            'available': ag['available count'],
            'used': ag['used count']
        }

    right_acl_group = {}
    for ag in left['acl_group']:
        key = '{}|{}|{}'.format(ag['resource name'], ag['bind point'], ag['stage'])
        right_acl_group[key] = {
            'available': ag['available count'],
            'used': ag['used count']
        }

    for k, v in list(left_acl_group.items()):
        lv = v
        rv = right_acl_group[k]
        if lv['available'] != rv['available'] or lv['used'] != rv['used']:
            unmatched.append({'left': {k: lv}, 'right': {k: rv}})

    return unmatched


def dump_scapy_packet_show_output(packet):
    """Dump packet show output to string."""
    _stdout, sys.stdout = sys.stdout, StringIO()
    try:
        if six.PY2:
            packet.show()
        else:
            packet.show2()
        return sys.stdout.getvalue()
    finally:
        sys.stdout = _stdout


def compose_dict_from_cli(str_output):
    """Convert the output of sonic-db-cli <DB> HGETALL command from string to
       dict object containing the field, key pairs of the database table content

    Args:
        str_output: String with output of cli sonic-db-cli <DB> HGETALL <key>
    Returns:
        dict: dict object containing the field, key pairs of the database table content
    """
    return literal_eval(str_output)


def get_intf_by_sub_intf(sub_intf, vlan_id=None):
    """
    Deduce interface from sub interface by striping vlan id,
    if vlan id is not passed, will automatically strip vlan id by finding '.',
     if '.' found: strip the right or it,
     if '.' not found, return original sub_intf.
    Args:
        sub_intf (str): sub interface name, e.g. Ethernet100.10
        vlan_id (str): vlan id, e.g. 10

    Returns:
        str: interface name, e.g. Ethernet100
    """
    if type(sub_intf) != str:
        sub_intf = str(sub_intf)

    if not vlan_id:
        idx_of_sub_int_indicator = sub_intf.find(constants.VLAN_SUB_INTERFACE_SEPARATOR)
        if idx_of_sub_int_indicator > -1:
            return sub_intf[:idx_of_sub_int_indicator]
        return sub_intf

    vlan_suffix = constants.VLAN_SUB_INTERFACE_SEPARATOR + vlan_id
    if sub_intf.endswith(vlan_suffix):
        return sub_intf[:-len(vlan_suffix)]
    return sub_intf


def check_qos_db_fv_reference_with_table(duthost):
    """
    @summary: Check qos db field value refrence with table name or not.
    @param duthost: The DUT
    """
    release_list = ["201811", "201911", "202012", "202106"]
    if any(release == duthost.sonic_release for release in release_list):
        logger.info("DUT release {} exits in release list {}, QOS db field value refered to table names"
                    .format(duthost.sonic_release, ", ".join(release_list)))
        return True
    return False


def str2bool(str):
    """
    This is used as a type when add option for pytest
    :param str: The input string value
    :return: False if value is 0 or false, else True
    """
    return str.lower() not in ["0", "false", "no"]


def setup_ferret(duthost, ptfhost, tbinfo):
    '''
        Sets Ferret service on PTF host.
    '''
    VXLAN_CONFIG_FILE = '/tmp/vxlan_decap.json'

    def prepareVxlanConfigData(duthost, ptfhost, tbinfo):
        '''
            Prepares Vxlan Configuration data for Ferret service running on PTF host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        '''
        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        vxlanConfigData = {
            'minigraph_port_indices': mgFacts['minigraph_ptf_indices'],
            'minigraph_portchannel_interfaces': mgFacts['minigraph_portchannel_interfaces'],
            'minigraph_portchannels': mgFacts['minigraph_portchannels'],
            'minigraph_lo_interfaces': mgFacts['minigraph_lo_interfaces'],
            'minigraph_vlans': mgFacts['minigraph_vlans'],
            'minigraph_vlan_interfaces': mgFacts['minigraph_vlan_interfaces'],
            'dut_mac': duthost.facts['router_mac']
        }
        with open(VXLAN_CONFIG_FILE, 'w') as file:
            file.write(json.dumps(vxlanConfigData, indent=4))

        logger.info('Copying ferret config file to {0}'.format(ptfhost.hostname))
        ptfhost.copy(src=VXLAN_CONFIG_FILE, dest='/tmp/')

    ptfhost.copy(src="arp/files/ferret.py", dest="/opt")
    result = duthost.shell(
        cmd=r'''ip route show type unicast |
            sed -e '/proto 186\|proto zebra\|proto bgp/!d' -e '/default/d' -ne '/0\//p' |
            head -n 1 |
            sed -ne 's/0\/.*$/1/p'
            '''
    )
    dip = result['stdout']
    logger.info('VxLan Sender {0}'.format(dip))
    vxlan_port_out = duthost.shell('redis-cli -n 0 hget "SWITCH_TABLE:switch" "vxlan_port"')
    if 'stdout' in vxlan_port_out and vxlan_port_out['stdout'].isdigit():
        vxlan_port = int(vxlan_port_out['stdout'])
        ferret_args = '-f /tmp/vxlan_decap.json -s {0} -a {1} -p {2}'.format(
            dip, duthost.facts["asic_type"], vxlan_port)
    else:
        ferret_args = '-f /tmp/vxlan_decap.json -s {0} -a {1}'.format(dip, duthost.facts["asic_type"])

    ptfhost.host.options['variable_manager'].extra_vars.update({'ferret_args': ferret_args})
    logger.info('Copying ferret config file to {0}'.format(ptfhost.hostname))
    ptfhost.template(src='arp/files/ferret.conf.j2', dest='/etc/supervisor/conf.d/ferret.conf')

    logger.info('Generate pem and key files for ssl')
    ptfhost.command(
        cmd='''openssl req -new -x509 -keyout test.key -out test.pem -days 365 -nodes
        -subj "/C=10/ST=Test/L=Test/O=Test/OU=Test/CN=test.com"''',
        chdir='/opt'
    )
    prepareVxlanConfigData(duthost, ptfhost, tbinfo)
    logger.info('Refreshing supervisor control with ferret configuration')
    ptfhost.shell('supervisorctl reread && supervisorctl update')
    ptfhost.shell('supervisorctl restart ferret')


def safe_filename(filename, replacement_char='_'):
    """Replace illegal characters in the original filename with "_" or other specified characters.

    Reference: https://www.mtu.edu/umc/services/websites/writing/characters-avoid/

    Args:
        filename (str): The original filename
        replacement_char (str, optional): Replacement for illegal characters. Defaults to '_'.

    Returns:
        str: New filename with illegal characters replaced.
    """
    illegal_chars_pattern = re.compile(r"[#%&{}\\<>\*\?/ \$!'\":@\+`|=]")
    return re.sub(illegal_chars_pattern, replacement_char, filename)


@contextlib.contextmanager
def update_environ(*remove, **update):
    """
    Temporarily update the environment variables.

    :param remove: Environment variables to remove.
    :param update: Dictionary of environment variables and values to add/update.
    """
    env = os.environ
    update = update or {}
    remove = remove or []

    updated = (set(update.keys()) | set(remove)) & set(env.keys())

    to_restore = {k: env[k] for k in updated}
    to_removed = set(k for k in update if k not in env)

    try:
        env.update(update)
        [env.pop(k, None) for k in remove]
        yield
    finally:
        env.update(to_restore)
        for k in to_removed:
            env.pop(k)


def get_plt_reboot_ctrl(duthost, tc_name, reboot_type):
    """
    @summary: utility function returns list of reboot dict containing timeout and wait
    for each reboot type
    @return a list of reboot dict containing timeout and wait for each reboot type
    DUTHOST:
        plt_reboot_dict:
          cold:
            timeout: 300
            wait: 600
          warm-reboot:
            timeout: 300
            wait: 600
          acl/test_acl.py::TestAclWithReboot:
            timeout: 300
            wait: 600
          platform_tests/test_reload_config.py::test_reload_configuration_checks:
            timeout: 300
            wait: 60
    """

    reboot_dict = dict()
    im = duthost.sonichost.host.options['inventory_manager']
    inv_files = im._sources
    dut_vars = get_host_visible_vars(inv_files, duthost.hostname)

    if 'plt_reboot_dict' in dut_vars:
        for key in list(dut_vars['plt_reboot_dict'].keys()):
            if key in tc_name:
                for mod_id in list(dut_vars['plt_reboot_dict'][key].keys()):
                    reboot_dict[mod_id] = dut_vars['plt_reboot_dict'][key][mod_id]
        if not reboot_dict:
            if reboot_type in list(dut_vars['plt_reboot_dict'].keys()):
                for mod_id in list(dut_vars['plt_reboot_dict'][reboot_type].keys()):
                    reboot_dict[mod_id] = dut_vars['plt_reboot_dict'][reboot_type][mod_id]

    return reboot_dict


def pdu_reboot(pdu_controller):
    """Power-cycle the DUT by turning off and on the PDU outlets.

    Args:
        pdu_controller: PDU controller object implementing the BasePduController interface.
            User can acquire pdu_controller object from fixture tests.common.plugins.pdu_controller.pdu_controller

    Returns: True if the PDU reboot is successful, False otherwise.
    """
    if not pdu_controller:
        logging.warning("pdu_controller is None, skip PDU reboot")
        return False
    hostname = pdu_controller.dut_hostname
    if not pdu_controller.turn_off_outlet():
        logging.error("Turn off the PDU outlets of {} failed".format(hostname))
        return False
    time.sleep(10)  # sleep 10 second to ensure there is gap between power off and on
    if not pdu_controller.turn_on_outlet():
        logging.error("Turn on the PDU outlets of {} failed".format(hostname))
        return False
    return True


def get_image_type(duthost):
    """get the SONiC image type
        It might be public/microsoft/...or any other type.
        Different vendors can define their different types by checking the specific information from the build image.
    Args:
        duthost: AnsibleHost instance for DUT
    Returns:
        The returned image type string will be used as a key of map DEFAULT_SSH_CONNECT_PARAMS defined in
        tests/common/constants.py for looking up default credential for this type of image.
    """

    return "public"


def find_duthost_on_role(duthosts, role, tbinfo):
    role_set = False
    role_host = None
    for duthost in duthosts:
        if role_set:
            break
        if duthost.is_supervisor_node():
            continue

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
            if role in neighbor["name"]:
                role_host = duthost
                role_set = True
    pytest_assert(role_host, "Could not find {} duthost".format(role))
    return role_host


def get_neighbor_port_list(duthost, neighbor_name):
    """
    @summary: Get neighbor port in dut by neighbor_name
    @param duthost: The DUT
    @param neighbor_name: name or keyword contained in name of neighbor
    @return a list of port name
        Sample output: ["Ethernet45", "Ethernet46"]
    """
    config_facts = duthost.get_running_config_facts()
    neighbor_port_list = []
    for port_name, value in list(config_facts["DEVICE_NEIGHBOR"].items()):
        if neighbor_name.upper() in value["name"].upper():
            neighbor_port_list.append(port_name)

    return neighbor_port_list


def get_neighbor_ptf_port_list(duthost, neighbor_name, tbinfo):
    """
    @summary: Get neighbor port in ptf by neighbor_name
    @param duthost: The DUT
    @param neighbor_name: name or keyword contained in name of neighbor
    @param tbinfo: testbed information
    @return a list of port index
        Sample output: [45, 46]
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    neighbor_port_list = get_neighbor_port_list(duthost, neighbor_name)
    ptf_port_list = []
    for neighbor_port in neighbor_port_list:
        ptf_port_list.append(mg_facts["minigraph_ptf_indices"][neighbor_port])

    return ptf_port_list


def get_upstream_neigh_type(topo_type, is_upper=True):
    """
    @summary: Get neighbor type by topo type
    @param topo_type: topo type
    @param is_upper: if is_upper is True, return uppercase str, else return lowercase str
    @return a str
        Sample output: "mx"
    """
    if topo_type in UPSTREAM_NEIGHBOR_MAP:
        return UPSTREAM_NEIGHBOR_MAP[topo_type].upper() if is_upper else UPSTREAM_NEIGHBOR_MAP[topo_type]

    return None


def get_downstream_neigh_type(topo_type, is_upper=True):
    """
    @summary: Get neighbor type by topo type
    @param topo_type: topo type
    @param is_upper: if is_upper is True, return uppercase str, else return lowercase str
    @return a str
        Sample output: "mx"
    """
    if topo_type in DOWNSTREAM_NEIGHBOR_MAP:
        return DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper() if is_upper else DOWNSTREAM_NEIGHBOR_MAP[topo_type]

    return None


def run_until(interval, delay, retry, condition, function, *args, **kwargs):
    """
    @summary: Execute function until condition or retry number met.
    @param interval: Interval between function execution.
    @param delay: delay before start function call
    @param retry: Number of retries until function meets condition.
    @param condition: The expected condition for function to be met.
    @param function: The function to be executed.
    @param *args: Extra args required by the 'function'.
    @param **kwargs: Extra args required by the 'function'.
    @return: If the function meets conditions returns function output before finish specified retries. If no conditions
        specified or was not meet - returns last function call output.
    """
    logger.debug("Wait until %s meet condition %s or %s retries, interval between calls is %s seconds" %
                 (function.__name__, condition, retry, interval))
    if delay > 0:
        time.sleep(delay)

    def compare_base_on_result_type(condition, result):
        # Check exact match
        if condition == result:
            return True
        # Check if function returns dict
        elif isinstance(result, dict):
            if condition in result.items():
                return True
        # Check if function returns string, list, set or tuple
        elif isinstance(result, str) or isinstance(result, list) or isinstance(result, set) or \
                isinstance(result, tuple):
            if condition in result:
                return True
        else:
            return False

    for _ in range(retry):
        try:
            func_call_result = function(*args, **kwargs)
            # Check if condition meets function result
            if compare_base_on_result_type(condition, func_call_result):
                break
        except Exception as e:
            exc_info = sys.exc_info()
            details = traceback.format_exception(*exc_info)
            logger.error(
                "Exception caught while checking {}:{}, error:{}".format(
                    function.__name__, "".join(details), e
                )
            )
        finally:
            # Wait if interval is set
            if interval > 0:
                time.sleep(interval)
    return func_call_result


def convert_scapy_packet_to_bytes(packet):
    """Convert scapy packet to bytes for python2 and python3 compatibility
    Args:
        packet: scapy packet
    Returns:
        str or bytes: packet in bytes
    """
    if six.PY2:
        return str(packet)
    else:
        return bytes(packet)


def update_pfcwd_default_state(duthost, filepath, default_pfcwd_value):
    """
    Set default_pfcwd_status in the specified file with parameter default_pfcwd_value
    The path is expected to be one of:
    - /etc/sonic/init_cfg.json
    - /etc/sonic/config_db.json

    Args:
        duthost (AnsibleHost): instance
        default_pfcwd_value: value of default_pfcwd_status, enable or disable

    Returns:
        original value of default_pfcwd_status
    """
    output = duthost.shell("cat {} | grep default_pfcwd_status".format(filepath))['stdout']
    matched = re.search('"default_pfcwd_status": "(.*)"', output)
    if matched:
        original_value = matched.group(1)
    else:
        pytest.fail("There is no default_pfcwd_status in /etc/sonic/init_cfg.json.")

    sed_command = ("sed -i \'s/\"default_pfcwd_status\": \"{}\"/\"default_pfcwd_status\": \"{}\"/g\' {}"
                   .format(original_value, default_pfcwd_value, filepath))
    duthost.shell(sed_command)

    return original_value


def delete_running_config(config_entry, duthost, is_json=True):
    if is_json:
        duthost.copy(content=json.dumps(config_entry, indent=4), dest="/tmp/del_config_entry.json")
    else:
        duthost.copy(src=config_entry, dest="/tmp/del_config_entry.json")
    duthost.shell("configlet -d -j {}".format("/tmp/del_config_entry.json"))
    duthost.shell("rm -f {}".format("/tmp/del_config_entry.json"))


def get_data_acl(duthost):
    acl_facts = duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]
    pre_acl_rules = acl_facts.get("DATAACL", {}).get("rules", None)
    return pre_acl_rules


def recover_acl_rule(duthost, data_acl):
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, "templates")
    acl_rules_template = "default_acl_rules.json"
    dut_tmp_dir = "/tmp"
    dut_conf_file_path = os.path.join(dut_tmp_dir, acl_rules_template)

    for key, value in data_acl.items():
        if key != "DEFAULT_RULE":
            seq_id = key.split('_')[1]
            acl_config = json.loads(open(os.path.join(template_dir, acl_rules_template)).read())
            acl_entry_template = \
                acl_config["acl"]["acl-sets"]["acl-set"]["dataacl"]["acl-entries"]["acl-entry"]["1"]
            acl_entry_config = acl_config["acl"]["acl-sets"]["acl-set"]["dataacl"]["acl-entries"]["acl-entry"]

            acl_entry_config[seq_id] = copy.deepcopy(acl_entry_template)
            acl_entry_config[seq_id]["config"]["sequence-id"] = seq_id
            acl_entry_config[seq_id]["l2"]["config"]["ethertype"] = value["ETHER_TYPE"]
            acl_entry_config[seq_id]["l2"]["config"]["vlan_id"] = value["VLAN_ID"]

    with tempfile.NamedTemporaryFile(suffix=".json", prefix="acl_config", mode="w") as fp:
        json.dump(acl_config, fp)
        fp.flush()
        logger.info("Generating config for ACL rule, ACL table - DATAACL")
        duthost.template(src=fp.name, dest=dut_conf_file_path, force=True)

    logger.info("Applying {}".format(dut_conf_file_path))
    duthost.command("acl-loader update full {}".format(dut_conf_file_path))


def get_ipv4_loopback_ip(duthost):
    """
    Get ipv4 loopback ip address
    """
    config_facts = duthost.get_running_config_facts()
    los = config_facts.get("LOOPBACK_INTERFACE", {})
    loopback_ip = None

    for key, _ in los.items():
        if "Loopback" in key:
            loopback_ips = los[key]
            for ip_str, _ in loopback_ips.items():
                ip = ip_str.split("/")[0]
                if is_ipv4_address(ip):
                    loopback_ip = ip
                    break

    return loopback_ip


def get_dscp_to_queue_value(dscp_value, dscp_to_tc_map, tc_to_queue_map):
    """
    Given a DSCP value, and the DSCP to TC map and TC to queue map, return the
    corresponding queue value.

    Args:
        dscp_value (int): DSCP value
        dscp_to_tc_map (str dict): DSCP to TC map
        tc_to_queue_map (str dict): TC to queue map
    Returns:
        int: queue value
    """
    if str(dscp_value) not in dscp_to_tc_map:
        return None

    tc_value = dscp_to_tc_map[str(dscp_value)]
    if tc_value not in tc_to_queue_map:
        return None

    return int(tc_to_queue_map[tc_value])


def find_egress_queue(all_queue_pkts, exp_queue_pkts, tolerance=0.05):
    """
    Given the number of packets egressing out of each queue and an expected number of packets to
    egress out of ONE of the queues, this function returns which queue it is. If no such queue exists, it returns -1.

    Args:
        all_queue_pkts ([int]): egress queue counts for all queues where packets are expected to egress from
                                in array form ex. [0, 0, 100, 0, 0, 0, 0]
        exp_queue_pkts (int): expected number of packets to egress from port
        tolerance (float): packet tolerance to expected queue packets - only followed if atleast 100 packets are
                           expected this accounts for background traffic
    Returns:
        queue_val (int): egress queue if found, else -1
    """
    pytest_assert(exp_queue_pkts >= 1, "At least one packet is expected to egress from the queue")
    for queue_pkt_index in range(len(all_queue_pkts)):
        if all_queue_pkts[queue_pkt_index] == 0:
            continue
        elif all_queue_pkts[queue_pkt_index] == exp_queue_pkts and exp_queue_pkts < 100:
            return queue_pkt_index
        elif (abs(all_queue_pkts[queue_pkt_index] - exp_queue_pkts)/exp_queue_pkts < tolerance) and \
             (exp_queue_pkts >= 100):
            # tolerance only followed if atleast 100 packets are expected
            return queue_pkt_index

    return -1


def get_egress_queue_pkt_count_all_prio(duthost, port):
    """
    Get the egress queue count in packets for a given port and all priorities from SONiC CLI.
    This is the equivalent of the "queuestat -j" command.
    Args:
        duthost (Ansible host instance): device under test
        port (str): port name
    Returns:
        array [int]: total count of packets in the queue for all priorities
    """
    raw_out = duthost.shell("queuestat -jp {}".format(port))['stdout']
    raw_json = json.loads(raw_out)
    intf_queue_stats = raw_json.get(port)
    queue_stats = []

    for prio in range(8):
        total_pkts_prio_str = intf_queue_stats.get("UC{}".format(prio)) if intf_queue_stats.get("UC{}".format(prio)) \
            is not None else {"totalpacket": "0"}
        total_pkts_str = total_pkts_prio_str.get("totalpacket")
        if total_pkts_str == "N/A" or total_pkts_str is None:
            total_pkts_str = "0"
        queue_stats.append(int(total_pkts_str.replace(',', '')))

    return queue_stats


@contextlib.contextmanager
def capture_and_check_packet_on_dut(
    duthost,
    interface='any',
    pkts_filter='',
    pkts_validator=lambda pkts: pytest_assert(len(pkts) > 0, "No packets captured"),
    pkts_validator_args=[],
    pkts_validator_kwargs={},
    wait_time=1
):
    """
    Capture packets on DUT and check if the packet is expected
    Parameters:
        duthost: the DUT to perform the packet capture
        interface: the interface to capture packets on, default is 'any'
        pkts_filter: the PCAP-FILTER to apply to the captured packets, default is '' means no filter
        pkts_validator: the function to validate the captured packets, default is to check if any packet is captured
        pkts_validator_args: ther args to pass to the pkts_validator function
        pkts_validator_kwargs: the kwargs to pass to the pkts_validator function
        wait_time: the time to wait before stopping the packet capture, default is 1 second
    """
    pcap_save_path = "/tmp/func_capture_and_check_packet_on_dut_%s.pcap" % (str(uuid.uuid4()))
    cmd_capture_pkts = "sudo nohup tcpdump --immediate-mode -U -i %s -w %s >/dev/null 2>&1 %s & echo $!" \
        % (interface, pcap_save_path, pkts_filter)
    tcpdump_pid = duthost.shell(cmd_capture_pkts)["stdout"]
    cmd_check_if_process_running = "ps -p %s | grep %s |grep -v grep | wc -l" % (tcpdump_pid, tcpdump_pid)
    pytest_assert(duthost.shell(cmd_check_if_process_running)["stdout"] == "1",
                  "Failed to start tcpdump on DUT")
    logging.info("Start to capture packet on DUT, tcpdump pid: %s, pcap save path: %s, with command: %s"
                 % (tcpdump_pid, pcap_save_path, cmd_capture_pkts))
    try:
        yield
        time.sleep(wait_time)
        duthost.shell("kill -s 2 %s" % tcpdump_pid)
        with tempfile.NamedTemporaryFile() as temp_pcap:
            duthost.fetch(src=pcap_save_path, dest=temp_pcap.name, flat=True)
            pkts_validator(scapy_sniff(offline=temp_pcap.name), *pkts_validator_args, **pkts_validator_kwargs)
    finally:
        duthost.file(path=pcap_save_path, state="absent")


def _paramiko_ssh(ip_address, username, passwords):
    """
    Connect to the device via ssh using paramiko
    Args:
        ip_address (str): The ip address of device
        username (str): The username of device
        passwords (str or list): Potential passwords of device
            this argument can be either a string or a list of string
    Returns:
        AuthResult: the ssh session of device
    """
    if isinstance(passwords, str):
        candidate_passwords = [passwords]
    elif isinstance(passwords, list):
        candidate_passwords = passwords
    else:
        raise Exception("The passwords argument must be either a string or a list of string.")

    for password in candidate_passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip_address, username=username, password=password,
                        allow_agent=False, look_for_keys=False, timeout=10)
            return ssh, password
        except AuthenticationException:
            continue
        except Exception as e:
            logging.info("Cannot access device {} via ssh, error: {}".format(ip_address, e))
            raise e
    logging.info("Cannot access device {} via ssh, error: Password incorrect".format(ip_address))
    raise AuthenticationException


def paramiko_ssh(ip_address, username, passwords):
    ssh, pwd = _paramiko_ssh(ip_address, username, passwords)
    return ssh


def get_dut_current_passwd(ipv4_address, ipv6_address, username, passwords):
    try:
        _, passwd = _paramiko_ssh(ipv4_address, username, passwords)
    except AuthenticationException:
        raise
    except Exception:
        _, passwd = _paramiko_ssh(ipv6_address, username, passwords)
    return passwd


def check_msg_in_syslog(duthost, log_msg):
    """
    Checks for a given log message after the last start-LogAnalyzer message in syslog

    Args:
        duthost: Device under test.
        log_msg: Log message to be searched

    Yields:
        True if log message is present or returns False
    """
    la_output = duthost.script(LA_START_MARKER_SCRIPT)["stdout"]
    if not la_output:
        return False
    else:
        output = la_output.replace('\r', '').replace('\n', '')

    try:
        log_msg = f"\"{log_msg}\""
        log_output = duthost.script("%s %s %s" % (FIND_SYSLOG_MSG_SCRIPT, output, log_msg))
        if log_output:
            return True
        else:
            return False
    except Exception:
        return False
