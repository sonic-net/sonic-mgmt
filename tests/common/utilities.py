"""
Utility functions can re-used in testing scripts.
"""
import collections
import inspect
import ipaddress
import logging
import re
import six
import sys
import threading
import time
import traceback
from io import BytesIO

import pytest
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager

from tests.common import constants
from tests.common.cache import cached
from tests.common.cache import FactsCache

logger = logging.getLogger(__name__)
cache = FactsCache()


def skip_version(duthost, version_list):
    """
    @summary: Skip current test if any given version keywords are in os_version
    @param duthost: The DUT
    @param version_list: A list of incompatible versions
    """
    if any(version in duthost.os_version for version in version_list):
        pytest.skip("DUT has version {} and test does not support {}".format(duthost.os_version, ", ".join(version_list)))

def skip_release(duthost, release_list):
    """
    @summary: Skip current test if any given release keywords are in os_version, match sonic_release.
              skip_release is more robust than skip_version.
    @param duthost: The DUT
    @param release_list: A list of incompatible releases
    """
    if any(release in duthost.os_version for release in release_list):
        pytest.skip("DUT has version {} and test does not support {}".format(duthost.os_version, ", ".join(release_list)))

    if any(release == duthost.sonic_release for release in release_list):
        pytest.skip("DUT is release {} and test does not support {}".format(duthost.sonic_release, ", ".join(release_list)))

def skip_release_for_platform(duthost, release_list, platform_list):
    """
    @summary: Skip current test if any given release keywords are in os_version and any given platform keywords are in platform
    @param duthost: The DUT
    @param release_list: A list of incompatible releases
    @param platform_list: A list of incompatible platforms
    """
    if any(release in duthost.os_version for release in release_list) and \
		any(platform in duthost.facts['platform'] for platform in platform_list):
        pytest.skip("DUT has version {} and platform {} and test does not support {} for {}".format(
            duthost.os_version,
            duthost.facts['platform'],
			", ".join(release_list),
			", ".join(platform_list)))

def wait(seconds, msg=""):
    """
    @summary: Pause specified number of seconds
    @param seconds: Number of seconds to pause
    @param msg: Optional extra message for pause reason
    """
    logger.info("Pause %d seconds, reason: %s" % (seconds, msg))
    time.sleep(seconds)


def wait_until(timeout, interval, condition, *args, **kwargs):
    """
    @summary: Wait until the specified condition is True or timeout.
    @param timeout: Maximum time to wait
    @param interval: Poll interval
    @param condition: A function that returns False or True
    @param *args: Extra args required by the 'condition' function.
    @param **kwargs: Extra args required by the 'condition' function.
    @return: If the condition function returns True before timeout, return True. If the condition function raises an
        exception, log the error and keep waiting and polling.
    """
    logger.debug("Wait until %s is True, timeout is %s seconds, checking interval is %s" % \
        (condition.__name__, timeout, interval))
    start_time = time.time()
    elapsed_time = 0
    while elapsed_time < timeout:
        logger.debug("Time elapsed: %f seconds" % elapsed_time)

        try:
            check_result = condition(*args, **kwargs)
        except Exception:
            exc_info = sys.exc_info()
            details = traceback.format_exception(*exc_info)
            logger.error("Exception caught while checking %s:\n%s" % (condition.__name__, "".join(details)))
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


def wait_tcp_connection(client, server_hostname, listening_port, timeout_s = 30):
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
    if 'exception' in res:
        logger.warn("Failed to establish TCP connection to %s:%d, timeout=%d" % (str(server_hostname), listening_port, timeout_s))
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
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
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
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False


def compare_crm_facts(left, right):
    """Compare CRM facts

    Args:
        left (dict): crm facts returned by dut.get_crm_facts()
        right (dict): crm facts returned by dut.get_crm_facts()

    Returns:
        list: List of unmatched items.
    """
    unmatched = []

    for k, v in left['resources'].items():
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

    for k, v in left_acl_group.items():
        lv = v
        rv = right_acl_group[k]
        if lv['available'] != rv['available'] or lv['used'] != rv['used']:
            unmatched.append({'left': {k: lv}, 'right': {k: rv}})

    return unmatched


def dump_scapy_packet_show_output(packet):
    """Dump packet show output to string."""
    _stdout, sys.stdout = sys.stdout, BytesIO()
    try:
        packet.show()
        return sys.stdout.getvalue()
    finally:
        sys.stdout = _stdout


def compose_dict_from_cli(fields_list):
    """Convert the output of hgetall command to a dict object containing the field, key pairs of the database table content

    Args:
        fields_list: A list of lines, the output of redis-cli hgetall command
    """
    return dict(zip(fields_list[0::2], fields_list[1::2]))


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
        logger.info("DUT release {} exits in release list {}, QOS db field value refered to table names".format(duthost.sonic_release, ", ".join(release_list)))
        return True
    return False
