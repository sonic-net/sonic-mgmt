"""
Utility functions can re-used in testing scripts.
"""
import collections
import ipaddress
import logging
import six
import sys
import threading
import time
import re

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager

from tests.common.cache import FactsCache

logger = logging.getLogger(__name__)
cache = FactsCache()


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
        except Exception as e:
            logger.error("Exception caught while checking %s: %s" % (condition.__name__, repr(e)))
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

    def run(self):
        """
        @summary: Run the target function, call `start()` to start the thread
                  instead of directly calling this one.
        """
        self._e = None
        try:
            threading.Thread.run(self)
        except Exception:
            self._e = sys.exc_info()

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


def get_host_vars(inv_files, hostname, variable=None):
    """Use ansible's InventoryManager to get value of variables defined for the specified host in the specified
    inventory files.

    Args:
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
        hostname (string): Hostname
        variable (string or None): Variable name. Defaults to None.

    Returns:
        string or dict or None: If variable name is specified, return the variable value. If variable is not found,
            return None. If variable name is not specified, return all variables in a dictionary. If the host is not
            found, return None.
    """
    cached_vars = cache.read(hostname, 'host_vars')
    if cached_vars and cached_vars['inv_files'] == inv_files:
        host_vars = cached_vars['vars']
    else:
        im = get_inventory_manager(inv_files)
        host = im.get_host(hostname)
        if not host:
            logger.error("Unable to find host {} in {}".format(hostname, str(inv_files)))
            return None
        host_vars = host.vars
        cache.write(hostname, 'host_vars', {'inv_files': inv_files, 'vars': host_vars})

    if variable:
        return host_vars.get(variable, None)
    else:
        return host_vars


def get_host_visible_vars(inv_files, hostname, variable=None):
    """Use ansible's VariableManager and InventoryManager to get value of variables visible to the specified host.
    The variable could be defined in host_vars or in group_vars that the host belongs to.

    Args:
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
        hostname (string): Hostname
        variable (string or None): Variable name. Defaults to None.

    Returns:
        string or dict or None: If variable name is specified, return the variable value. If variable is not found,
            return None. If variable name is not specified, return all variables in a dictionary. If the host is not
            found, return None.
    """
    cached_vars = cache.read(hostname, 'host_visible_vars')

    if cached_vars and cached_vars['inv_files'] == inv_files:
        host_visible_vars = cached_vars['vars']
    else:
        vm = get_variable_manager(inv_files)
        im = vm._inventory
        host = im.get_host(hostname)
        if not host:
            logger.error("Unable to find host {} in {}".format(hostname, str(inv_files)))
            return None

        host_visible_vars = vm.get_vars(host=host)
        cache.write(hostname, 'host_visible_vars', {'inv_files': inv_files, 'vars': host_visible_vars})

    if variable:
        return host_visible_vars.get(variable, None)
    else:
        return host_visible_vars


def get_group_visible_vars(inv_files, group_name, variable=None):
    """Use ansible's VariableManager and InventoryManager to get value of variables visible to the first host belongs
    to the specified group. The variable could be defined in host_vars of the first host or in group_vars that the host
    belongs to.

    Args:
        inv_files (list or string): List of inventory file pathes, or string of a single inventory file path. In tests,
            it can be get from request.config.getoption("ansible_inventory").
        group_name (string): Name of group in ansible inventory.
        variable (string or None): Variable name. Defaults to None.

    Returns:
        string or dict or None: If variable name is specified, return the variable value. If variable is not found,
            return None. If variable name is not specified, return all variables in a dictionary. If the group is not
            found or there is no host in the group, return None.
    """
    cached_vars = cache.read(group_name, 'group_visible_vars')
    if cached_vars and cached_vars['inv_files'] == inv_files:
        group_visible_vars = cached_vars['vars']
    else:
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

        group_visible_vars = vm.get_vars(host=first_host)
        cache.write(group_name, 'group_visible_vars', {'inv_files': inv_files, 'vars': group_visible_vars})

    if variable:
        return group_visible_vars.get(variable, None)
    else:
        return group_visible_vars


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


def get_test_server_vars(inv_files, server, variable=None):
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
        variable (string or None): Variable name. Defaults to None.

    Returns:
        string or dict or None: If variable name is specified, return the variable value. If variable is not found,
            return None. If variable name is not specified, return all variables in a dictionary. If the server group
            is not found or there is no test server host in the group, return None.
    """
    cached_vars = cache.read(server, 'test_server_vars')
    if cached_vars and cached_vars['inv_files'] == inv_files:
        test_server_vars = cached_vars['vars']
    else:
        test_server_vars = None
        host = get_test_server_host(inv_files, server)
        if host:
            test_server_vars = host.vars
            cache.write(server, 'test_server_vars', {'inv_files': inv_files, 'vars': test_server_vars})

    if test_server_vars:
        if variable:
            return test_server_vars.get(variable, None)
        else:
            return test_server_vars
    else:
        logger.error("Unable to find test server host under group {}".format(server))
        return None


def get_test_server_visible_vars(inv_files, server, variable=None):
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
        variable (string or None): Variable name. Defaults to None.

    Returns:
        string or dict or None: If variable name is specified, return the variable value. If variable is not found,
            return None. If variable name is not specified, return all variables in a dictionary. If the group is not
            found or there is no host in the group, return None.
    """
    cached_vars = cache.read(server, 'test_server_visible_vars')
    if cached_vars and cached_vars['inv_files'] == inv_files:
        test_server_visible_vars = cached_vars['vars']
    else:
        test_server_visible_vars = None

        vm = get_variable_manager(inv_files)
        im = vm._inventory
        group = im.groups.get(server, None)
        if not group:
            logger.error("Unable to find group {} in {}".format(server, str(inv_files)))
            return None
        for host in group.get_hosts():
            if not re.match(r'VM\d+', host.name):   # This must be the test server host
                test_server = host.name
        test_server_host = im.get_host(test_server)
        if not test_server_host:
            logger.error("Unable to find host %s in %s", test_server_host, inv_files)
            return None

        test_server_visible_vars = vm.get_vars(host=test_server_host)
        cache.write(server, 'test_server_visible_vars', {'inv_files': inv_files, 'vars': test_server_visible_vars})

    if test_server_visible_vars:
        if variable:
            return test_server_visible_vars.get(variable, None)
        else:
            return test_server_visible_vars
    else:
        logger.error("Unable to find test server host under group {}".format(server))
        return None


def is_ipv4_address(ip_address):
    """Check if ip address is ipv4."""
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False
