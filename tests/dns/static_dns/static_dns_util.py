import logging
import json
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from ipaddress import ip_address, IPv4Address, IPv6Address


logger = logging.getLogger(__name__)
allure.logger = logger

RESOLV_CONF_FILE = "/etc/resolv.conf"


def get_nameserver_from_config_db(duthost):
    """
    Get the DNS nameserver configured in the config db
    :param duthost: DUT host object
    :return: DNS nameserver list
    """
    nameservers = duthost.show_and_parse("show dns nameserver")
    return [str(nameserver["nameserver"]) for nameserver in nameservers]


def get_nameserver_from_resolvconf(duthost, file_name=RESOLV_CONF_FILE, container=None):
    """
    Get the DNS nameserver from resolv.conf
    :param duthost: DUT host object
    :param container: The container name, if it is specified, then get the file content of the container,
                      else get the file content in the host
    :return: DNS nameserver list
    Example of content in resolv.conf:
        nameserver 1.1.1.1
        nameserver 2.2.2.2

    """
    if container:
        resolv_conf = duthost.shell(f"docker exec -i {container} cat {file_name}", module_ignore_errors=True)
    else:
        resolv_conf = duthost.shell(f"cat {file_name}", module_ignore_errors=True)
    assert resolv_conf["rc"] == 0, f"Failed to read {file_name}!"
    current_nameservers = []
    for line in resolv_conf["stdout_lines"]:
        if not line.startswith("nameserver"):
            continue
        current_nameservers.append(line.split()[1])

    current_nameservers = set(current_nameservers)
    nameservers = " ".join(current_nameservers)
    logger.info(f"nameservers in resolv.conf are: [{nameservers}]")
    return current_nameservers


def clear_nameserver_from_resolvconf(duthost):
    duthost.shell(f"echo > {RESOLV_CONF_FILE}")
    containers = duthost.get_running_containers()
    for container in containers:
        duthost.shell(f"docker exec {container} /bin/bash -c \"echo > {RESOLV_CONF_FILE}\"")


def get_mgmt_port_ip_info(duthost):
    mgmt_port = "eth0"
    ip_addr = duthost.shell(f"show ip interfaces | grep -w '{mgmt_port}' | awk '{{print $2}}'")['stdout']
    default_route = duthost.shell("show ip route 0.0.0.0/0 json")['stdout']

    if default_route:
        default_route = json.loads(default_route)
        gwaddr = default_route['0.0.0.0/0'][0]["nexthops"][0]["ip"]

    return {
        mgmt_port:
        {
            ip_addr:
            {
                "gwaddr": gwaddr
            }
        }
    }


def config_mgmt_ip(duthost, mgmt_interfaces, action):
    """
    Config the ip for mgmt interface
    :param duthost: DUT host object
    :param mgmt_interfaces: mgmt interfaces info dict
           examples:
           {
              "eth0":
              {
                 "10.210.24.128/22":
                 {
                    "gwaddr": "10.210.24.1"
                 },
                 "fe80::e42:a1ff:fe60:65d8/64":
                 {
                    "gwaddr": "fe80::1"
                 }
              }
           }
    :param action: add/remove
    Notes: When add both ipv4 and ipv6 and the mgmt interface, need to add ipv4 first, and then ipv6.
           When remove the address from the mgmt interface, better to remove ipv6 first, and then ipv4.
    """
    for mgmt_interface, ip_configs in mgmt_interfaces.items():
        ip_addrs_with_prefix = []
        for ip_addr_with_prefix in ip_configs.keys():
            ip_addr = ip_address(ip_addr_with_prefix.split("/")[0])
            is_ipv4 = type(ip_addr) is IPv4Address
            is_ipv6 = type(ip_addr) is IPv6Address
            if (is_ipv4 and action == "add") or (is_ipv6 and action == "remove"):
                ip_addrs_with_prefix.insert(0, ip_addr_with_prefix)
            else:
                ip_addrs_with_prefix.append(ip_addr_with_prefix)

        for ip_addr_with_prefix in ip_addrs_with_prefix:
            gwaddr = ip_configs[ip_addr_with_prefix]['gwaddr']
            if action == "remove":
                duthost.remove_ip_addr_from_port(mgmt_interface, ip_addr_with_prefix)
            else:
                duthost.add_ip_addr_to_port(mgmt_interface, ip_addr_with_prefix, gwaddr)


def verify_nameserver_in_config_db(duthost, expected_nameserver):
    """
    Verify the nameserver in the config db is expected
    :param duthost: DUT host object
    :param expected_nameserver: Expected nameserver list
    """
    nameservers_in_config_db = get_nameserver_from_config_db(duthost)
    assert set(nameservers_in_config_db) == set(expected_nameserver), \
        f"The nameserver in the config db is: {nameservers_in_config_db}, expected is: {nameservers_in_config_db}"


def verify_nameserver_in_conf_file(duthost, expected_nameserver, expect_same=True):
    """
    Verify the DNS nameserver in the conf file is same or not with the expected nameservers
    :param duthost: DUT host object
    :param expected_nameserver: expected_nameserver: Expected nameserver list
    :param expected_same: expect the value in the conf file to be same or not as expected_nameserver
    """
    assert wait_until(30, 5, 0, _verify_nameserver_in_conf_file, duthost, expected_nameserver,
                      expect_same=expect_same), "The nameserver is resolv.conf file is not as expected"


def _verify_nameserver_in_conf_file(duthost, expected_nameserver, expect_same=True):
    """
    Verify the DNS nameserver in the conf file is same or not with the expected nameservers
    :param duthost: DUT host object
    :param expected_nameserver: expected_nameserver: Expected nameserver list
    :param expect_same: expect the value in the conf file to be same or not as expected_nameserver
    """
    nameserver_in_host_conf = get_nameserver_from_resolvconf(duthost)
    logging.info(f"The nameserver in the host's {RESOLV_CONF_FILE} is: {nameserver_in_host_conf}, "
                 f"expected is: {expected_nameserver}")
    if expect_same:
        assert set(nameserver_in_host_conf) == set(expected_nameserver), \
            f"The nameserver in the host's {RESOLV_CONF_FILE} is: {nameserver_in_host_conf}, " \
            f"expected is: {expected_nameserver}"
    else:
        assert set(nameserver_in_host_conf) != set(expected_nameserver), \
            f"The nameserver in the host's {RESOLV_CONF_FILE} is: {nameserver_in_host_conf}, " \
            f"expected is: {expected_nameserver}"
    containers = duthost.get_running_containers()
    for container in containers:
        nameserver_in_containers_conf = get_nameserver_from_resolvconf(duthost, container=container)
        logging.info(f"The nameserver in container {container}'s {RESOLV_CONF_FILE} "
                     f"is: {nameserver_in_containers_conf}, expected is: {expected_nameserver}")
        if expect_same:
            assert set(nameserver_in_containers_conf) == set(expected_nameserver), \
                f"The nameserver in container {container}'s {RESOLV_CONF_FILE} is: {nameserver_in_containers_conf}, " \
                f"expected is: {expected_nameserver}"
        else:
            assert set(nameserver_in_containers_conf) != set(expected_nameserver), \
                f"The nameserver in container {container}'s {RESOLV_CONF_FILE} is: {nameserver_in_containers_conf}, " \
                f"expected is: {expected_nameserver}"
    return True


def add_dns_nameserver(duthost, ip_addr, module_ignore_errors=False):
    return duthost.shell(f"config dns nameserver add {ip_addr}", module_ignore_errors=module_ignore_errors)


def del_dns_nameserver(duthost, ip_addr, module_ignore_errors=False):
    return duthost.shell(f"config dns nameserver del {ip_addr}", module_ignore_errors=module_ignore_errors)


# DNS_OPTIONS is the singleton table DNS_OPTIONS with a single well-known row GLOBAL
# (i.e. ConfigDB key "DNS_OPTIONS|GLOBAL"). There is no `config dns` CLI for the
# resolver options, so they are written directly to CONFIG_DB. The `search` leaf-list
# is serialized by SONiC as the "search@" field with a comma-separated value.
DNS_OPTIONS_TABLE = "DNS_OPTIONS"
DNS_OPTIONS_KEY = f"{DNS_OPTIONS_TABLE}|GLOBAL"


def apply_resolv_config(duthost):
    """
    Regenerate /etc/resolv.conf from the current CONFIG_DB without a full config reload.
    The resolv-config service renders resolv.conf.j2 with sonic-cfggen and runs resolvconf.
    :param duthost: DUT host object
    """
    duthost.shell("systemctl restart resolv-config.service")


def set_dns_options(duthost, search=None, ndots=None, timeout=None, attempts=None):
    """
    Write DNS resolver options to CONFIG_DB at DNS_OPTIONS|GLOBAL.
    :param duthost: DUT host object
    :param search: list of search-domain suffixes (stored as the "search@" leaf-list field)
    :param ndots: ndots threshold (0-15)
    :param timeout: per-query timeout in seconds (1-30)
    :param attempts: number of query attempts (1-5)
    Only the arguments that are not None are written, so callers can set a subset of options.
    """
    if search is not None:
        duthost.shell(f'sonic-db-cli CONFIG_DB hset "{DNS_OPTIONS_KEY}" "search@" "{",".join(search)}"')
    for field, value in (("ndots", ndots), ("timeout", timeout), ("attempts", attempts)):
        if value is not None:
            duthost.shell(f'sonic-db-cli CONFIG_DB hset "{DNS_OPTIONS_KEY}" "{field}" "{value}"')


def clear_dns_options(duthost):
    """
    Remove the DNS_OPTIONS|GLOBAL row from CONFIG_DB.
    :param duthost: DUT host object
    """
    duthost.shell(f'sonic-db-cli CONFIG_DB del "{DNS_OPTIONS_KEY}"')


def _read_resolvconf_lines(duthost, file_name=RESOLV_CONF_FILE, container=None):
    if container:
        resolv_conf = duthost.shell(f"docker exec -i {container} cat {file_name}", module_ignore_errors=True)
    else:
        resolv_conf = duthost.shell(f"cat {file_name}", module_ignore_errors=True)
    assert resolv_conf["rc"] == 0, f"Failed to read {file_name}!"
    return resolv_conf["stdout_lines"]


def get_search_from_resolvconf(duthost, container=None):
    """
    Return the ordered search-domain list from the `search` line in resolv.conf ([] if absent).
    :param duthost: DUT host object
    :param container: container name to read from, else the host
    """
    for line in _read_resolvconf_lines(duthost, container=container):
        if line.startswith("search"):
            return line.split()[1:]
    return []


def get_options_from_resolvconf(duthost, container=None):
    """
    Return the resolver options from the `options` line in resolv.conf as a dict, e.g.
    "options ndots:2 timeout:3 attempts:4" -> {"ndots": "2", "timeout": "3", "attempts": "4"} ({} if absent).
    :param duthost: DUT host object
    :param container: container name to read from, else the host
    """
    options = {}
    for line in _read_resolvconf_lines(duthost, container=container):
        if line.startswith("options"):
            for token in line.split()[1:]:
                if ":" in token:
                    key, value = token.split(":", 1)
                    options[key] = value
    return options


def verify_dns_options_in_conf_file(duthost, expected_search=None, expected_options=None):
    """
    Verify the DNS search list and/or resolver options in resolv.conf on the host and every
    running container match expectations, retrying to allow the resolv-config service to settle.
    :param duthost: DUT host object
    :param expected_search: expected ordered search list (None skips the search check)
    :param expected_options: expected options dict (None skips the options check)
    """
    assert wait_until(30, 5, 0, _verify_dns_options_in_conf_file, duthost, expected_search, expected_options), \
        "The DNS options in the resolv.conf file are not as expected"


def _verify_dns_options_in_conf_file(duthost, expected_search, expected_options):
    expected_options_str = None if expected_options is None else {k: str(v) for k, v in expected_options.items()}
    expected_search_list = None if expected_search is None else list(expected_search)
    for container in [None] + list(duthost.get_running_containers()):
        location = "host" if container is None else f"container {container}"
        if expected_search_list is not None:
            search = get_search_from_resolvconf(duthost, container=container)
            if search != expected_search_list:
                logging.info(f"The search list in the {location}'s {RESOLV_CONF_FILE} is: {search}, "
                             f"expected is: {expected_search_list}")
                return False
        if expected_options_str is not None:
            options = get_options_from_resolvconf(duthost, container=container)
            if options != expected_options_str:
                logging.info(f"The options in the {location}'s {RESOLV_CONF_FILE} are: {options}, "
                             f"expected is: {expected_options_str}")
                return False
    return True
