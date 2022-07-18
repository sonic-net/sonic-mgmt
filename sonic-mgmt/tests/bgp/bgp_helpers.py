import os
import re
import time
import json
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
BGP_PLAIN_TEMPLATE = 'bgp_plain.j2'
BGP_NO_EXPORT_TEMPLATE = 'bgp_no_export.j2'
BGP_CONFIG_BACKUP = 'backup_bgpd.conf.j2'
DEFAULT_BGP_CONFIG = '/usr/share/sonic/templates/bgpd/bgpd.conf.j2'
DUMP_FILE = "/tmp/bgp_monitor_dump.log"
CUSTOM_DUMP_SCRIPT = "bgp/bgp_monitor_dump.py"
CUSTOM_DUMP_SCRIPT_DEST = "/usr/share/exabgp/bgp_monitor_dump.py"
BGPMON_TEMPLATE_FILE = 'bgp/templates/bgp_template.j2'
BGPMON_CONFIG_FILE = '/tmp/bgpmon.json'
BGP_MONITOR_NAME = "bgp_monitor"
BGP_MONITOR_PORT = 7000
BGP_ANNOUNCE_TIME = 30 #should be enough to receive and parse bgp updates

def apply_bgp_config(duthost, template_name):
    """
    Apply bgp configuration on the bgp docker of DUT

    Args:
        duthost: DUT host object
        template_name: pathname of the bgp config on the DUT
    """
    duthost.docker_copy_to_all_asics('bgp', template_name, DEFAULT_BGP_CONFIG)
    duthost.restart_service("bgp")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "swss"), "SWSS not started.")

def define_config(duthost, template_src_path, template_dst_path):
    """
    Define configuration of bgp on the DUT

    Args:
        duthost: DUT host object
        template_src_path: pathname of the bgp config on the server
        template_dst_path: pathname of the bgp config on the DUT
    """
    duthost.shell("mkdir -p {}".format(DUT_TMP_DIR))
    duthost.copy(src=template_src_path, dest=template_dst_path)
        

def get_no_export_output(vm_host):
    """
    Get no export routes on the VM

    Args:
        vm_host: VM host object
    """
    out = vm_host.eos_command(commands=['show ip bgp community no-export'])["stdout"]
    return re.findall(r'\d+\.\d+.\d+.\d+\/\d+\s+\d+\.\d+.\d+.\d+.*', out[0])


def apply_default_bgp_config(duthost, copy=False):
    """
    Apply default bgp configuration on the bgp docker of DUT

    Args:
        duthost: DUT host object
        copy: Bool value defines copy action of default bgp configuration
    """
    bgp_config_backup = os.path.join(DUT_TMP_DIR, BGP_CONFIG_BACKUP)
    if copy:
        duthost.docker_copy_from_asic('bgp', DEFAULT_BGP_CONFIG, bgp_config_backup)
    else:
        duthost.docker_copy_to_all_asics('bgp', bgp_config_backup, DEFAULT_BGP_CONFIG)
        # Skip 'start-limit-hit' threshold
        duthost.reset_service("bgp")
        duthost.restart_service("bgp")
        pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")

def parse_exabgp_dump(host):
    """
    Parse the dump file of exabgp, and build a set for checking routes
    """
    routes = set()
    output_lines = host.shell("cat {}".format(DUMP_FILE), verbose=False)['stdout_lines']
    for line in output_lines:
        routes.add(line)
    return routes

def parse_rib(host, ip_ver):
    """
    Parse output of 'show bgp ipv4/6' and parse into a dict for checking routes
    """
    routes = {}

    for namespace in host.get_frontend_asic_namespace_list():
        bgp_cmd = "vtysh -c \"show bgp ipv%d json\"" % ip_ver
        cmd = host.get_vtysh_cmd_for_namespace(bgp_cmd, namespace)

        route_data = json.loads(host.shell(cmd, verbose=False)['stdout'])
        for ip, nexthops in route_data['routes'].iteritems():
            aspath = set()
            for nexthop in nexthops:
                # if internal route with aspath as '' skip adding
                if nexthop.has_key('path') and nexthop['path'] =='':
                    continue
                aspath.add(nexthop['path'])
            # if aspath is valid, add it into routes
            if aspath:
                routes[ip] = aspath

    return routes

def get_routes_not_announced_to_bgpmon(duthost, ptfhost):
    """
    Get the routes that are not announced to bgpmon by checking dump of bgpmon on PTF.
    """
    def _dump_fie_exists(host):
        return host.stat(path=DUMP_FILE).get('stat', {}).get('exists', False)
    pytest_assert(wait_until(120, 10, 0, _dump_fie_exists, ptfhost))
    time.sleep(20)  # Wait until all routes announced to bgpmon
    bgpmon_routes = parse_exabgp_dump(ptfhost)
    rib_v4 = parse_rib(duthost, 4)
    rib_v6 = parse_rib(duthost, 6)
    routes_dut = dict(rib_v4.items() + rib_v6.items())
    return [route for route in routes_dut.keys() if route not in bgpmon_routes]

def remove_bgp_neighbors(duthost, asic_index):
    """
    Remove the bgp neigbors for a particular BGP instance
    """
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    namespace_prefix = '-n ' + namespace if namespace else ''

    # Convert the json formatted result of sonic-cfggen into bgp_neighbors dict
    bgp_neighbors = json.loads(duthost.command("sudo sonic-cfggen {} -d --var-json {}".format(namespace_prefix, "BGP_NEIGHBOR"))["stdout"])
    cmd = 'sudo sonic-db-cli {} CONFIG_DB keys "BGP_NEI*" | xargs sonic-db-cli {} CONFIG_DB del'.format(namespace_prefix, namespace_prefix)
    duthost.shell(cmd)

    # Restart BGP instance on that asic
    duthost.restart_service_on_asic("bgp", asic_index)
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")

    return bgp_neighbors

def restore_bgp_neighbors(duthost, asic_index, bgp_neighbors):
    """
    Restore the bgp neigbors for a particular BGP instance
    """
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    namespace_prefix = '-n ' + namespace if namespace else ''

    # Convert the bgp_neighbors dict into json format after adding the table name.
    bgp_neigh_dict = {"BGP_NEIGHBOR":bgp_neighbors}
    bgp_neigh_json = json.dumps(bgp_neigh_dict)
    duthost.shell("sudo sonic-cfggen {} -a '{}' --write-to-db".format(namespace_prefix, bgp_neigh_json))

    # Restart BGP instance on that asic
    duthost.restart_service_on_asic("bgp", asic_index)
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")
