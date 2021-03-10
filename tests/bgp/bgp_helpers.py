import os
import re
import time
import json

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
BGP_PLAIN_TEMPLATE = 'bgp_plain.j2'
BGP_NO_EXPORT_TEMPLATE = 'bgp_no_export.j2'
BGP_CONFIG_BACKUP = 'backup_bgpd.conf.j2'
DEFAULT_BGP_CONFIG = 'bgp:/usr/share/sonic/templates/bgpd/bgpd.conf.j2'
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
    duthost.shell('docker cp {} {}'.format(template_name, DEFAULT_BGP_CONFIG))
    restart_bgp(duthost)


def restart_bgp(duthost):
    """
    Restart bgp services on the DUT

    Args:
        duthost: DUT host object
    """
    duthost.shell('systemctl restart bgp')
    time.sleep(60)


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
        duthost.shell('docker cp {} {}'.format(DEFAULT_BGP_CONFIG, bgp_config_backup))
    else:
        duthost.shell('docker cp {} {}'.format(bgp_config_backup, DEFAULT_BGP_CONFIG))
        # Skip 'start-limit-hit' threshold
        duthost.shell('systemctl reset-failed bgp')
        restart_bgp(duthost)

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
    cmd = "vtysh -c \"show bgp ipv%d json\"" % ip_ver
    route_data = json.loads(host.shell(cmd, verbose=False)['stdout'])
    for ip, nexthops in route_data['routes'].iteritems():
        aspath = set()
        for nexthop in nexthops:
            aspath.add(nexthop['path'])
        routes[ip] = aspath
    return routes

def verify_all_routes_announce_to_bgpmon(duthost, ptfhost):
    time.sleep(BGP_ANNOUNCE_TIME)
    bgpmon_routes = parse_exabgp_dump(ptfhost)
    rib_v4 = parse_rib(duthost, 4)
    rib_v6 = parse_rib(duthost, 6)
    routes_dut = dict(rib_v4.items() + rib_v6.items())
    for route in routes_dut.keys():
        if route not in bgpmon_routes:
            return False
    return True
