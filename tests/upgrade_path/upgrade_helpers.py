import pytest
import logging
import time
import ipaddress
import json
import re
from six.moves.urllib.parse import urlparse
from tests.common.helpers.assertions import pytest_assert
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_WARM

logger = logging.getLogger(__name__)

TMP_VLAN_PORTCHANNEL_FILE = '/tmp/portchannel_interfaces.json'
TMP_VLAN_FILE = '/tmp/vlan_interfaces.json'
TMP_PORTS_FILE = '/tmp/ports.json'
TMP_PEER_INFO_FILE = "/tmp/peer_dev_info.json"
TMP_PEER_PORT_INFO_FILE = "/tmp/neigh_port_info.json"


def pytest_runtest_setup(item):
    from_list = item.config.getoption('base_image_list')
    to_list = item.config.getoption('target_image_list')
    if not from_list or not to_list:
        pytest.skip("base_image_list or target_image_list is empty")


@pytest.fixture(scope="module")
def restore_image(localhost, duthosts, rand_one_dut_hostname, upgrade_path_lists, tbinfo):
    _, _, _, restore_to_image = upgrade_path_lists
    yield
    duthost = duthosts[rand_one_dut_hostname]
    if restore_to_image:
        logger.info("Preparing to cleanup and restore to {}".format(restore_to_image))
        # restore orignial image
        install_sonic(duthost, restore_to_image, tbinfo)
        # Perform a cold reboot
        reboot(duthost, localhost)


def get_reboot_command(duthost, upgrade_type):
    reboot_command = reboot_ctrl_dict.get(upgrade_type).get("command")
    if upgrade_type == REBOOT_TYPE_WARM:
        next_os_version = duthost.shell('sonic_installer list | grep Next | cut -f2 -d " "')['stdout']
        current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
        # warm-reboot has to be forced for an upgrade from 201811 to 201811+ to bypass ASIC config changed error
        if 'SONiC-OS-201811' in current_os_version and 'SONiC-OS-201811' not in next_os_version:
            reboot_command = "warm-reboot -f"
    return reboot_command


def check_sonic_version(duthost, target_version):
    current_version = duthost.image_facts()['ansible_facts']['ansible_image_facts']['current']
    assert current_version == target_version, \
        "Upgrade sonic failed: target={} current={}".format(target_version, current_version)


def install_sonic(duthost, image_url, tbinfo):
    new_route_added = False
    if urlparse(image_url).scheme in ('http', 'https',):
        mg_gwaddr = duthost.get_extended_minigraph_facts(tbinfo).get("minigraph_mgmt_interface", {}).get("gwaddr")
        mg_gwaddr = ipaddress.IPv4Address(mg_gwaddr)
        rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network('0.0.0.0/0'))
        for nexthop in rtinfo_v4['nexthops']:
            if mg_gwaddr == nexthop[0]:
                break
        else:
            # Temporarily change the default route to mgmt-gateway address. This is done so that
            # DUT can download an image from a remote host over the mgmt network.
            logger.info("Add default mgmt-gateway-route to the device via {}".format(mg_gwaddr))
            duthost.shell("ip route replace default via {}".format(mg_gwaddr), module_ignore_errors=True)
            new_route_added = True
        res = duthost.reduce_and_add_sonic_images(new_image_url=image_url)
    else:
        out = duthost.command("df -BM --output=avail /host", module_ignore_errors=True)["stdout"]
        avail = int(out.split('\n')[1][:-1])
        if avail >= 2000:
            # There is enough space to install directly
            save_as = "/host/downloaded-sonic-image"
        else:
            save_as = "/tmp/tmpfs/downloaded-sonic-image"
            # Create a tmpfs partition to download image to install
            duthost.shell("mkdir -p /tmp/tmpfs", module_ignore_errors=True)
            duthost.shell("umount /tmp/tmpfs", module_ignore_errors=True)
            duthost.shell("mount -t tmpfs -o size=1300M tmpfs /tmp/tmpfs", module_ignore_errors=True)
        logger.info("Image exists locally. Copying the image {} into the device path {}".format(image_url, save_as))
        duthost.copy(src=image_url, dest=save_as)
        res = duthost.reduce_and_add_sonic_images(save_as=save_as)

    # if the new default mgmt-gateway route was added, remove it. This is done so that
    # default route src address matches Loopback0 address
    if new_route_added:
        logger.info("Remove default mgmt-gateway-route earlier added")
        duthost.shell("ip route del default via {}".format(mg_gwaddr), module_ignore_errors=True)
    return res['ansible_facts']['downloaded_image_version']


def check_services(duthost):
    """
    Perform a health check of services
    """
    logging.info("Wait until DUT uptime reaches {}s".format(300))
    while duthost.get_uptime().total_seconds() < 300:
        time.sleep(1)
    logging.info("Wait until all critical services are fully started")
    logging.info("Check critical service status")
    pytest_assert(duthost.critical_services_fully_started(), "dut.critical_services_fully_started is False")

    for service in duthost.critical_services:
        status = duthost.get_service_props(service)
        pytest_assert(status["ActiveState"] == "active", "ActiveState of {} is {}, expected: active"
                      .format(service, status["ActiveState"]))
        pytest_assert(status["SubState"] == "running", "SubState of {} is {}, expected: running"
                      .format(service, status["SubState"]))


def check_reboot_cause(duthost, expected_cause):
    reboot_cause = get_reboot_cause(duthost)
    logging.info("Checking cause from dut {} to expected {}".format(reboot_cause, expected_cause))
    return reboot_cause == expected_cause

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
        cmd='''ip route show type unicast |
        sed -e '/proto 186\|proto zebra\|proto bgp/!d' -e '/default/d' -ne '/0\//p' |
        head -n 1 |
        sed -ne 's/0\/.*$/1/p'
        '''
    )

    pytest_assert(len(result['stdout'].strip()) > 0, 'Empty DIP returned')

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

def check_copp_config(duthost):
    logging.info("Comparing CoPP configuration from copp_cfg.json to COPP_TABLE")
    copp_tables = json.loads(duthost.shell("sonic-db-dump -n APPL_DB -k COPP_TABLE* -y")["stdout"])
    copp_cfg = json.loads(duthost.shell("cat /etc/sonic/copp_cfg.json")["stdout"])
    feature_status = duthost.shell("show feature status")["stdout"]
    copp_tables_formatted = get_copp_table_formatted_dict(copp_tables)
    copp_cfg_formatted = get_copp_cfg_formatted_dict(copp_cfg, feature_status)
    pytest_assert(copp_tables_formatted == copp_cfg_formatted,
                  "There is a difference between CoPP config and CoPP tables. CoPP config: {}\nCoPP tables:"
                  " {}".format(copp_tables_formatted, copp_cfg_formatted))


def get_copp_table_formatted_dict(copp_tables):
    """
    Format the copp tables output to "copp_group":{"values"} only
    """
    formatted_dict = {}
    for queue_group, queue_group_value in copp_tables.items():
        new_queue_group = queue_group.replace("COPP_TABLE:", "")
        formatted_dict.update({new_queue_group: queue_group_value["value"]})
    logging.debug("Formatted copp tables dictionary: {}".format(formatted_dict))
    return formatted_dict


def get_copp_cfg_formatted_dict(copp_cfg, feature_status):
    """
    Format the copp_cfg.json output to compare with copp tables
    """
    formatted_dict = {}
    for trap_name, trap_value in copp_cfg["COPP_TRAP"].items():
        pattern = r"{}\s+enabled".format(trap_name)
        trap_enabled = re.search(pattern, feature_status)
        if trap_value.get("always_enabled", "") or trap_enabled:
            trap_group = trap_value["trap_group"]
            if trap_group in formatted_dict:
                exist_trap_ids = formatted_dict[trap_group]["trap_ids"].split(",")
                additional_trap_ids = trap_value["trap_ids"].split(",")
                trap_ids = exist_trap_ids + additional_trap_ids
                trap_ids.sort()
                formatted_dict[trap_group].update({"trap_ids": ",".join(trap_ids)})
            else:
                formatted_dict.update({trap_group: copp_cfg["COPP_GROUP"][trap_group]})
                formatted_dict[trap_group].update({"trap_ids": trap_value["trap_ids"]})
    formatted_dict.update({"default": copp_cfg["COPP_GROUP"]["default"]})
    logging.debug("Formatted copp_cfg.json dictionary: {}".format(formatted_dict))
    return formatted_dict
