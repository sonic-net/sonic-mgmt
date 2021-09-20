import pytest
import logging
import json
import os
import time
from urlparse import urlparse
from jinja2 import Template
import ipaddr
import ipaddress
from tests.common.helpers.assertions import pytest_assert
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_WARM

logger = logging.getLogger(__name__)

TMP_VLAN_PORTCHANNEL_FILE = '/tmp/portchannel_interfaces.json'
TMP_VLAN_FILE = '/tmp/vlan_interfaces.json'
TMP_PORTS_FILE = '/tmp/ports.json'


def pytest_runtest_setup(item):
    from_list = item.config.getoption('base_image_list')
    to_list = item.config.getoption('target_image_list')
    if not from_list or not to_list:
        pytest.skip("base_image_list or target_image_list is empty")


def cleanup(localhost, ptfhost, duthost, upgrade_path_lists, tbinfo):
    _, _, _, restore_to_image = upgrade_path_lists
    if restore_to_image:
        logger.info("Preparing to cleanup and restore to {}".format(restore_to_image))
        # restore orignial image
        install_sonic(duthost, restore_to_image, tbinfo)
        # Perform a cold reboot
        reboot(duthost, localhost)
    # cleanup
    ptfhost.shell("rm -f {} {} {}".format(TMP_VLAN_FILE, TMP_VLAN_PORTCHANNEL_FILE, TMP_PORTS_FILE),
                  module_ignore_errors=True)
    os.remove(TMP_VLAN_FILE)
    os.remove(TMP_VLAN_PORTCHANNEL_FILE)
    os.remove(TMP_PORTS_FILE)


def prepare_ptf(ptfhost, duthost, tbinfo):
    logger.info("Preparing ptfhost")

    # Prapare vlan conf file
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    with open(TMP_VLAN_PORTCHANNEL_FILE, "w") as file:
        file.write(json.dumps(mg_facts['minigraph_portchannels']))
    ptfhost.copy(src=TMP_VLAN_PORTCHANNEL_FILE,
                 dest=TMP_VLAN_PORTCHANNEL_FILE)

    with open(TMP_VLAN_FILE, "w") as file:
        file.write(json.dumps(mg_facts['minigraph_vlans']))
    ptfhost.copy(src=TMP_VLAN_FILE,
                 dest=TMP_VLAN_FILE)

    with open(TMP_PORTS_FILE, "w") as file:
        file.write(json.dumps(mg_facts['minigraph_ptf_indices']))
    ptfhost.copy(src=TMP_PORTS_FILE,
                 dest=TMP_PORTS_FILE)

    arp_responder_conf = Template(open("../ansible/roles/test/templates/arp_responder.conf.j2").read())
    ptfhost.copy(content=arp_responder_conf.render(arp_responder_args="-e"),
                 dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")


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
        rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network(u'0.0.0.0/0'))
        for nexthop in rtinfo_v4['nexthops']:
            if mg_gwaddr == nexthop[0]:
                break
        else:
            # Temporarily change the default route to mgmt-gateway address. This is done so that
            # DUT can download an image from a remote host over the mgmt network.
            logger.info("Add default mgmt-gateway-route to the device via {}".format(mg_gwaddr))
            duthost.shell("ip route add default via {}".format(mg_gwaddr), module_ignore_errors=True)
            new_route_added = True
        res = duthost.reduce_and_add_sonic_images(new_image_url=image_url)
    else:
        out = duthost.command("df -BM --output=avail /host",
                        module_ignore_errors=True)["stdout"]
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
        pytest_assert(status["ActiveState"] == "active", "ActiveState of {} is {}, expected: active".format(service, status["ActiveState"]))
        pytest_assert(status["SubState"] == "running", "SubState of {} is {}, expected: running".format(service, status["SubState"]))


def check_reboot_cause(duthost, expected_cause):
    reboot_cause = get_reboot_cause(duthost)
    logging.info("Checking cause from dut {} to expected {}".format(reboot_cause, expected_cause))
    return reboot_cause == expected_cause


@pytest.fixture(scope="module")
def setup(localhost, ptfhost, duthosts, rand_one_dut_hostname, upgrade_path_lists, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    prepare_ptf(ptfhost, duthost, tbinfo)
    yield
    cleanup(localhost, ptfhost, duthost, upgrade_path_lists, tbinfo)


@pytest.fixture(scope="module")
def ptf_params(duthosts, rand_one_dut_hostname, creds, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        reboot_limit_in_seconds = 150
    else:
        reboot_limit_in_seconds = 30

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    lo_v6_prefix = ""
    for intf in mg_facts["minigraph_lo_interfaces"]:
        ipn = ipaddr.IPNetwork(intf['addr'])
        if ipn.version == 6:
            lo_v6_prefix = str(ipaddr.IPNetwork(intf['addr'] + '/64').network) + '/64'
            break

    mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_hosts = [
            attr['mgmt_addr'] for dev, attr in mgFacts['minigraph_devices'].items() if attr['hwsku'] == 'Arista-VM'
        ]

    vlan_ip_range = dict()
    for vlan in mgFacts['minigraph_vlan_interfaces']:
        if type(ipaddress.ip_network(vlan['subnet'])) is ipaddress.IPv4Network:
            vlan_ip_range[vlan['attachto']] = vlan['subnet']

    sonicadmin_alt_password = duthost.host.options['variable_manager']._hostvars[duthost.hostname].get("ansible_altpassword")
    ptf_params = {
        "verbose": False,
        "dut_username": creds.get('sonicadmin_user'),
        "dut_password": creds.get('sonicadmin_password'),
        "alt_password": sonicadmin_alt_password,
        "dut_hostname": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'],
        "reboot_limit_in_seconds": reboot_limit_in_seconds,
        "reboot_type": "warm-reboot",
        "portchannel_ports_file": TMP_VLAN_PORTCHANNEL_FILE,
        "vlan_ports_file": TMP_VLAN_FILE,
        "ports_file": TMP_PORTS_FILE,
        "dut_mac": duthost.facts["router_mac"],
        "dut_vlan_ip": "192.168.0.1",
        "default_ip_range": "192.168.100.0/18",
        "vlan_ip_range": json.dumps(vlan_ip_range),
        "lo_v6_prefix": lo_v6_prefix,
        "arista_vms": vm_hosts,
        "setup_fdb_before_test": True,
        "target_version": "Unknown"
    }
    return ptf_params
