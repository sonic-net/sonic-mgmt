import pytest
import logging
import json
import os
import time
from urlparse import urlparse
from datetime import datetime
from jinja2 import Template
import ipaddr
import ipaddress
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.ssh_utils import prepare_testbed_ssh_keys
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_WARM, REBOOT_TYPE_COLD


from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)


TMP_VLAN_PORTCHANNEL_FILE = '/tmp/portchannel_interfaces.json'
TMP_VLAN_FILE = '/tmp/vlan_interfaces.json'
TMP_PORTS_FILE = '/tmp/ports.json'


@pytest.fixture(scope="module")
def setup(localhost, ptfhost, duthosts, rand_one_dut_hostname, upgrade_path_lists, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    prepare_ptf(ptfhost, duthost, tbinfo)
    yield
    cleanup(localhost, ptfhost, duthost, upgrade_path_lists, tbinfo)


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
        "vlan_ip_range": mg_facts['minigraph_vlan_interfaces'][0]['subnet'],
        "lo_v6_prefix": lo_v6_prefix,
        "arista_vms": vm_hosts,
        "setup_fdb_before_test": True,
        "target_version": "Unknown"
    }
    return ptf_params


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
        

@pytest.mark.device_type('vs')
def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost, upgrade_path_lists, ptf_params, setup, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_list_images, to_list_images, _ = upgrade_path_lists
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    for from_image in from_list:
        for to_image in to_list:
            logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
            # Install base image
            logger.info("Installing {}".format(from_image))
            target_version = install_sonic(duthost, from_image, tbinfo)
            # Perform a cold reboot
            logger.info("Cold reboot the DUT to make the base image as current")
            reboot(duthost, localhost)
            check_sonic_version(duthost, target_version)

            # Install target image
            logger.info("Upgrading to {}".format(to_image))
            target_version = install_sonic(duthost, to_image, tbinfo)
            test_params = ptf_params
            test_params['target_version'] = target_version
            test_params['reboot_type'] = get_reboot_command(duthost, upgrade_type)
            prepare_testbed_ssh_keys(duthost, ptfhost, test_params['dut_username'])
            log_file = "/tmp/advanced-reboot.ReloadTest.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
            if test_params['reboot_type'] == reboot_ctrl_dict.get(REBOOT_TYPE_COLD).get("command"):
                # advance-reboot test (on ptf) does not support cold reboot yet
                reboot(duthost, localhost)
            else:
                ptf_runner(ptfhost,
                        "ptftests",
                        "advanced-reboot.ReloadTest",
                        platform_dir="ptftests",
                        params=test_params,
                        platform="remote",
                        qlen=10000,
                        log_file=log_file)
            reboot_cause = get_reboot_cause(duthost)
            logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
            pytest_assert(reboot_cause == upgrade_type, "Reboot cause {} did not match the trigger - {}".format(reboot_cause, upgrade_type))
            check_services(duthost)

