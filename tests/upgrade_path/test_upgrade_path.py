import pytest
import logging
import json
import os
from tests.common import reboot
from jinja2 import Template
import ipaddr as ipaddress
from tests.ptf_runner import ptf_runner
from tests.common.platform.ssh_utils import prepare_testbed_ssh_keys
from datetime import datetime

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
    cleanup(localhost, ptfhost, duthost, upgrade_path_lists)


def cleanup(localhost, ptfhost, duthost, upgrade_path_lists):
    _, _, restore_to_image = upgrade_path_lists
    if restore_to_image:
        logger.info("Preparing to cleanup and restore to {}".format(restore_to_image))
        # restore orignial image
        install_sonic(duthost, restore_to_image)
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
def ptf_params(duthosts, rand_one_dut_hostname, nbrhosts, creds, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    lo_v6_prefix = ""
    for intf in mg_facts["minigraph_lo_interfaces"]:
        ipn = ipaddress.IPNetwork(intf['addr'])
        if ipn.version == 6:
            lo_v6_prefix = str(ipaddress.IPNetwork(intf['addr'] + '/64').network) + '/64'
            break

    vm_hosts = []
    nbrs = nbrhosts
    for key, value in nbrs.items():
        #TODO:Update to vm_hosts.append(value['host'].host.mgmt_ip)
        vm_hosts.append(value['host'].host.options['inventory_manager'].get_host(value['host'].hostname).vars['ansible_host'])

    ptf_params = {
        "verbose": False,
        "dut_username": creds.get('sonicadmin_user'),
        "dut_password": creds.get('sonicadmin_password'),
        "dut_hostname": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'],
        "reboot_limit_in_seconds": 30,
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

def get_reboot_type(duthost):
    next_os_version = duthost.shell('sonic_installer list | grep Next | cut -f2 -d " "')['stdout']
    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']

    # warm-reboot has to be forced for an upgrade from 201811 to 201911 to bypass ASIC config changed error
    if 'SONiC-OS-201811' in current_os_version and 'SONiC-OS-201911' in next_os_version:
        reboot_type = "warm-reboot -f"
    else:
        reboot_type = "warm-reboot"
    return reboot_type

def check_sonic_version(duthost, target_version):
    current_version = duthost.image_facts()['ansible_facts']['ansible_image_facts']['current']
    assert current_version == target_version, \
        "Upgrade sonic failed: target={} current={}".format(target_version, current_version)


def install_sonic(duthost, image_url):
    res = duthost.reduce_and_add_sonic_images(new_image_url=image_url)
    return res['ansible_facts']['downloaded_image_version']

def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost, upgrade_path_lists, ptf_params, setup):
    duthost = duthosts[rand_one_dut_hostname]
    from_list_images, to_list_images, _ = upgrade_path_lists
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    for from_image in from_list:
        for to_image in to_list:
            logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
            # Install base image
            logger.info("Installing {}".format(from_image))
            target_version = install_sonic(duthost, from_image)
            # Perform a cold reboot
            reboot(duthost, localhost)
            check_sonic_version(duthost, target_version)

            # Install target image
            logger.info("Upgrading to {}".format(to_image))
            target_version = install_sonic(duthost, to_image)
            test_params = ptf_params
            test_params['target_version'] = target_version
            test_params['reboot_type'] = get_reboot_type(duthost)
            prepare_testbed_ssh_keys(duthost, ptfhost, test_params['dut_username'])
            log_file = "/tmp/advanced-reboot.ReloadTest.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

            ptf_runner(ptfhost,
                       "ptftests",
                       "advanced-reboot.ReloadTest",
                       platform_dir="ptftests",
                       params=test_params,
                       platform="remote",
                       qlen=10000,
                       log_file=log_file)

