import pytest
import logging
import json
import os
from common import reboot
from jinja2 import Template
import ipaddr as ipaddress
from ptf_runner import ptf_runner
from common.platform.ssh_utils import prepare_testbed_ssh_keys
from datetime import datetime

from common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

SOURCE_UPGRADE_SCRIPT = 'upgrade_path/upgrade_sonic.sh'
UPGRADE_SCRIPT = '/tmp/upgrade_sonic.sh'

TMP_VLAN_PORTCHANNEL_FILE = '/tmp/portchannel_interfaces.json'
TMP_VLAN_FILE = '/tmp/vlan_interfaces.json'
TMP_PORTS_FILE = '/tmp/ports.json'


@pytest.fixture(scope="module")
def duthost_original_image(duthost):
    original_image = ""
    res = duthost.shell('sonic_installer list', module_ignore_errors=True)
    for line in res['stdout'].splitlines():
        if line.startswith('Current:'):
            original_image = line.split(':')[-1].strip()
            break
    logger.info("Original image is {}".format(original_image))
    return original_image


@pytest.fixture(scope="module")
def setup(localhost, ptfhost, duthost, duthost_original_image):
    prepare_ptf(ptfhost, duthost)
    yield
    cleanup(localhost, ptfhost, duthost, duthost_original_image)


def prepare_dut(duthost):
    # copy script to dut
    duthost.copy(src=SOURCE_UPGRADE_SCRIPT,
                 dest=UPGRADE_SCRIPT,
                 mode=0755)


def cleanup(localhost, ptfhost, duthost, duthost_original_image):
    original_image = duthost_original_image
    logger.info("Preparing to cleanup and restore to {}".format(original_image))
    # restore orignial image
    logger.info("Set default image to {}".format(original_image))
    # try to restore original image
    duthost.shell("sonic_installer set_default {}".format(original_image),
                  module_ignore_errors=True)
    # Perform a cold reboot
    reboot(duthost, localhost)
    # cleanup
    duthost.shell("sonic_installer cleanup -y", module_ignore_errors=True)
    duthost.shell("config load_minigraph -y", module_ignore_errors=True)
    ptfhost.shell("rm -f {} {} {}".format(TMP_VLAN_FILE, TMP_VLAN_PORTCHANNEL_FILE, TMP_PORTS_FILE),
                  module_ignore_errors=True)
    os.remove(TMP_VLAN_FILE)
    os.remove(TMP_VLAN_PORTCHANNEL_FILE)
    os.remove(TMP_PORTS_FILE)


def prepare_ptf(ptfhost, duthost):
    logger.info("Preparing ptfhost")
    ptfhost.script("./scripts/remove_ip.sh")
    ptfhost.copy(src="../ansible/roles/test/files/helpers/arp_responder.py",
                 dest="/opt")

    # Prapare vlan conf file
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    with open(TMP_VLAN_PORTCHANNEL_FILE, "w") as file:
        file.write(json.dumps(mg_facts['minigraph_portchannels']))
    ptfhost.copy(src=TMP_VLAN_PORTCHANNEL_FILE,
                 dest=TMP_VLAN_PORTCHANNEL_FILE)

    with open(TMP_VLAN_FILE, "w") as file:
        file.write(json.dumps(mg_facts['minigraph_vlans']))
    ptfhost.copy(src=TMP_VLAN_FILE,
                 dest=TMP_VLAN_FILE)

    with open(TMP_PORTS_FILE, "w") as file:
        file.write(json.dumps(mg_facts['minigraph_port_indices']))
    ptfhost.copy(src=TMP_PORTS_FILE,
                 dest=TMP_PORTS_FILE)

    arp_responder_conf = Template(open("../ansible/roles/test/templates/arp_responder.conf.j2").read())
    ptfhost.copy(content=arp_responder_conf.render(arp_responder_args="-e"),
                 dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")


@pytest.fixture(scope="module")
def ptf_params(duthost, nbrhosts):

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
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

    hostVars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    inventory = hostVars['inventory_file'].split('/')[-1]
    secrets = duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']

    ptf_params = {
        "verbose": False,
        "dut_username": secrets[inventory]['sonicadmin_user'],
        "dut_password": secrets[inventory]['sonicadmin_password'],
        "dut_hostname": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'],
        "reboot_limit_in_seconds": 30,
        "reboot_type": "warm-reboot",
        "portchannel_ports_file": TMP_VLAN_PORTCHANNEL_FILE,
        "vlan_ports_file": TMP_VLAN_FILE,
        "ports_file": TMP_PORTS_FILE,
        "dut_mac": duthost.setup()['ansible_facts']['ansible_Ethernet0']['macaddress'],
        "dut_vlan_ip": "192.168.0.1",
        "default_ip_range": "192.168.100.0/18",
        "vlan_ip_range": mg_facts['minigraph_vlan_interfaces'][0]['subnet'],
        "lo_v6_prefix": lo_v6_prefix,
        "arista_vms": vm_hosts,
        "setup_fdb_before_test": True,
        "target_version": "Unknown"
    }
    return ptf_params


def check_sonic_version(duthost, target_version):
    res = duthost.shell(r"sudo sonic_installer list | grep Current | awk '{print $2}'")
    assert res['stdout'] == target_version, \
        "Upgrade sonic failed: target={} current={}".format(target_version, res['stdout'])


def install_sonic(duthost, image_url):
    prepare_dut(duthost)
    res = duthost.shell("bash {} {}".format(UPGRADE_SCRIPT, image_url))
    target_version = "Unknown"
    for line in res['stdout'].split('\n'):
        if line.startswith(u"installed_version"):
            target_version = line.split()[-1]
            break
    return target_version

def test_upgrade_path(localhost, duthost, ptfhost, upgrade_path_lists, ptf_params, setup):
    from_list_images, to_list_images = upgrade_path_lists
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    test_params = ptf_params
    logger.info(json.dumps(test_params))
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
            test_params['target_version'] = target_version
            prepare_testbed_ssh_keys(duthost, ptfhost, test_params['dut_username'])
            log_file = "/tmp/advanced-reboot.ReloadTest.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

            ptf_runner(ptfhost,
                       "ptftests",
                       "advanced-reboot.ReloadTest",
                       platform_dir="ptftests",
                       params=test_params,
                       platform="remote",
                       qlen=1000,
                       log_file=log_file)

