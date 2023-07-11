import pytest
import logging
import time
import ipaddress
from six.moves.urllib.parse import urlparse
from tests.common.helpers.assertions import pytest_assert
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict, reboot_into_onie, wait_for_startup
from tests.common.reboot import REBOOT_TYPE_WARM

logger = logging.getLogger(__name__)

TMP_VLAN_PORTCHANNEL_FILE = '/tmp/portchannel_interfaces.json'
TMP_VLAN_FILE = '/tmp/vlan_interfaces.json'
TMP_PORTS_FILE = '/tmp/ports.json'
TMP_PEER_INFO_FILE = "/tmp/peer_dev_info.json"
TMP_PEER_PORT_INFO_FILE = "/tmp/neigh_port_info.json"
DUT_MINIGRAPH_PATH = "/etc/sonic/minigraph.xml"


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


def copy_sonic_image_into_onie(image_path, localhost, dut_ip):
    """
    Copy SONiC image into ONIE
    """

    dst_path = "/tmp/sonic.bin"
    if image_path.startswith("http"):
        localhost.shell(
            "sshpass -v ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{} 'wget -O {} {}'".format(
                dut_ip, dst_path, image_path))
    else:
        localhost.shell(
            "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {} root@{}:{}".format(image_path,
                                                                                                   dut_ip, dst_path))
    return dst_path


def install_base_sonic_image(duthost, localhost, image_path, tbinfo, local_mg_path, downgrade_type):
    """
    Install base SONiC image
    """
    if downgrade_type == "sonic":
        target_version = install_sonic(duthost, image_path, tbinfo)
        # Perform a cold reboot
        logger.info("Cold reboot the DUT to make the base image as current")
        reboot(duthost, localhost)
        check_sonic_version(duthost, target_version)
    else:
        reboot_into_onie(duthost, localhost)

        # Copy image into ONIE
        dut_host_ip = duthost.sonichost.mgmt_ip
        onie_image_path = copy_sonic_image_into_onie(image_path, localhost, dut_host_ip)

        # Install image via ONIE
        localhost.shell(
            "sshpass -v ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{} "
            "'onie-nos-install {}'".format(dut_host_ip, onie_image_path))
        wait_for_startup(duthost, localhost, 10, 300)

        check_services(duthost)

        # Load minigraph on DUT
        duthost.copy(src=local_mg_path, dest=DUT_MINIGRAPH_PATH)
        duthost.shell("config load_minigraph -y")
        duthost.shell("config save -y")


def store_minigraph_from_dut(duthost):
    """
    Store minigraph from DUT into local /tmp/ folder
    """
    contents = duthost.fetch(src=DUT_MINIGRAPH_PATH, dest='/tmp/')
    local_minigraph_file_path = contents['dest']
    return local_minigraph_file_path
