import logging
import os
import re
from ipaddress import ip_network, IPv4Network, IPv6Network
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common.reboot import REBOOT_TYPE_COLD, REBOOT_TYPE_SOFT
from tests.common.helpers.upgrade_helpers import install_sonic, check_sonic_version, reboot

logger = logging.getLogger(__name__)


def fix_forced_mgmt_routes_config(duthost):
    """
    Fixes the 201811 forced management routes configuration in the Redis DB where IPv4 CIDRs are mixed with IPv6 CIDRs
    by partitioning them into the expected lists.
    No config save or load is required as future upgrades before the issue manifests occur and do the config
    sync in the process.
    """

    logger.info("Checking forced management routes configuration...")

    # Fetch the interface IP keys e.g. 'MGMT_INTERFACE|eth0|2603:10e2:140:3000::43/122'
    mgmt_if_ip_keys = duthost.command("redis-cli -n 4 KEYS MGMT_INTERFACE\\|eth0\\*")["stdout_lines"]

    assert len(mgmt_if_ip_keys) == 2, \
        "Expected 2 keys for the management interface - One for IPv4 and one for IPv6 but got: {}" \
        .format(mgmt_if_ip_keys)

    # Work out which is the IPv4 and which is the IPv6
    key0_cidr = ip_network(mgmt_if_ip_keys[0].split("|")[-1], strict=False)
    if isinstance(key0_cidr, IPv4Network):
        ipv4_key = mgmt_if_ip_keys[0]
        ipv6_key = mgmt_if_ip_keys[1]
    elif isinstance(key0_cidr, IPv6Network):
        ipv4_key = mgmt_if_ip_keys[1]
        ipv6_key = mgmt_if_ip_keys[0]
    else:
        assert False, "Unexpected IP network type: {}".format(key0_cidr)

    # Get the current forced management routes
    get_forced_mgmt_routes_cmd_tmpl = "redis-cli -n 4 HGET '{}' 'forced_mgmt_routes@'"
    orig_ipv4_forced_mgmt_routes = duthost.command(get_forced_mgmt_routes_cmd_tmpl.format(ipv4_key))["stdout"]
    orig_ipv4_forced_mgmt_routes = orig_ipv4_forced_mgmt_routes.split(",") if orig_ipv4_forced_mgmt_routes else []
    orig_ipv6_forced_mgmt_routes = duthost.command(get_forced_mgmt_routes_cmd_tmpl.format(ipv6_key))["stdout"]
    orig_ipv6_forced_mgmt_routes = orig_ipv6_forced_mgmt_routes.split(",") if orig_ipv6_forced_mgmt_routes else []

    # Partition based on IP
    corrected_ipv4_forced_mgmt_routes = []
    corrected_ipv6_forced_mgmt_routes = []
    for cidr_str in orig_ipv4_forced_mgmt_routes + orig_ipv6_forced_mgmt_routes:
        cidr = ip_network(cidr_str, strict=False)
        if isinstance(cidr, IPv4Network):
            corrected_ipv4_forced_mgmt_routes.append(cidr_str)
        elif isinstance(cidr, IPv6Network):
            corrected_ipv6_forced_mgmt_routes.append(cidr_str)
        else:
            raise TypeError("Unexpected IP network type: {}".format(cidr))

    # Write them back out
    set_forced_mgmt_routes_cmd_tmpl = "redis-cli -n 4 HSET '{}' 'forced_mgmt_routes@' '{}'"
    if corrected_ipv4_forced_mgmt_routes != orig_ipv4_forced_mgmt_routes:
        # IPv4 forced management routes have changed - write them back out
        duthost.command(set_forced_mgmt_routes_cmd_tmpl.format(ipv4_key, ",".join(corrected_ipv4_forced_mgmt_routes)))
        logger.info("Fixed IPv4 forced management routes from {} to {}".format(orig_ipv4_forced_mgmt_routes,
                                                                               corrected_ipv4_forced_mgmt_routes))
    if corrected_ipv6_forced_mgmt_routes != orig_ipv6_forced_mgmt_routes:
        # IPv6 forced management routes have changed - write them back out
        duthost.command(set_forced_mgmt_routes_cmd_tmpl.format(ipv6_key, ",".join(corrected_ipv6_forced_mgmt_routes)))
        logger.info("Fixed IPv6 forced management routes from {} to {}".format(orig_ipv6_forced_mgmt_routes,
                                                                               corrected_ipv6_forced_mgmt_routes))

    logger.info("Forced management routes configuration fixed.")


def set_base_image_a(duthost, localhost, base_image, tbinfo):
    """
    Installs and boots the DUT into the base_image.
    """
    logger.info("Installing base image {}".format(base_image))
    try:
        target_version = install_sonic(duthost, base_image, tbinfo)
    except RunAnsibleModuleFail as err:
        migration_err_regexp = r"Traceback.*migrate_sonic_packages.*SonicRuntimeException"
        msg = err.results['msg'].replace('\n', '')
        if re.search(migration_err_regexp, msg):
            logger.info(
                "Ignore the package migration error when downgrading to base_image")
            target_version = duthost.shell(
                "cat /tmp/downloaded-sonic-image-version")['stdout']
        else:
            raise err
    # Remove old config_db before rebooting the DUT in case it is not successfully
    # removed in install_sonic due to migration error
    logger.info("Remove old config_db file if exists, to load minigraph from scratch")
    if duthost.shell("ls /host/old_config/minigraph.xml", module_ignore_errors=True)['rc'] == 0:
        duthost.shell("rm -f /host/old_config/config_db.json")
    # Perform a cold reboot
    logger.info("Cold reboot the DUT to make the base image as current")
    # for 6100 devices, sometimes cold downgrade will not work, use soft-reboot here
    reboot_type = 'hard' if "s6100" in duthost.facts["platform"] else 'cold'
    reboot(duthost, localhost, reboot_type=reboot_type)
    check_sonic_version(duthost, target_version)
    if "201811" in target_version:
        fix_forced_mgmt_routes_config(duthost)


def cleanup_prev_images(duthost):
    logger.info("Cleaning up previously installed images on DUT")
    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
    duthost.shell("sonic_installer set_next_boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer set-next-boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer cleanup -y", module_ignore_errors=True)


def sonic_update_firmware(duthost, localhost, image_url, upgrade_type):
    base_path = os.path.dirname(__file__)
    metadata_scripts_path = os.path.join(base_path, "../../../sonic-metadata/scripts")
    pytest_assert(os.path.exists(metadata_scripts_path), "SONiC Metadata scripts not found in {}"
            .format(metadata_scripts_path))

    cleanup_prev_images(duthost)
    logger.info("Step 1 Copy the scripts to the DUT")
    duthost.file(path="/tmp/anpscripts", state="absent")
    duthost.file(path="/tmp/anpscripts", state="directory")
    localhost.archive(path=metadata_scripts_path + "/", dest="metadata.tar.gz", exclusion_patterns=[".git"])
    duthost.copy(src="metadata.tar.gz", dest="/host/metadata.tar.gz")
    duthost.unarchive(src="/host/metadata.tar.gz", dest="/tmp/anpscripts/", remote_src="yes")

    logger.info("perform a purge based on manifest.json to make sure it is correct")
    duthost.command("python /tmp/anpscripts/tests/purge.py")

    logger.info("Step 2 Copy the image to /tmp/")
    image_name = image_url.split("/")[-1]
    image_path = "/tmp/" + image_name
    duthost.command("curl -o {} {}".format(image_path, image_url))
    out = duthost.command("md5sum {}".format(image_path))
    md5sum = out['stdout'].split()

    duthost.command("chmod +x /tmp/anpscripts/preload_firmware")
    logger.info("execute preload_firmware {} {} {}".format(image_name, image_url, md5sum[0]))
    duthost.command("/usr/bin/sudo /tmp/anpscripts/preload_firmware {} {} {}".format(image_name, image_url, md5sum[0]))

    out = duthost.command("sonic_installer binary_version {}".format(image_path))

    logger.info("Step 3 Install image")
    if (upgrade_type == REBOOT_TYPE_COLD or upgrade_type == REBOOT_TYPE_SOFT):
        UPDATE_MLNX_CPLD_FW = 1
    else:
        UPDATE_MLNX_CPLD_FW = 0

    duthost.command("chmod +x /tmp/anpscripts/update_firmware")
    duthost.command("/usr/bin/sudo /tmp/anpscripts/update_firmware {} UPDATE_MLNX_CPLD_FW={}".format(
        image_name, UPDATE_MLNX_CPLD_FW))
    patch_rsyslog(duthost)

    return out['stdout'].rstrip('\n')
