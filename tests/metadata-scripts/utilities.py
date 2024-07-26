import logging
import os
import re
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common.reboot import REBOOT_TYPE_COLD, REBOOT_TYPE_SOFT
from tests.upgrade_path.upgrade_helpers import install_sonic, check_sonic_version, reboot

logger = logging.getLogger(__name__)

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
