import logging
import re
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.helpers.upgrade_helpers import install_sonic, reboot, check_sonic_version

logger = logging.getLogger(__name__)


def boot_into_base_image(duthost, localhost, base_image, tbinfo):
    target_version = _install_base_image(duthost, base_image, tbinfo)
    # Perform a cold reboot
    logger.info("Cold reboot the DUT to make the base image as current")
    # for 6100 devices, sometimes cold downgrade will not work, use soft-reboot here
    reboot_type = 'soft' if "s6100" in duthost.facts["platform"] else 'cold'
    reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
    check_sonic_version(duthost, target_version)


def boot_into_base_image_t2(duthosts, localhost, base_image, tbinfo):
    target_vers = {}
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in duthosts:
            future = executor.submit(_install_base_image, duthost, base_image, tbinfo)
            target_vers[duthost] = future.get()  # Should all be the same, but following best practice

    # Rebooting the supervisor host will reboot all T2 DUTs
    suphost = duthosts.supervisor_nodes[0]
    reboot(suphost, localhost, reboot_type='cold', safe_reboot=True)

    for duthost in duthosts:
        check_sonic_version(duthost, target_vers[duthost])


def _install_base_image(duthost, base_image, tbinfo):
    logger.info("Installing {}".format(base_image))
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
        duthost.shell("rm -f /host/old_config/golden_config_db.json")

    return target_version


def cleanup_prev_images(duthost):
    logger.info("Cleaning up previously installed images on DUT")
    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
    duthost.shell("sonic_installer set_next_boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer set-next-boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer cleanup -y", module_ignore_errors=True)
