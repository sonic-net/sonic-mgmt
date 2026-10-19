import logging
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
    # Base-image downgrade intentionally rebuilds configuration. SmartSwitch
    # configuration cannot be reconstructed from minigraph.
    basic_facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    config_source = "config_db" if basic_facts.get("is_smartswitch", False) else "minigraph"
    return install_sonic(duthost, base_image, tbinfo, config_source=config_source)


def cleanup_prev_images(duthost):
    logger.info("Cleaning up previously installed images on DUT")
    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
    duthost.shell("sonic_installer set_next_boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer set-next-boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer cleanup -y", module_ignore_errors=True)
