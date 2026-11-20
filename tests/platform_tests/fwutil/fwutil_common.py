import time
import pytest
import os
import re
import json
import logging
import allure

from copy import deepcopy

from tests.common.utilities import wait_until
from tests.common.reboot import SONIC_SSH_REGEX
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.firmware_helper import (
    get_bmc_firmware_list, get_bmc_ip, get_bmc_version_from_firmware_data,
    load_bmc_creds, resolve_bmc_flavor, show_firmware
)
from tests.common.platform.bmc_utils import get_host_boot_id, wait_host_rebooted

logger = logging.getLogger(__name__)

TEMP_STATUS_FILE = "/tmp/firmwareupdate/fw_au_status"

WARM_REBOOT = "warm"
COLD_REBOOT = "cold"
POWER_CYCLE = "power off"
FAST_REBOOT = "fast"

DEVICES_PATH = "usr/share/sonic/device"
TIMEOUT = 1200
COMMON_REBOOT_TIMEOUT = 600
BMC_COMPONENT = "BMC"
# The BMC may hold the Switch-Host off for its configured power-on delay (300s by default) before
# powering it on, and the switch then needs several minutes to start its critical services.
SWITCH_HOST_POWER_ON_TIMEOUT = 900
# Warning fwutil prints before a BMC firmware install: the new firmware runs only after a power cycle.
BMC_ACTIVATION_NOTICE_RE = re.compile(r"BMC power cycle.*required to activate", re.IGNORECASE)

REBOOT_TYPES = {
    COLD_REBOOT: "reboot",
    WARM_REBOOT: "warm-reboot",
    FAST_REBOOT: "fast-reboot"
}
LATEST_VERSION_IDX = 0


def find_pattern(lines, pattern):
    for line in lines:
        if pattern.match(line):
            return True
    return False


def get_hw_revision(duthost):
    out = duthost.command("show platform summary")
    rev_line = out["stdout"].splitlines()[6]
    return rev_line.split(": ")[1]


def power_cycle(duthost=None, pdu_ctrl=None, delay_time=60):
    assert pdu_ctrl, "pdu_ctrl is not ready, fail test"

    all_outlets = pdu_ctrl.get_outlet_status()

    logger.info("Powering off the PDU outlets.")
    for outlet in all_outlets:
        pdu_ctrl.turn_off_outlet(outlet)
    time.sleep(delay_time)
    logger.info("Powering on the PDU outlets.")
    for outlet in all_outlets:
        pdu_ctrl.turn_on_outlet(outlet)


def reboot(duthost, pdu_ctrl, reboot_type, pdu_delay=60):
    if reboot_type == POWER_CYCLE:
        power_cycle(duthost, pdu_ctrl, pdu_delay)
        return

    if reboot_type not in REBOOT_TYPES:
        pytest.fail("Invalid reboot type {}".format(reboot_type))

    logger.info("Rebooting using {}".format(reboot_type))
    duthost.command(REBOOT_TYPES[reboot_type], module_ignore_errors=True, module_async=True)


def complete_install(duthost, localhost, boot_type, res, pdu_ctrl, component, auto_reboot=False, current=None,
                     next_image=None, timeout=TIMEOUT, pdu_delay=60, post_install=None):
    hn = duthost.mgmt_ip
    component_name = component if isinstance(component, str) else ""

    if boot_type != "none":
        if not auto_reboot:
            logger.info("Waiting on install to finish.")
            res.get(timeout)
            if res._value['failed']:
                pytest.fail(f"The component installation is not successful: {res._value}")
            if post_install:
                # Checks that need the DUT as the install left it, before the reboot.
                post_install(res._value)
            logger.info("Rebooting switch using {} boot".format(boot_type))
            duthost.command("sonic-installer set-default {}".format(current))
            reboot(duthost, pdu_ctrl, boot_type, pdu_delay)
            logger.info("Waiting on switch to shutdown...")
            localhost.wait_for(host=hn, port=22, state='stopped', delay=1, timeout=60)
            # Wait for 30s in case there is ssh flap
            time.sleep(30)
            logger.info("Waiting on switch to come up in SONiC....")
            localhost.wait_for(
                host=hn, port=22, state='started', search_regex=SONIC_SSH_REGEX, delay=10,
                timeout=COMMON_REBOOT_TIMEOUT)
        else:
            # For auto reboot scenario, it takes some time in ONIE to update the firmware
            logger.info("Waiting on switch to shutdown after auto reboot...")
            if 'FPGA' in component_name:
                # For FPGA update, no reboot is needed.
                logger.info("Waiting for switch update result...")
                res.get(timeout)
                if res._value['failed']:
                    pytest.fail(f"The component installation is not successful: {res._value}")
                logger.info("FPGA update is successful")
            else:
                if 'CPLD' in component_name:
                    # For CPLD update, most time is spend before the reboot
                    pre_reboot_timeout = timeout
                    post_reboot_timeout = COMMON_REBOOT_TIMEOUT
                else:
                    # For BIOS/ONIE, most time is spend after the reboot in ONIE
                    pre_reboot_timeout = 120
                    if duthost.facts["platform"] == "x86_64-nvidia_sn4280-r0":
                        pre_reboot_timeout += 240
                    post_reboot_timeout = timeout
                localhost.wait_for(host=hn, port=22, state='stopped', delay=1, timeout=pre_reboot_timeout)
                # Wait for 30s in case there is ssh flap
                time.sleep(30)
                logger.info("Waiting on switch to come up in SONiC....")
                localhost.wait_for(
                    host=hn, port=22, state='started', search_regex=SONIC_SSH_REGEX, delay=10,
                    timeout=post_reboot_timeout)

        # Only wait for critical systems when a reboot actually occurred (FPGA update does not reboot).
        if (not auto_reboot) or ('FPGA' not in component_name):
            logger.info("Waiting on critical systems to come online...")
            wait_until(300, 30, 0, duthost.critical_services_fully_started)
            time.sleep(60)

        # Reboot back into original image if neccesary
        if next_image and auto_reboot:
            logger.info("We booted into the new image... booting back into the image under test.")
            duthost.command("sonic-installer set-default {}".format(current))
            reboot(duthost, pdu_ctrl, COLD_REBOOT, pdu_delay)
            logger.info("Waiting on switch to shutdown....")
            localhost.wait_for(host=hn, port=22, state='stopped', delay=10, timeout=150)
            time.sleep(100)
            logger.info("Waiting on switch to come up....")
            localhost.wait_for(host=hn, port=22, state='started', delay=10, timeout=150)
            wait_until(300, 30, 0, duthost.critical_services_fully_started)
            time.sleep(60)


def get_install_paths(request, duthost, defined_fw, versions, chassis, target_component, force=False):
    component = get_defined_components(duthost, defined_fw, chassis)
    ver = versions["chassis"].get(chassis, {})["component"]

    paths = {}

    if target_component is not None:
        component = {target_component: component[target_component]}

    for comp, revs in list(component.items()):
        if comp in ver:
            if revs[0].get("upgrade_only", False) and ver[comp] not in [r["version"] for r in revs]:
                logger.warning("Firmware is upgrade only and existing firmware {} is not present in version list. "
                               "Skipping {}".format(ver[comp], comp))
                continue
            for rev in revs:
                if "hw_revision" in rev and rev["hw_revision"] != get_hw_revision(duthost):
                    logger.warning("Firmware {} only supports HW Revision {} and this chassis is {}. Skipping".
                                   format(rev["version"], rev["hw_revision"], get_hw_revision(duthost)))
                    continue
                if force:
                    paths[comp] = rev
                    break
                if "install" in request.node.name and len(revs) == 1:
                    paths[comp] = rev
                    break
                elif rev["version"] != ver[comp]:
                    paths[comp] = rev
                    break
                elif rev.get("upgrade_only", False):
                    logger.warning("Firmware is upgrade only and newer version than {} is not available. Skipping {}".
                                   format(ver[comp], comp))
                    break
    return paths


def _resolve_flavor_components(component, defined_fw, chassis, duthost):
    """Resolve any flavor-dict entries (e.g. BMC) into revision lists."""
    for comp, revs in list(component.items()):
        if comp == "BMC" and isinstance(revs, dict):
            bmc_ip = bmc_user = bmc_password = None
            if len(revs) > 1:
                bmc_ip = get_bmc_ip(duthost)
                bmc_user, bmc_password = load_bmc_creds()
            flavor = resolve_bmc_flavor(defined_fw, chassis, duthost, bmc_ip,
                                        bmc_user, bmc_password)
            component[comp] = revs.get(flavor, [])
    return component


def get_defined_components(duthost, defined_fw, chassis):
    """
    Update the component content, in case there is a pre-definition for a specific host.
    Sometimes, if there is some DUTs has specific component(for example a respined board which requires
    a different CPLD) - it can be defined in the firmware.json file
    """
    component = defined_fw["chassis"].get(chassis, {})["component"]
    if "host" in defined_fw and duthost.hostname in defined_fw["host"]:
        for component_type in list(defined_fw["host"][duthost.hostname]["component"].keys()):
            component[component_type] = defined_fw["host"][duthost.hostname]["component"][component_type]
    return _resolve_flavor_components(component, defined_fw, chassis, duthost)


def generate_config(duthost, cfg, versions):
    valid_keys = ["firmware", "version"]
    chassis = list(versions["chassis"].keys())[0]
    paths = deepcopy(cfg)

    # Init all the components to null
    for comp in list(versions["chassis"][chassis]["component"].keys()):
        paths[comp] = paths.get(comp, {})
        if "firmware" in paths[comp]:
            paths[comp]["firmware"] = os.path.join("/", DEVICES_PATH, duthost.facts["platform"],
                                                   os.path.basename(paths[comp]["firmware"]))

    # Populate items we are installing
    with open("platform_components.json", "w") as f:
        json.dump({"chassis": {chassis: {"component": {comp: {k: v for k, v in list(dat.items()) if k in valid_keys}
                                                       for comp, dat in list(paths.items())}}}}, f, indent=4)


def upload_platform(duthost, paths, next_image=None):
    target = next_image if next_image else "/"

    # Clear auto update status file
    duthost.command("rm -rf {}".format(TEMP_STATUS_FILE))

    # Backup the original platform_components.json file
    duthost.fetch(dest=os.path.join("firmware", "platform_components_backup.json"),
                  src=os.path.join(target, DEVICES_PATH, duthost.facts["platform"], "platform_components.json"),
                  flat=True)
    logger.info("Backing up platform_components.json")

    # Copy over the platform_components.json file
    duthost.copy(src="platform_components.json", dest=os.path.join(target, DEVICES_PATH, duthost.facts["platform"]))
    logger.info("Copying platform_components.json to {}".format(
        os.path.join(target, DEVICES_PATH, duthost.facts["platform"])))

    for comp, dat in list(paths.items()):
        if dat["firmware"].startswith("http"):
            duthost.get_url(url=dat["firmware"], dest=os.path.join(target, DEVICES_PATH, duthost.facts["platform"]))
        else:
            duthost.copy(src=os.path.join("firmware", dat["firmware"]),
                         dest=os.path.join(target, DEVICES_PATH, duthost.facts["platform"]))


def validate_versions(final, config, chassis, boot):
    final = final["chassis"][chassis]["component"]
    for comp, dat in list(config.items()):
        logger.info("Validating {} is version {} (is {})".format(comp, dat["version"], final[comp]))
        if dat["version"] != final[comp] and boot in dat["reboot"]:
            pytest.fail("Failed to install FW verison {} on {}".format(dat["version"], comp))


def call_fwutil(request, duthost, localhost, pdu_ctrl, fw_pkg,
                component=None, next_image=None, boot=None, basepath=None, force=False, post_install=None):
    allure.step("Collect firmware versions")
    logger.info("Calling fwutil with component: {} | next_image: {} | boot: {} | basepath: {}".format(component,
                                                                                                      next_image,
                                                                                                      boot, basepath))
    init_versions = show_firmware(duthost)
    logger.info("Initial Versions: {}".format(init_versions))
    # Only one chassis
    chassis = list(init_versions["chassis"].keys())[0]
    paths = get_install_paths(request, duthost, fw_pkg, init_versions, chassis, component, force)
    if component not in paths:
        pytest.skip("No available firmware to install on {}. Skipping".format(component))
    boot_type = boot if boot else paths[component]["reboot"][0]
    if boot_type == POWER_CYCLE:
        assert pdu_ctrl, "pdu_ctrl is not ready, fail test"

    current = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']

    allure.step("Upload firmware to DUT")
    generate_config(duthost, paths, init_versions)
    upload_platform(duthost, paths, next_image)

    allure.step("Execute fwutil command")
    command = "fwutil"
    if basepath is not None:
        command += " install"
        auto_reboot = paths[component].get("force_reboot", False)
    else:
        command += " update"
        # The BMC activation needs power cycle
        if component == BMC_COMPONENT:
            auto_reboot = False
        else:
            auto_reboot = True

    if component is None:
        command += " all fw"
    else:
        command += " chassis component {} fw".format(component)

    if basepath is not None:
        # Install file is override if API implementation needs a different file for install / update
        filepath = paths[component]["firmware"]
        command += " {}".format(os.path.join(basepath, os.path.basename(filepath)))

    if next_image is not None:
        command += " --image={}".format("next" if next_image else "current")

    if boot is not None:
        command += " --boot={}".format(boot)
        auto_reboot = False
    else:
        command += " -y"

    # --force-update lets fwutil install firmware even when the target is older than the currently
    # installed one (e.g. BMC forced downgrade). Upgrades to a newer build do not need it.
    if force:
        command += " --force-update"

    logger.info("Running install command: {}".format(command))
    task, res = duthost.command(command, module_ignore_errors=True, module_async=True)

    allure.step("Perform Neccesary Reboot")
    timeout = max([v.get("timeout", TIMEOUT) for k, v in list(paths.items())])
    pdu_delay = fw_pkg["chassis"][chassis].get("power_cycle_delay", 60)
    complete_install(duthost, localhost, boot_type, res, pdu_ctrl, component,
                     auto_reboot, current, next_image, timeout, pdu_delay, post_install)

    allure.step("Collect Updated Firmware Versions")
    time.sleep(2)  # Give a little bit of time in case of no-op install for mounts to complete
    final_versions = show_firmware(duthost)
    validate_versions(final_versions, paths, chassis, boot_type)

    allure.step("Begin Switch Restoration")
    if next_image is None:
        duthost.copy(src=os.path.join("firmware", "platform_components_backup.json"),
                     dest=os.path.join("/", DEVICES_PATH, duthost.facts["platform"], "platform_components.json"))
        logger.info("Restoring backup platform_components.json to {}".format(
            os.path.join(DEVICES_PATH, duthost.facts["platform"])))

    update_needed = deepcopy(fw_pkg)
    update_needed["chassis"][chassis]["component"] = {}
    defined_components = get_defined_components(duthost, fw_pkg, chassis)
    final_components = final_versions["chassis"][chassis]["component"]
    for comp in list(paths.keys()):
        if defined_components[comp][LATEST_VERSION_IDX]["version"] != final_components[comp] and \
                boot in defined_components[comp][LATEST_VERSION_IDX]["reboot"] + [None] and \
                not paths[comp].get("upgrade_only", False):
            update_needed["chassis"][chassis]["component"][comp] = defined_components[comp]
    if len(list(update_needed["chassis"][chassis]["component"].keys())) > 0:
        logger.info("Latest firmware not installed after test. Installing....")
        call_fwutil(request, duthost, localhost, pdu_ctrl, update_needed, component, None, boot,
                    os.path.join("/", DEVICES_PATH, duthost.facts['platform']) if basepath is not None else None)


def get_bmc_fw_version(duthost):
    """
    Return the BMC firmware version reported by ``fwutil show status``, or None when there is none.
    """
    version, _ = get_bmc_version_from_firmware_data(show_firmware(duthost))
    return version


def get_bmc_chassis_and_entries(duthost, fw_pkg):
    """Return (chassis, BMC firmware entries ordered newest first).

    The entries are empty when *fw_pkg* defines no BMC firmware for the chassis, so that the caller
    can skip rather than fail.

    Example of the BMC definition in firmware.json::

        {
            "chassis": {
                "NVIDIA-AST2700-BMC": {             <- chassis name from "fwutil show status" on the BMC
                    "component": {
                        "BMC": {
                            "AST2700-A2": [         <- flavor, first word of /proc/device-tree/model
                                {                   <- newest first
                                    "firmware": "http://<server>/<path>/88.0070.2002/prod/ast2700.fwpkg",
                                    "version": "88.0070.2002",
                                    "reboot": ["power off"],
                                    "timeout": 2400
                                },
                                {
                                    "firmware": "http://<server>/<path>/88.0060.2303/prod/ast2700.fwpkg",
                                    "version": "88.0060.2303",
                                    "reboot": ["power off"],
                                    "timeout": 2400
                                }
                            ]
                        }
                    }
                }
            },
            "host": {
                "<bmc hostname>": {                 <- optional, overrides the chassis-level BMC entries
                    "component": {
                        "BMC": {"AST2700-A2": [{"firmware": "...", "version": "...", ...}]}
                    }
                }
            }
        }

    The flavor level may be omitted, i.e. "BMC" may hold the entry list directly.
    """
    _, chassis = get_bmc_version_from_firmware_data(show_firmware(duthost))
    # A "host" section overrides the chassis-level definition for that DUT, the same way
    # get_defined_components() does it for the components installed by call_fwutil(). BMC firmware
    # is signed per system, so a setup whose BMC needs a different signing flavor is listed there.
    host_bmc = fw_pkg.get("host", {}).get(duthost.hostname, {}).get("component", {}).get(BMC_COMPONENT)
    bmc = host_bmc or fw_pkg["chassis"].get(chassis, {}).get("component", {}).get(BMC_COMPONENT)
    if not bmc:
        return chassis, []
    if host_bmc:
        # get_bmc_firmware_list() reads the chassis section, so hand it the override instead.
        fw_pkg = {"chassis": {chassis: {"component": {BMC_COMPONENT: host_bmc}}}}
    # Resolving the flavor only needs the BMC itself when more than one flavor is defined.
    bmc_ip, bmc_user, bmc_password = None, None, None
    if isinstance(bmc, dict) and len(bmc) > 1:
        bmc_ip = get_bmc_ip(duthost)
        bmc_user, bmc_password = load_bmc_creds()
    return chassis, get_bmc_firmware_list(fw_pkg, chassis, duthost, bmc_ip, bmc_user, bmc_password)


def get_reachable_switch_host(duthost):
    """
    Return the Switch-Host paired with the BMC, or None when the testbed has none or it is not reachable.
    """
    if not duthost.duthosts.tbinfo.get("bmc_host"):
        return None
    try:
        switch_host = duthost.get_bmc_host()
        switch_host.command("echo ping")
    except Exception as e:
        logger.warning("Paired Switch-Host is not reachable, its power-on will not be checked: %s", e)
        return None
    return switch_host


def get_syslog_lines(duthost, keyword):
    """Return the syslog lines of *duthost* that contain *keyword*.

    Callers match the entry they look for in Python rather than by grep: the syslog also records every
    command the test runs, so a grep for the full entry would find its own command line.
    """
    return duthost.shell(f"sudo grep -aF '{keyword}' /var/log/syslog", module_ignore_errors=True)["stdout_lines"]


def fwutil_log_entry_re(action, firmware, status, component=BMC_COMPONENT):
    """
    Return a regex for the syslog entry fwutil writes when an *action* ("install" or "update") of *firmware* ends.
    """
    return re.compile(rf"fwutil: Firmware {action} ended: component=\S+/{component}, "
                      rf"firmware={re.escape(firmware)}, status={status}\b")


def count_fwutil_log_entries(duthost, action, firmware, status, component=BMC_COMPONENT):
    """
    Return how many times fwutil logged that an *action* of *firmware* ended with *status* ("success"/"failure").
    """
    entry = fwutil_log_entry_re(action, firmware, status, component)
    return sum(1 for line in get_syslog_lines(duthost, firmware) if entry.search(line))


def install_bmc_fw(request, duthost, localhost, pdu_ctrl, chassis, entry, force=False, from_file=True):
    """Install a single BMC firmware entry, power-cycle the system to activate it, and check that the
    BMC powers the paired Switch-Host back on.

    With *from_file* the package path is passed on the command line (``fwutil install``); otherwise
    fwutil takes it from platform_components.json in the current image (``fwutil update``).

    The power cycle also takes the Switch-Host down, and the BMC has to power it on again. A firmware
    can install and boot cleanly yet break that path (e.g. CPLD writes from the BMC are dropped), which
    leaves the switch off, so the BMC version alone does not prove the activation succeeded.
    """
    if not pdu_ctrl:
        pytest.skip("Activating BMC firmware needs a power cycle, but no PDU is connected to the testbed")

    switch_host = get_reachable_switch_host(duthost)
    boot_id_before = get_host_boot_id(switch_host) if switch_host else None

    # call_fwutil() puts the package here, for "fwutil install" and "fwutil update" alike.
    firmware = os.path.join("/", DEVICES_PATH, duthost.facts["platform"], os.path.basename(entry["firmware"]))
    action = "install" if from_file else "update"
    logged_before = count_fwutil_log_entries(duthost, action, firmware, "success")

    def install_logged():
        return count_fwutil_log_entries(duthost, action, firmware, "success") > logged_before

    def check_install_reported(result):
        # Checked before the power cycle, which wipes the BMC syslog (/var/log is a tmpfs).
        output = result.get("stdout", "") + result.get("stderr", "")
        pytest_assert(BMC_ACTIVATION_NOTICE_RE.search(output),
                      f"fwutil did not warn that a BMC power cycle activates the firmware: {output}")
        pytest_assert(wait_until(30, 2, 0, install_logged),
                      f"fwutil did not log the successful {action} of {firmware} in the BMC syslog")

    single = {"chassis": {chassis: {"component": {BMC_COMPONENT: [entry]}}}}
    basepath = os.path.join("/", DEVICES_PATH, duthost.facts["platform"]) if from_file else None
    call_fwutil(request, duthost, localhost, pdu_ctrl, single, component=BMC_COMPONENT,
                basepath=basepath, force=force, post_install=check_install_reported)

    if switch_host and not wait_host_rebooted(switch_host, boot_id_before, timeout=SWITCH_HOST_POWER_ON_TIMEOUT):
        modules = duthost.shell("show chassis modules status", module_ignore_errors=True)["stdout"]
        pytest.fail(f"Switch-Host {switch_host.hostname} did not reboot and come back up across the BMC firmware "
                    f"activation. BMC chassis modules status:\n{modules}")


def set_bmc_fw_to_target_version(request, duthost, localhost, pdu_ctrl, chassis, entry):
    """Bring the BMC to the firmware in *entry*, doing nothing if it already runs that version.

    Used to put the BMC in a known state before a test, so it is not the operation under test.
    ``--force-update`` is always passed because the target may be older than the installed
    firmware, and the BMC's anti-rollback check rejects a downgrade without it.
    """
    current = get_bmc_fw_version(duthost)
    if current == entry["version"]:
        logger.info("BMC already runs firmware version %s, skipping the install", current)
        return
    logger.info("Bringing the BMC from firmware version %s to %s", current, entry["version"])
    install_bmc_fw(request, duthost, localhost, pdu_ctrl, chassis, entry, force=True)
