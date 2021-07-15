import pytest
import os
import json
import logging

from copy import deepcopy

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

DEVICES_PATH="usr/share/sonic/device"
TIMEOUT=3600
REBOOT_TYPES = {
        "cold": "reboot",
        "warm": "warm-reboot",
        "fast": "fast-reboot"
        }

def find_pattern(lines, pattern):
    for line in lines:
        if pattern.match(line):
            return True
    return False

def power_cycle(duthost=None, pdu_ctrl=None, delay_time=60):
    if pdu_ctrl is None:
        pytest.skip("No PSU controller for %s, skipping" % duthost.hostname)

    all_outlets = pdu_ctrl.get_outlet_status()

    for outlet in all_outlets:
        pdu_ctrl.turn_off_outlet(outlet)
    time.sleep(delay_time)
    for outlet in all_outlets:
        pdu_ctrl.turn_on_outlet(outlet)

def reboot(duthost, pdu_ctrl, reboot_type):
    if reboot_type == "power off": 
        power_cycle(duthost, pdu_ctrl)
        return

    if reboot_type not in REBOOT_TYPES: pytest.fail("Invalid reboot type {}".format(reboot_type))

    duthost.command(REBOOT_TYPES[reboot_type], module_ignore_errors=True, module_async=True)

def complete_install(duthost, localhost, boot_type, res, pdu_ctrl, auto_reboot=False, current=None, next_image=None):
    hn = duthost.mgmt_ip

    if boot_type != "none":
        if not auto_reboot:
            logger.info("Waiting on install to finish.")
            res.get(TIMEOUT)
            logger.info("Rebooting switch using {} boot".format(boot_type))
            duthost.command("sonic-installer set-default {}".format(current))
            reboot(duthost, pdu_ctrl, boot_type)
        
        logger.info("Waiting on switch to shutdown...")
        # Wait for ssh flap
        localhost.wait_for(host=hn, port=22, state='stopped', delay=10, timeout=TIMEOUT)
        logger.info("Letting switch get through ONIE / BIOS before pinging....")
        time.sleep(300)
        logger.info("Waiting on switch to come up....")
        localhost.wait_for(host=hn, port=22, state='started', delay=10, timeout=300)
        logger.info("Waiting on critical systems to come online...")
        wait_until(300, 30, duthost.critical_services_fully_started)
        time.sleep(60)

    # Reboot back into original image if neccesary
    if next_image:
        logger.info("We booted into the new image... booting back into the image under test.")
        duthost.command("sonic-installer set-default {}".format(current))
        reboot(duthost, pdu_ctrl, "cold")
        logger.info("Waiting on switch to shutdown....")
        localhost.wait_for(host=hn, port=22, state='stopped', delay=10, timeout=150)
        time.sleep(100)
        logger.info("Waiting on switch to come up....")
        localhost.wait_for(host=hn, port=22, state='started', delay=10, timeout=150)
        wait_until(300, 30, duthost.critical_services_fully_started)
        time.sleep(60)

def show_firmware(duthost):
    out = duthost.command("fwutil show status")
    
    num_spaces = 2
    curr_chassis = ""
    output_data = {"chassis":{}}
    status_output = out['stdout']
    separators = re.split(r'\s{2,}', status_output.splitlines()[1])  # get separators
    output_lines = status_output.splitlines()[2:]

    for line in output_lines:
        data = []
        start = 0

        for sep in separators:
            curr_len = len(sep)
            data.append(line[start:start+curr_len].strip())
            start += curr_len + num_spaces

        if data[0].strip() != "":
            curr_chassis = data[0].strip()
            output_data["chassis"][curr_chassis] = {"component": {}}

        output_data["chassis"][curr_chassis]["component"][data[2]] = data[3]

    return output_data

def get_install_paths(duthost, fw, versions, chassis):
    chass = show_firmware(duthost)["chassis"].keys()[0]
    component = fw["chassis"].get(chass, {})["component"]
    ver = versions["chassis"].get(chass, {})["component"]
    
    paths = {}

    for comp, revs in component.items():
        if comp in ver:
            if revs[0].get("upgrade_only", False) and ver[comp] not in [r["version"] for r in revs]:
                # If upgrade only we need to skip if the installed version isn't on record
                continue
            for i, rev in enumerate(revs):
                if rev["version"] != ver[comp]:
                    paths[comp] = rev
                    break
                elif rev.get("upgrade_only", False):
                    # If upgrade only stop searching when installed version hit
                    break
    return paths

def generate_config(duthost, cfg, versions):
    valid_keys = ["firmware", "version"]
    chassis = versions["chassis"].keys()[0]
    paths = deepcopy(cfg)

    # Init all the components to null
    for comp in versions["chassis"][chassis]["component"].keys():
        paths[comp] = paths.get(comp, {})
        if "firmware" in paths[comp]:
            paths[comp]["firmware"] = os.path.join("/", DEVICES_PATH, 
                    duthost.facts["platform"], 
                    os.path.basename(paths[comp]["firmware"]))

    # Populate items we are installing
    with open("platform_components.json", "w") as f:
        json.dump({"chassis":{chassis:{"component":{comp:{k: v 
            for k, v in dat.items() 
            if k in valid_keys} 
            for comp, dat in paths.items()}}}}, f, indent=4)

def upload_platform(duthost, paths, next_image=None):
    target = next_image if next_image else "/"

    # Copy over the platform_components.json file
    duthost.copy(src="platform_components.json", 
            dest=os.path.join(target, DEVICES_PATH, duthost.facts["platform"]))
    logger.info("Copying platform_components.json to {}".format(
        os.path.join(target, DEVICES_PATH, duthost.facts["platform"])))

    for comp, dat in paths.items():
        duthost.copy(src=os.path.join("firmware", dat["firmware"]), 
                dest=os.path.join(target, DEVICES_PATH, duthost.facts["platform"]))
        if "install" in dat:
            duthost.copy(src=os.path.join("firmware", dat["install"]["firmware"]), 
                    dest=os.path.join(target, DEVICES_PATH, duthost.facts["platform"]))
            logger.info("Copying {} to {}".format(os.path.join("firmware", dat["install"]["firmware"]),
                os.path.join(target, DEVICES_PATH, duthost.facts["platform"])))

def validate_versions(init, final, config, chassis, boot):
    final = final["chassis"][chassis]["component"]
    init = init["chassis"][chassis]["component"]
    for comp, dat in config.items():
        logger.info("Validating {} is version {} (is {})".format(comp, dat["version"], final[comp]))
        if (dat["version"] != final[comp] or init[comp] == final[comp]) and boot in dat["reboot"]:
            pytest.fail("Failed to install FW verison {} on {}".format(dat["version"], comp))
            return False
    return True

def call_fwutil(duthost, localhost, pdu_ctrl, fw, component=None, next_image=None, boot=None, basepath=None):
    logger.info("Calling fwutil with component: {} | next_image: {} | boot: {} | basepath: {}".format(component, next_image, boot, basepath))
    init_versions = show_firmware(duthost)
    logger.info("Initial Versions: {}".format(init_versions))
    chassis = init_versions["chassis"].keys()[0] # Only one chassis
    paths = get_install_paths(duthost, fw, init_versions, chassis)
    current = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']

    generate_config(duthost, paths, init_versions)
    upload_platform(duthost, paths, next_image)

    command = "fwutil"
    if basepath is not None:
        command += " install"
    else:
        command += " update"

    if component is None:
        command += " all"
    else:
        if component not in paths:
            pytest.skip("No available firmware to install on {}. Skipping".format(component))
        command += " chassis component {} fw".format(component)

    if basepath is not None:
        # Install file is override if API implementation needs a different file for install / update
        filepath = paths[component]["install"]["firmware"] if "install" in paths[component] else paths[component]["firmware"]
        command += " {}".format(os.path.join(basepath, os.path.basename(filepath)))

    if next_image is not None:
        command += " --image={}".format("next" if next_image else "current")

    if boot is not None:
        command += " --boot={}".format(boot)

    command += " -y"

    logger.info("Running install command: {}".format(command))
    task, res = duthost.command(command, module_ignore_errors=True, module_async=True)
    boot_type = boot if boot else paths[component]["reboot"][0]

    if "install" in paths[component] and basepath is not None:
        auto_reboot = paths[component]["install"].get("auto_reboot", False)
    else:
        auto_reboot = paths[component].get("auto_reboot", False)

    complete_install(duthost, localhost, boot_type, res, pdu_ctrl, auto_reboot, current, next_image)

    final_versions = show_firmware(duthost)
    return validate_versions(init_versions, final_versions, paths, chassis, boot_type)

