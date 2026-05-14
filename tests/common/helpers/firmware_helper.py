import re
import os
import json
import logging
import tarfile
import yaml

from tests.common.helpers.platform_api import bmc

logger = logging.getLogger(__name__)

_BMC_SECRETS_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../ansible/group_vars/lab/secrets.yml'))


def load_bmc_creds():
    """Load BMC credentials from ansible/group_vars/lab/secrets.yml."""
    with open(_BMC_SECRETS_PATH) as f:
        secrets = yaml.safe_load(f)
    return secrets['sonic_bmc_root_user'], secrets['sonic_bmc_root_password']


PLATFORM_COMP_PATH_TEMPLATE = '/usr/share/sonic/device/{}/platform_components.json'
FW_TYPE_INSTALL = 'install'
FW_TYPE_UPDATE = 'update'


def extract_fw_data(fw_pkg_path):
    """Extract firmware data dict from a tar.gz or plain json file."""
    if tarfile.is_tarfile(fw_pkg_path):
        with tarfile.open(fw_pkg_path, "r:gz") as fw_tar:
            member = fw_tar.getmember("firmware.json")
            if not member.isfile():
                raise ValueError("firmware.json in {} is not a regular file".format(fw_pkg_path))

            fw = fw_tar.extractfile(member)
            if fw is None:
                raise ValueError("Failed to read firmware.json from {}".format(fw_pkg_path))

            with fw:
                fw_data = json.load(fw)
    else:
        with open(fw_pkg_path, 'r') as fw:
            fw_data = json.load(fw)

    return fw_data


def get_bmc_ip(duthost):
    """Read BMC IP from the DUT's bmc.json config file. Returns None if unavailable."""
    platform = duthost.shell(
        "sudo show platform summary | grep Platform | awk '{print $2}'"
    )["stdout"]
    bmc_config_file = f"/usr/share/sonic/device/{platform}/bmc.json"
    duthost.fetch(src=bmc_config_file, dest="/tmp")
    with open(f"/tmp/{duthost.hostname}/{bmc_config_file}") as f:
        return json.load(f)["bmc_addr"]


def get_bmc_flavor(duthost, bmc_ip, bmc_user, bmc_password):
    """
    Detect BMC flavor from BMC platform API model output
    (e.g. ``AST2700-A1 Spc6 CPU BMC`` -> ``AST2700-A1``).
    """
    model_output = bmc.get_model(duthost)

    if not model_output:
        raise ValueError("Empty BMC model output from platform API")

    flavor = str(model_output).split()[0]
    logger.info("Detected BMC flavor: %s (model: %s)", flavor, model_output)
    return flavor


def get_bmc_firmware_list(fw_pkg, chassis, duthost, bmc_ip,
                          bmc_user, bmc_password):
    """Resolve BMC flavor and return the firmware entry list for *chassis*."""
    bmc_entry = fw_pkg["chassis"][chassis]["component"]["BMC"]
    if isinstance(bmc_entry, list):
        logger.info("No flavor defined in firmware.json for chassis=%s, using flat BMC entry", chassis)
        return bmc_entry
    flavor = resolve_bmc_flavor(fw_pkg, chassis, duthost, bmc_ip,
                                bmc_user, bmc_password)
    return bmc_entry[flavor]


def resolve_bmc_flavor(fw_pkg, chassis, duthost, bmc_ip,
                       bmc_user, bmc_password):
    """Return the BMC flavor for *chassis*. Returns None when the old flat-list format is used."""
    bmc_entry = fw_pkg.get("chassis", {}).get(chassis, {}).get("component", {}).get("BMC")

    if isinstance(bmc_entry, list):
        logger.debug("BMC entry is a flat list (no flavor layer)")
        return None

    if not isinstance(bmc_entry, dict) or not bmc_entry:
        raise KeyError(f"No BMC flavors defined for chassis={chassis}")

    flavors = list(bmc_entry.keys())
    if len(flavors) == 1:
        logger.info("Single BMC flavor available: %s", flavors[0])
        return flavors[0]

    if not bmc_ip:
        raise ValueError(
            f"Multiple BMC flavors {flavors} for chassis={chassis}, but bmc_ip is not available"
        )

    return get_bmc_flavor(duthost, bmc_ip, bmc_user, bmc_password)


def get_bmc_info_from_firmware_data(fw_data, chassis_name, flavor):
    """Return ``(expected_version, firmware_path)`` or ``(None, None)``."""
    bmc_info = fw_data.get('chassis', {}).get(chassis_name, {}).get('component', {}).get('BMC')
    if not bmc_info:
        return None, None

    if isinstance(bmc_info, list):
        fw_list = bmc_info
    elif isinstance(bmc_info, dict):
        fw_list = bmc_info.get(flavor)
    else:
        return None, None

    if not fw_list:
        return None, None

    return fw_list[0].get('version'), fw_list[0].get('firmware')


def parse_firmware_status(status_output):
    """Parse ``fwutil show status`` output into ``{"chassis": {name: {"component": {...}}}}``."""
    output_data = {"chassis": {}}

    if not status_output:
        return output_data

    lines = status_output.splitlines()
    if len(lines) < 3:
        return output_data

    num_spaces = 2
    curr_chassis = ""
    separators = re.split(r'\s{2,}', lines[1])

    for line in lines[2:]:
        if not line.strip():
            continue

        data = []
        start = 0

        for sep in separators:
            curr_len = len(sep)
            data.append(line[start:start+curr_len].strip())
            start += curr_len + num_spaces

        if len(data) < 4:
            continue

        if data[0].strip():
            curr_chassis = data[0].strip()
            output_data["chassis"][curr_chassis] = {"component": {}}

        if curr_chassis and curr_chassis in output_data["chassis"]:
            output_data["chassis"][curr_chassis]["component"][data[2]] = data[3]

    return output_data


def show_firmware(duthost):
    """Run ``fwutil show status`` on the DUT and return parsed dict."""
    out = duthost.command("sudo fwutil show status")["stdout"]
    return parse_firmware_status(out)


def get_bmc_version_from_firmware_data(fw_data):
    """Return ``(bmc_version, chassis_name)`` or ``(None, None)``."""
    chassis_dict = fw_data.get("chassis", {})
    if not chassis_dict:
        return None, None

    # Get first chassis name (typically only one)
    chassis_name = list(chassis_dict.keys())[0]
    components = chassis_dict[chassis_name].get("component", {})

    bmc_version = components.get("BMC")
    return bmc_version, chassis_name
