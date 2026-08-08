import re
import os
import json
import logging
import shlex
import tarfile
import paramiko
import yaml

logger = logging.getLogger(__name__)

_BMC_SECRETS_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../ansible/group_vars/lab/secrets.yml'))


def load_bmc_creds():
    """Load BMC credentials from ansible/group_vars/lab/secrets.yml."""
    try:
        with open(_BMC_SECRETS_PATH) as f:
            secrets = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise FileNotFoundError(
            "BMC secrets file not found at {}".format(_BMC_SECRETS_PATH)
        ) from e

    if not isinstance(secrets, dict):
        raise ValueError(
            "Invalid BMC secrets file {}: expected a mapping".format(_BMC_SECRETS_PATH)
        )

    try:
        return secrets['sonic_bmc_root_user'], secrets['sonic_bmc_root_password']
    except KeyError as e:
        raise KeyError(
            "Missing BMC credential key {} in {}".format(e, _BMC_SECRETS_PATH)
        ) from e


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
    try:
        platform = duthost.shell(
            "sudo show platform summary | grep Platform | awk '{print $2}'"
        )["stdout"]
        if not platform:
            logger.warning("Failed to get platform name from %s", duthost.hostname)
            return None

        bmc_config_file = f"/usr/share/sonic/device/{platform}/bmc.json"
        duthost.fetch(src=bmc_config_file, dest="/tmp")
        with open(f"/tmp/{duthost.hostname}/{bmc_config_file}") as f:
            return json.load(f).get("bmc_addr")
    except Exception as e:
        logger.warning("Failed to read BMC IP from %s: %s", duthost.hostname, e)
        return None


def _ssh_bmc_cmd(duthost, bmc_ip, bmc_user, bmc_password, cmd):
    """
    Run *cmd* on the BMC via SSH through the DUT. No sshpass needed.

    """
    if hasattr(duthost, 'engine'):
        transport = duthost.engine.remote_conn.get_transport()
        channel = transport.open_channel("direct-tcpip", (bmc_ip, 22), ("127.0.0.1", 0))
        bmc_client = paramiko.SSHClient()
        bmc_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            bmc_client.connect(bmc_ip, username=bmc_user, password=bmc_password,
                               sock=channel, timeout=30)
            _, stdout, _ = bmc_client.exec_command(cmd)
            return stdout.read().decode().strip()
        finally:
            bmc_client.close()

    python_code = (
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        f"client.connect({bmc_ip!r}, username={bmc_user!r}, "
        f"password={bmc_password!r}, timeout=30)\n"
        f"_, stdout, _ = client.exec_command({cmd!r})\n"
        "print(stdout.read().decode().strip())\n"
        "client.close()"
    )
    return duthost.command(f"python3 -c {shlex.quote(python_code)}")["stdout"]


def get_bmc_flavor(duthost, bmc_ip, bmc_user, bmc_password):
    """
    Detect BMC flavor from ``/proc/device-tree/model``
    (e.g. ``AST2700-A1 Spc6 CPU BMC`` -> ``AST2700-A1``).
    """
    model_output = _ssh_bmc_cmd(duthost, bmc_ip, bmc_user, bmc_password,
                                "cat /proc/device-tree/model")

    if not model_output:
        raise ValueError("Empty output from BMC /proc/device-tree/model")

    flavor = model_output.split()[0]
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
