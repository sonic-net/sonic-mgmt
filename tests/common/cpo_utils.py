"""CPO (Co-Packaged Optics) helpers.

Platform detection and cpo.json parsing, the cpoutil firmware CLI, xcvrd
control, ELS port recovery, data-plane traffic checks and the firmware lock.
"""
import ipaddress
import json
import logging
import re
import shlex
import time

import pytest

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


# --- Platform detection and cpo.json ---

def get_cpo_json_path(duthost):
    """
    Get the path of the cpo.json file for the given dut object
    :param dut: dut object
    :return: The absolute path of the cpo.json file on the DUT
    """
    platform = duthost.facts["platform"]
    return "/usr/share/sonic/device/{}/cpo.json".format(platform)


def is_cpo_switch(duthost):
    """
    Check whether the given dut is a CPO (Co-Packaged Optics) switch.
    A device is considered a CPO switch when the cpo.json file exists under
    /usr/share/sonic/device/<platform>/ on the DUT.
    :param duthost: dut object
    :return: True if the device is a CPO switch, otherwise False
    """
    cpo_json_path = get_cpo_json_path(duthost)
    logger.info(f"Checking if {duthost.facts['platform']} is a CPO switch via {cpo_json_path}")
    return duthost.stat(path=cpo_json_path)["stat"]["exists"]


def get_cpo_data(duthost):
    """
    Load and return the content of the cpo.json file for the given dut object.
    :param duthost: dut object
    :return: A dictionary contains the CPO data parsed from cpo.json
    """
    cpo_json_path = get_cpo_json_path(duthost)
    # Quote the path and use 'cat --' to avoid shell metacharacter / option injection
    # in case the platform string contains unexpected characters.
    result = duthost.shell("cat -- {}".format(shlex.quote(cpo_json_path)), module_ignore_errors=True)
    if result["rc"] != 0:
        raise RuntimeError(
            "Failed to read cpo.json on {} at {}: rc={}, stderr={}".format(
                duthost.hostname, cpo_json_path, result["rc"], result.get("stderr", "")))
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError as e:
        raise ValueError(
            "Failed to parse cpo.json on {} at {}: {}. stdout(first 200 chars)={!r}".format(
                duthost.hostname, cpo_json_path, e, result["stdout"][:200]))


def get_cpo_device_expected_num_sfps(duthost):
    """
    Get the expected number of SFPs for a CPO switch based on the cpo.json file.
    :param duthost: dut object
    :return: The expected number of SFPs on the CPO switch
    """
    cpo_data = get_cpo_data(duthost)

    # For 'sfps', one SFP == one unique 'sdk_module_index'.
    sfp_module_indexes = set(
        sfp_data.get("sdk_module_index")
        for sfp_data in cpo_data.get("sfps", {}).values()
    )
    num_sfp_sfps = len(sfp_module_indexes)

    logger.info(f"CPO cpo.json entities: num_sfp_sfps={num_sfp_sfps}")
    return num_sfp_sfps


def get_cpo_device_sfp_index_list(duthost):
    """
    Get the list of SFP physical port indices for a CPO switch based on the
    cpo.json file. The physical port index is derived as (module_index + 1)
    for each unique module_index found in the sfps section of cpo.json.
    :param duthost: dut object
    :return: A sorted list of SFP physical port indices on the CPO switch
    """
    cpo_data = get_cpo_data(duthost)

    # For sfps, one SFP == one unique module_index. The physical port
    # index used by the platform API is (module_index + 1).
    module_indexes = set(
        int(sfp_data.get("module_index"))
        for sfp_data in cpo_data.get("sfps", {}).values()
    )
    sfp_index_list = sorted(module_index + 1 for module_index in module_indexes)

    logger.info(f"CPO cpo.json sfp index list: {sfp_index_list}")
    return sfp_index_list


# --- cpoutil firmware management ---

def normalize_fw_version(version):
    """Strip leading zeros from each segment: "42.050.01011" -> "42.50.1011"."""
    return ".".join(str(int(seg)) if seg.isdigit() else seg for seg in version.split("."))


FW_ACTIVE = "Active Firmware"
FW_INACTIVE = "Inactive Firmware"
FW_RUNNING_IMAGE = "Running Image"
FW_COMMITTED_IMAGE = "Committed Image"

BUSY_ERROR = "busy"

# Not under /tmp, which is tmpfs and lost on reboot.
CPOUTIL_FW_STAGE_DIR = "/home/admin/cpoutil_firmware"

PORT_LINK_TIMEOUT = 360
OE_LOW_POWER_TIMEOUT = 60  # seconds to wait for ModuleLowPwr after reset

# Each ELS serves 32 lanes: ELS<N> -> Ethernet<32*N> .. Ethernet<32*N+31>
ELS_LANES = 32

XCVRD_STOP_WAIT_SEC = 5

BANK_SUFFIX_RE = re.compile(r"\s*\(Bank [A-Z]\)$")
ETHERNET_PORT_RE = re.compile(r"^Ethernet(\d+)$")


def parse_fwversion_text(output_lines):
    """Parse cpoutil show {oe|els} fwversion output into {target: {field: value}}.

    Example:
        ELS0:
          Image A Version: 1.2.0
          Image B Version: 1.1.0
          Running Image: A
          Committed Image: A
          Active Firmware: 1.2.0 (Bank A)
          Inactive Firmware: 1.1.0 (Bank B)

    The "(Bank X)" suffix is dropped so the value matches the --json output.
    """
    result = {}
    current_target = None
    for line in output_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            current_target = stripped[:-1].lower()
            result[current_target] = {}
            continue
        if ":" in stripped and current_target is not None:
            key, _, value = stripped.partition(":")
            result[current_target][key.strip()] = BANK_SUFFIX_RE.sub("", value.strip())
    return result


def pick_different_firmware(binaries, active_version):
    """Return (path, version) of the staged image whose version differs from
    active_version, preferring the target image. If no staged image differs
    (e.g. firmware.json has a single ELS entry), return the target image.
    """
    for role in ("target", "default"):
        if binaries[f"{role}_version"] != active_version:
            return binaries[role], binaries[f"{role}_version"]
    return binaries["target"], binaries["target_version"]


def cpoutil_show_fwversion(duthost, component, index=None, json_output=False):
    """Run cpoutil show {oe|els} fwversion [index] [--json] and return the parsed
    output. Fails unless it has the requested target (or any target if no index).
    """
    cmd = f"cpoutil show {component} fwversion"
    if index is not None:
        cmd += f" {index}"
    if json_output:
        cmd += " --json"
    result = duthost.command(cmd)
    if json_output:
        try:
            fwinfo = json.loads(result["stdout"])
        except json.JSONDecodeError as e:
            pytest.fail(f"'{cmd}' returned invalid JSON ({e}): {result['stdout']}")
    else:
        fwinfo = parse_fwversion_text(result["stdout_lines"])
    if index is None:
        assert fwinfo, f"No target in '{cmd}' output: {result['stdout']}"
    else:
        assert f"{component}{index}" in fwinfo, f"{component}{index} not in '{cmd}' output: {result['stdout']}"
    return fwinfo


def cpoutil_firmware(duthost, op, target, fw_path=None):
    """Run cpoutil firmware <op> els <target> [--raw fw_path] and return stdout.

    op: download, run, commit or upgrade. target: ELS index or "all".
    """
    cmd = f"cpoutil firmware {op} els {target}"
    if fw_path:
        cmd += f" --raw {fw_path}"
    return duthost.command(cmd)["stdout"]


def cpoutil_reset_oe(duthost, oe_index):
    """Reset the OE (Optical Engine) by index and return stdout.
    After firmware run/reset, the OE needs to be reset to reinitialize.
    The OE index corresponds to the ELS index (OE0 <-> ELS0, etc.).
    """
    return duthost.command(f"sudo cpoutil config oe reset {oe_index}")["stdout"]


def get_oe_status(duthost):
    """Parse 'cpoutil show oe status' output into {oe_index: state} dict.

    Example output:
        OE    Module State
        ----  --------------
        OE0   ModuleLowPwr
        OE1   ModuleReady

    Returns: {0: "ModuleLowPwr", 1: "ModuleReady", ...}
    """
    result = duthost.shell("sudo cpoutil show oe status", module_ignore_errors=True)
    if result["rc"] != 0:
        logger.warning(f"Failed to get OE status: {result.get('stderr', '')}")
        return {}

    oe_status = {}
    for line in result["stdout_lines"]:
        line = line.strip()
        # Match lines like "OE0   ModuleLowPwr"
        if line.startswith("OE") and not line.startswith("OE "):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    oe_index = int(parts[0][2:])  # Extract number from "OE0"
                    oe_status[oe_index] = parts[1]
                except (ValueError, IndexError):
                    continue
    return oe_status


def is_oe_in_low_power(duthost, oe_index):
    """Check if the specified OE is in ModuleLowPwr state."""
    return get_oe_status(duthost).get(oe_index) == "ModuleLowPwr"


def stop_xcvrd(duthost):
    """Stop xcvrd if it is running, so it does not access the modules (I2C contention)."""
    status = duthost.shell("docker exec pmon supervisorctl status xcvrd", module_ignore_errors=True)
    if "RUNNING" in status["stdout"]:
        duthost.shell("docker exec pmon supervisorctl stop xcvrd")
        logger.info("Stopped xcvrd in pmon")
        time.sleep(XCVRD_STOP_WAIT_SEC)


def start_xcvrd(duthost):
    """Start xcvrd if it is not running (it restarts on its own after a reboot)."""
    status = duthost.shell("docker exec pmon supervisorctl status xcvrd", module_ignore_errors=True)
    if "RUNNING" not in status["stdout"]:
        duthost.shell("docker exec pmon supervisorctl start xcvrd")
        logger.info("Started xcvrd in pmon")


def els_ports(duthost, index):
    """Return the admin up front-panel ports served by ELS <index>
    (Ethernet<32*index>..+31). Admin down ports are not in use, so the tests
    neither toggle them nor expect them to be oper up.
    """
    first, last = ELS_LANES * index, ELS_LANES * (index + 1)
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    ports = {}
    for name, st in status.items():
        match = ETHERNET_PORT_RE.match(name)
        if match and first <= int(match.group(1)) < last and st["admin_state"] == "up":
            ports[name] = int(match.group(1))
    assert ports, f"No admin up ports found for ELS{index} (Ethernet{first}..Ethernet{last - 1})"
    return sorted(ports, key=ports.get)


def recover_els_ports(duthost, indices):
    """Bring up the ports of the given ELS after a firmware run, and return them.

    Sequence:
    1. Stop xcvrd (avoid I2C contention during reset)
    2. Reset each OE, wait for ModuleLowPwr state
    3. Start xcvrd (takes software control of the modules)
    4. Wait for ports to link up
    """
    stop_xcvrd(duthost)
    ports = []
    for index in indices:
        ports.extend(els_ports(duthost, index))
        cpoutil_reset_oe(duthost, index)
        time.sleep(3)
        assert wait_until(OE_LOW_POWER_TIMEOUT, 5, 0, is_oe_in_low_power, duthost, index), (
            f"OE{index} did not reach ModuleLowPwr within {OE_LOW_POWER_TIMEOUT}s"
        )
    start_xcvrd(duthost)
    if not wait_until(PORT_LINK_TIMEOUT, 10, 0, duthost.links_status_up, ports):
        down = duthost.show_interface(command="status", up_ports=ports)[
            "ansible_facts"]["ansible_interface_link_down_ports"]
        raise AssertionError(f"Ports not up after reset: {down}")
    return ports


def assert_els_running(target, state, version):
    """Fail unless the ELS runs <version> and its running image is committed."""
    assert state[FW_ACTIVE] == version, f"{target}: active firmware {state[FW_ACTIVE]} != {version}"
    assert state[FW_COMMITTED_IMAGE] == state[FW_RUNNING_IMAGE], (
        f"{target}: committed image {state[FW_COMMITTED_IMAGE]} != running image {state[FW_RUNNING_IMAGE]}"
    )


def verify_traffic_between_ports(ptfadapter, duthost, mg_facts, src_port, dst_port, count=1):
    """Send IPv4 packets from src_port to dst_port's neighbor and verify receipt.

    Args:
        count: Number of packets to send (default 1).
    """
    import ptf.testutils as testutils
    from ptf import mask, packet

    # dst_port is either a routed port or a member of a routed PortChannel
    l3_intf = dst_port
    for pc_name, pc in mg_facts.get("minigraph_portchannels", {}).items():
        if dst_port in pc["members"]:
            l3_intf = pc_name
            break
    peer_ip = next(
        (intf["peer_addr"]
         for intf in mg_facts["minigraph_interfaces"] + mg_facts["minigraph_portchannel_interfaces"]
         if intf["attachto"] == l3_intf and ipaddress.ip_address(intf["peer_addr"]).version == 4),
        None,
    )
    assert peer_ip, f"No IPv4 neighbor found behind {dst_port} ({l3_intf})"

    src_ptf = mg_facts["minigraph_ptf_indices"][src_port]
    dst_ptf = mg_facts["minigraph_ptf_indices"][dst_port]
    router_mac = duthost.facts["router_mac"]

    pkt = testutils.simple_ip_packet(
        eth_dst=router_mac,
        eth_src=ptfadapter.dataplane.get_mac(0, src_ptf),
        ip_src="1.1.1.1",
        ip_dst=peer_ip,
        ip_ttl=64,
    )
    exp_pkt = pkt.copy()
    exp_pkt[packet.IP].ttl = 63
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
    exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")

    logger.info(f"Sending {count} packets {src_port} -> {dst_port} (peer {peer_ip})")
    ptfadapter.dataplane.flush()
    for _ in range(count):
        testutils.send(ptfadapter, src_ptf, pkt)
    testutils.verify_packet(ptfadapter, exp_pkt, dst_ptf, timeout=5)
