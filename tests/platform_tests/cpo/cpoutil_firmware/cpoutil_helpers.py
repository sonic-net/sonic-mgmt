"""CLI wrappers and parsers for cpoutil firmware commands."""
import json
import logging
import re
import time

import pytest

logger = logging.getLogger(__name__)


def normalize_fw_version(version):
    """Strip leading zeros from each segment: "42.050.01011" -> "42.50.1011"."""
    return ".".join(str(int(seg)) if seg.isdigit() else seg for seg in version.split("."))


FW_ACTIVE = "Active Firmware"
FW_INACTIVE = "Inactive Firmware"
FW_RUNNING_IMAGE = "Running Image"
FW_COMMITTED_IMAGE = "Committed Image"

BUSY_ERROR = "Another firmware operation is in progress"

# Not under /tmp, which is tmpfs and lost on reboot.
CPOUTIL_FW_STAGE_DIR = "/home/admin/cpoutil_firmware"

FIRMWARE_LOCK_DIR = "/var/lock/nvidia-cpo"
FLOCK_BUSY_RC = 75

# Per-ELS timeout (seconds) of each firmware operation
FW_OP_TIMEOUT = {"download": 900, "upgrade": 1200, "run": 120, "commit": 60}
FWVERSION_TIMEOUT = 30
RESET_TIMEOUT = 120
PORT_LINK_TIMEOUT = 180

# Each ELS serves 32 lanes: ELS<N> -> Ethernet<32*N> .. Ethernet<32*N+31>
ELS_LANES = 32

XCVRD_STOP_WAIT_SEC = 5

BANK_SUFFIX_RE = re.compile(r"\s*\(Bank [A-Z]\)$")


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
    active_version, preferring the target image.
    """
    for role in ("target", "default"):
        if binaries[f"{role}_version"] != active_version:
            return binaries[role], binaries[f"{role}_version"]
    pytest.fail(f"Both firmware.json images have the active version {active_version}")


def cpoutil_show_fwversion(duthost, component, index=None, json_output=False):
    """Run cpoutil show {oe|els} fwversion [index] [--json] and return the parsed
    output. Fails unless it has the requested target (or any target if no index).
    """
    cmd = f"timeout {FWVERSION_TIMEOUT} cpoutil show {component} fwversion"
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
    cpoutil processes the targets of "all" sequentially, so the timeout scales
    with the number of ELS.
    """
    timeout = FW_OP_TIMEOUT[op]
    if str(target) == "all":
        timeout *= len(cpoutil_show_fwversion(duthost, "els"))
    cmd = f"timeout {timeout} cpoutil firmware {op} els {target}"
    if fw_path:
        cmd += f" --raw {fw_path}"
    return duthost.command(cmd)["stdout"]


def cpoutil_reset_interface(duthost, port):
    """Reset the CPO virtual module serving <port> and return stdout."""
    return duthost.command(f"timeout {RESET_TIMEOUT} sudo cpoutil config interface reset {port}")["stdout"]


def stop_xcvrd(duthost):
    """Stop xcvrd so it does not access the modules (I2C contention)."""
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
    """Return the front-panel ports served by ELS <index> (Ethernet<32*index>..+31)."""
    first, last = ELS_LANES * index, ELS_LANES * (index + 1)
    ports = []
    for line in duthost.command("show interfaces status")["stdout_lines"]:
        name = line.split()[0] if line.strip() else ""
        if name.startswith("Ethernet") and name[8:].isdigit() and first <= int(name[8:]) < last:
            ports.append(name)
    assert ports, f"No ports found for ELS{index} (Ethernet{first}..Ethernet{last - 1})"
    return ports


def verify_traffic_between_ports(ptfadapter, duthost, mg_facts, src_port, dst_port):
    """Send one IPv4 packet from the PTF port of src_port, routed by the DUT to
    the neighbor of dst_port, and verify it arrives on the PTF port of dst_port.
    """
    # Imported here so the module can be loaded without the PTF packages.
    import ptf.testutils as testutils
    from ptf import mask, packet

    peer_ip = None
    for pc in mg_facts["minigraph_portchannel_interfaces"]:
        members = mg_facts["minigraph_portchannels"].get(pc["attachto"], {}).get("members", [])
        if dst_port in members and "." in pc["peer_addr"]:
            peer_ip = pc["peer_addr"]
            break
    assert peer_ip, f"No IPv4 neighbor found behind {dst_port}"

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

    logger.info(
        f"Sending packet from {src_port} (ptf {src_ptf}) to {peer_ip} via {dst_port} (ptf {dst_ptf})"
    )
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_ptf, pkt)
    testutils.verify_packet(ptfadapter, exp_pkt, dst_ptf, timeout=5)


# A non-interactive shell starts "&" jobs with SIGINT ignored, so a plain
# background cpoutil would ignore "kill -INT". This wrapper restores the
# default SIGINT handling and then execs the command in the same process.
_SIGINT_DEFAULT_EXEC = (
    "python3 -c 'import os, signal, sys; "
    "signal.signal(signal.SIGINT, signal.SIG_DFL); "
    "os.execvp(sys.argv[1], sys.argv[1:])'"
)


def start_firmware_background(duthost, op, index, fw_path, reset_sigint=False):
    """Start cpoutil firmware <op> els <index> --raw <fw_path> in background.
    Returns the PID; output goes to /tmp/cpoutil_bg_<index>.log.

    reset_sigint: allow interrupting the process with "kill -INT".
    """
    cmd = f"cpoutil firmware {op} els {index} --raw {fw_path}"
    if reset_sigint:
        cmd = f"{_SIGINT_DEFAULT_EXEC} {cmd}"
    pid = duthost.shell(f"nohup {cmd} > /tmp/cpoutil_bg_{index}.log 2>&1 & echo $!")["stdout"].strip()
    assert pid.isdigit(), f"Failed to start background {op} on ELS{index}, got pid '{pid}'"
    logger.info(f"Started background {op} on ELS{index}, pid={pid}")
    return pid


def wait_for_process(duthost, pid, timeout_sec=FW_OP_TIMEOUT["upgrade"]):
    """Wait for a process on the DUT to exit; fail if it is still running after timeout_sec."""
    duthost.shell(f"timeout {timeout_sec} tail --pid={pid} -f /dev/null", module_ignore_errors=True)
    still_running = duthost.shell(f"kill -0 {pid}", module_ignore_errors=True)["rc"] == 0
    assert not still_running, f"Process {pid} still running after {timeout_sec}s"


def read_background_log(duthost, index):
    """Return the output of a background firmware process."""
    return duthost.shell(f"cat /tmp/cpoutil_bg_{index}.log", module_ignore_errors=True)["stdout"]


def is_firmware_lock_held(duthost, lock_name):
    """Check whether a firmware lock is held by another process.

    The lock file is never removed, so its existence proves nothing. flock
    exits with FLOCK_BUSY_RC only when the lock is held; other failures, such
    as a lock file that does not exist yet, are not "held".
    """
    lock_file = f"{FIRMWARE_LOCK_DIR}/{lock_name}.lock"
    result = duthost.shell(f"sudo flock -n -x -E {FLOCK_BUSY_RC} {lock_file} true", module_ignore_errors=True)
    return result["rc"] == FLOCK_BUSY_RC


def cleanup_background_logs(duthost):
    """Remove the output files of background firmware processes."""
    duthost.shell("sudo rm -f /tmp/cpoutil_bg_*.log")
