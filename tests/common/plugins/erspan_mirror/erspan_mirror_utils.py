import logging
import time

from tests.common.helpers.constants import ERSPAN_GRE_TYPE

logger = logging.getLogger(__name__)


def add_erspan_mirror_session(duthost, session_name, src_port, dst_ip,
                              src_ip="1.1.1.1", dscp=8, ttl=64, queue=0,
                              direction="both"):
    """
    Create an ERSPAN mirror session on the DUT.

    Args:
        duthost: DUT host object
        session_name: Mirror session name
        src_port: DUT interface to mirror traffic from (e.g. "Ethernet224")
        dst_ip: Destination IP address to mirror traffic to
    """
    cmd = (
        f"config mirror_session erspan add {session_name} {src_ip} {dst_ip} "
        f"{dscp} {ttl} {ERSPAN_GRE_TYPE} {queue} {src_port} {direction}"
    )
    duthost.command(cmd)
    logger.info(
        f"Created ERSPAN mirror session '{session_name}' on {duthost.hostname} (src={src_port} dst={dst_ip})"
    )


def get_monitor_ptf_intf(duthost, session_name, tbinfo):
    """Resolve the PTF eth interface attached to the DUT-side monitor port."""
    time.sleep(1)
    monitor_port = duthost.shell(
        f"sonic-db-cli STATE_DB HGET 'MIRROR_SESSION_TABLE|{session_name}' 'monitor_port'"
    )["stdout"].strip()

    monitor_ptf_intf = None
    if monitor_port and tbinfo:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ptf_indices = mg_facts.get("minigraph_ptf_indices", {})
        idx = ptf_indices.get(monitor_port)
        if idx is not None:
            monitor_ptf_intf = f"eth{idx}"

    logger.info(
        f"Mirror session '{session_name}' monitor port: {monitor_port} (PTF {monitor_ptf_intf})"
    )
    return monitor_ptf_intf


def run_pcap(ptfhost, pcap_path, monitor_ptf_intf, tcpdump_filter):
    """Start a backgrounded tcpdump on the PTF monitor interface"""
    tcpdump_cmd = (
        f"nohup tcpdump -U -i {monitor_ptf_intf} -w {pcap_path} '{tcpdump_filter}' &"
    )
    ptfhost.shell(tcpdump_cmd)


def remove_mirror_session(duthost, session_name):
    """Remove a mirror session from the DUT."""
    duthost.command(f"config mirror_session remove {session_name}",
                    module_ignore_errors=True)
    logger.info(f"Removed mirror session '{session_name}' on {duthost.hostname}")
