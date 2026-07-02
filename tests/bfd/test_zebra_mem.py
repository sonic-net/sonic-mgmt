import re
import time
from datetime import datetime, timezone
import logging
import random
import threading

import pytest

from tests.bfd.bfd_helpers import extract_ip_addresses_for_backend_portchannels, batch_control_interface_state


pytestmark = [
    pytest.mark.topology("t2"),
    pytest.mark.disable_loganalyzer
]


logger = logging.getLogger(__name__)
POLL_SEC = 2


def _parse_zebra_status(text):
    """
    Return zebra state from `supervisorctl status` stdout, e.g. 'RUNNING', 'EXITED', etc.
    Raises ValueError if 'zebra' line not found.
    """
    for line in text.splitlines():
        m = re.match(r"^\s*zebra\s+([A-Z]+)\b", line)
        if m:
            return m.group(1)
    raise ValueError("zebra line not found in supervisorctl output")


def _abort_if_zebra_not_running(duthost, asic_index):
    res = duthost.shell("sudo docker exec bgp{} supervisorctl status".format(asic_index), module_ignore_errors=True)
    out = (res.get("stdout") or "").strip()
    try:
        zebra_state = _parse_zebra_status(out)
    except Exception:
        zebra_state = "UNKNOWN"

    if zebra_state != "RUNNING":
        logger.error("Zebra is not running, collecting show-tech before exiting!")
        # duthost.command("show techsupport --since yesterday", module_ignore_errors=True)
        pytest.fail("Zebra is not running (state={}) on {}:asic{}".format(zebra_state, duthost.hostname, asic_index))


def _monitor_zebra_mem(duthost, asic_index, stop_evt: threading.Event, label=""):
    # Avoid test failure if grep finds nothing
    cmd = 'sudo vtysh -n {} -c "show memory" | grep -A10 zebra || true'.format(asic_index)

    logger.info("[zebra-mem {}] monitor starting (interval={}s)".format(label, POLL_SEC))
    while not stop_evt.is_set():
        try:
            res = duthost.shell(cmd, module_ignore_errors=True)
            out = (res.get("stdout") or "").strip()
            ts = datetime.now(timezone.utc)
            if out:
                logger.info("[zebra-mem {}] {}\n{}".format(label, ts, out))
            else:
                logger.info("[zebra-mem {}] {} (no output)".format(label, ts))
        except Exception as e:
            logger.warning("[zebra-mem {}] error: {}".format(label, e))

        stop_evt.wait(POLL_SEC)
    logger.info("[zebra-mem {}] monitor stopped".format(label))


def test_zebra_mem(duthosts):
    dut_indices = random.sample(list(range(len(duthosts.frontend_nodes))), 2)
    src_dut_index = dut_indices[0]
    dst_dut_index = dut_indices[1]

    # Random selection of source asic based on number of asics available on source dut
    src_asic_index_selection = random.choice(
        duthosts.frontend_nodes[src_dut_index].get_asic_namespace_list()
    )
    src_asic_index = int(src_asic_index_selection.split("asic")[1])

    # Random selection of destination asic based on number of asics available on destination dut
    dst_asic_index_selection = random.choice(
        duthosts.frontend_nodes[dst_dut_index].get_asic_namespace_list()
    )
    dst_asic_index = int(dst_asic_index_selection.split("asic")[1])

    src_dut = duthosts.frontend_nodes[src_dut_index]
    dst_dut = duthosts.frontend_nodes[dst_dut_index]
    src_asic = src_dut.asics[src_asic_index]
    dst_asic = dst_dut.asics[dst_asic_index]

    src_dut_nexthops = (
        extract_ip_addresses_for_backend_portchannels(
            dst_dut, dst_asic, "ipv4"
        )
    )

    list_of_portchannels_on_dst = src_dut_nexthops.keys()

    # Start background zebra memory monitor BEFORE any toggling
    stop_evt = threading.Event()
    mon_label = "{}:asic{}".format(dst_dut.hostname, dst_asic_index)
    mon_thread = threading.Thread(
        target=_monitor_zebra_mem,
        args=(dst_dut, dst_asic_index, stop_evt, mon_label),
        daemon=True,
    )
    mon_thread.start()
    time.sleep(10)

    try:
        for i in range(5):
            logger.info("===== Iteration {}/5 =====".format(i + 1))
            logger.info("Right before shutdown of portchannels")
            batch_control_interface_state(dst_dut, dst_asic, list_of_portchannels_on_dst, "shutdown")

            logger.info("Shut down done, sleeping 20s to observe zebra memory…")
            for _ in range(180):  # check once per second during sleep
                time.sleep(1)
                _abort_if_zebra_not_running(dst_dut, dst_asic_index)

            logger.info("Bringing portchannels back up…")
            batch_control_interface_state(dst_dut, dst_asic, list_of_portchannels_on_dst, "startup")

            logger.info("Startup done, sleeping 20s before next iteration…")
            for _ in range(180):
                time.sleep(1)
                _abort_if_zebra_not_running(dst_dut, dst_asic_index)

        logger.info("All 5 iterations complete.")
    finally:
        # Always stop the monitor
        stop_evt.set()
        mon_thread.join(timeout=10)
        logger.info("Finishing up...")
