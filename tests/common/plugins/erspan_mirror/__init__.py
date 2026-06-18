import json
import logging
import os
import re

import allure
import pytest

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.utilities import wait_until
from .erspan_mirror_utils import (
    add_erspan_mirror_session,
    get_monitor_ptf_intf,
    remove_mirror_session,
    run_pcap,
)

logger = logging.getLogger(__name__)


def _tcpdump_exited(host, pcap_path):
    res = host.shell(
        f"pgrep -f '[t]cpdump.*{pcap_path}'",
        module_ignore_errors=True,
    )
    return res.get("rc", 1) != 0


def pytest_addoption(parser):
    parser.addoption(
        "--enable-dpc-mirroring",
        action="store_true",
        default=False,
        help="Auto-create ERSPAN mirror sessions and PTF tcpdump captures around each test. "
             "Mirror targets are resolved via the 'erspan_mirror_targets' fixture.",
    )


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    """
    Attach the ERSPAN mirror fixture only when --enable-dpc-mirroring is set.
    """
    if not config.getoption("--enable-dpc-mirroring"):
        return
    for item in items:
        if "_erspan_mirror" not in item.fixturenames:
            item.fixturenames.append("_erspan_mirror")


@pytest.fixture
def erspan_mirror_targets(duthosts):
    """Default mirror targets: every NPU<->DPU midplane port on each DUT.

    Enumerates DPC ports straight from each DUT's ``platform.json`` so the
    capture set does not depend on ``--dpu-pattern`` ordering or on which
    DPUs a particular test happens to exercise. On non-smartswitch DUTs
    (no ``DPUS`` section) this returns ``[]`` and the plugin is a no-op.

    A package can override this fixture in its ``conftest.py`` to mirror a
    different set of ``(duthost, src_port)`` tuples.
    """
    targets = []
    for duthost in duthosts:
        platform = duthost.facts["platform"]
        platform_json = json.loads(
            duthost.shell(f"cat /usr/share/sonic/device/{platform}/platform.json")["stdout"]
        )
        for dpu_entry in (platform_json.get("DPUS") or {}).values():
            for dpc_port in ((dpu_entry or {}).get("interface") or {}).keys():
                targets.append((duthost, dpc_port))
    return targets


@pytest.fixture
def _erspan_mirror(request, ptfhost, tbinfo, erspan_mirror_targets):
    """
    For every (duthost, src_port) in `erspan_mirror_targets`:
      - create one ERSPAN mirror session,
      - start a tcpdump on the corresponding PTF monitor interface,
      - on teardown: stop tcpdump, strip ERSPAN headers, fetch pcaps,
        remove the mirror session.
    """
    targets = erspan_mirror_targets
    # sanitize test name so the pcap path has no spaces/brackets that would
    # break the tcpdump/editcap/pgrep shell commands that embed the path
    test_name = re.sub(r"[^\w.-]+", "_", request.node.name)
    # session name has length limit so keep only first 20 characters
    session_base_name = test_name[:20]
    sessions = []

    try:
        for n, target in enumerate(targets, start=1):
            duthost, src_port = target
            session_name = f"{session_base_name}_{n}"
            pcap_path = f"/tmp/{test_name}_{duthost.hostname}_{src_port}.pcap"
            dst_ip = f"2.2.2.{n}"
            tcpdump_filter = f"proto gre and dst {dst_ip}"

            # Register before any fail-able op, so the finally block cleans up
            # even if a later step (assert / pcap start) raises mid-setup.
            session = {
                "duthost": duthost,
                "session_name": session_name,
                "pcap_path": None,
            }
            sessions.append(session)

            add_erspan_mirror_session(duthost, session_name, src_port, dst_ip)
            monitor_ptf_intf = get_monitor_ptf_intf(duthost, session_name, tbinfo)
            pt_assert(
                monitor_ptf_intf,
                f"Failed to resolve monitor PTF interface for session {session_name}",
            )
            run_pcap(ptfhost, pcap_path, monitor_ptf_intf, tcpdump_filter)
            session["pcap_path"] = pcap_path

        yield
    finally:
        logger.info("erspan_mirror teardown")
        pcap_sessions = [s for s in sessions if s["pcap_path"]]
        for s in pcap_sessions:
            ptfhost.shell(
                f"pkill -SIGINT -f '[t]cpdump.*{s['pcap_path']}'",
                module_ignore_errors=True,
            )
        # Wait for all tcpdumps to exit
        for s in pcap_sessions:
            if not wait_until(5, 0.2, 0, _tcpdump_exited, ptfhost, s["pcap_path"]):
                logger.warning(f"tcpdump for {s['pcap_path']} did not exit within 5s")
        # Strip ERSPAN headers and fetch pcaps
        for s in pcap_sessions:
            stripped_pcap = s["pcap_path"].replace(".pcap", "_stripped.pcap")
            # Eth + IPv4 + GRE: 38 bytes, ERSPAN II: 22 bytes -> strip 60 bytes
            ptfhost.shell(
                f"editcap -C 60 {s['pcap_path']} {stripped_pcap}",
                module_ignore_errors=True,
            )
            ptfhost.fetch(src=stripped_pcap, dest="/tmp/", flat=True, fail_on_missing=False)
            local_stripped = os.path.join("/tmp", os.path.basename(stripped_pcap))
            if not os.path.exists(local_stripped):
                logger.warning(f"Could not attach pcap {local_stripped} - file not found")
                continue
            try:
                allure.attach.file(
                    local_stripped,
                    f"{os.path.basename(local_stripped)}",
                    allure.attachment_type.PCAP,
                )
            except Exception as e:
                logger.warning(f"Failed to attach pcap {local_stripped} to allure report: {e}")
        # Remove ERSPAN sessions
        for s in sessions:
            remove_mirror_session(s["duthost"], s["session_name"])
