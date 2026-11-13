"""cpoutil ELS firmware management system tests.

Test plan: docs/testplan/cpo-util/cpo-util-els-test-plan.md
"""
import ipaddress
import logging
import time

import pytest

from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.common.utilities import wait_until
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.cpo_utils import (
    cpoutil_show_fwversion,
    cpoutil_firmware,
    els_ports,
    assert_els_running,
    verify_traffic_between_ports,
    pick_different_firmware,
    start_xcvrd,
    FW_ACTIVE,
    FW_INACTIVE,
    FW_RUNNING_IMAGE,
    FW_COMMITTED_IMAGE,
    BUSY_ERROR,
    PORT_LINK_TIMEOUT,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]

# Errors that negative tests trigger on purpose (corrupted image, busy lock,
# interrupted download).
CPOUTIL_IGNORE_REGEX = [
    r".*ERR cpoutil: ELS firmware \w+ (failed|aborted) on ELS\d+.*",
    r".*ERR CdbFirmware: .*",
]


def log_els_state(stage, fwinfo):
    """Log Active/Inactive firmware and Running/Committed image of each ELS."""
    logger.info(f"ELS firmware state {stage}:")
    for target in sorted(fwinfo, key=lambda t: int(t[3:]) if t[3:].isdigit() else t):
        state = fwinfo[target]
        logger.info(
            f"  {target}: active={state.get(FW_ACTIVE)} inactive={state.get(FW_INACTIVE)} "
            f"running={state.get(FW_RUNNING_IMAGE)} committed={state.get(FW_COMMITTED_IMAGE)}"
        )


def _traffic_passes_all_ports(ptfadapter, duthost, mg_facts, src_port, dst_ports, count=10):
    """Send count packets to each dst_port. Return True if all pass."""
    try:
        for dst_port in dst_ports:
            verify_traffic_between_ports(ptfadapter, duthost, mg_facts, src_port, dst_port, count)
        return True
    except AssertionError as e:
        logger.info(f"Traffic check failed: {e}")
        return False


@pytest.fixture(autouse=True)
def ignore_expected_cpoutil_errors(duthost, loganalyzer):
    """Ignore cpoutil errors that negative tests trigger on purpose."""
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(CPOUTIL_IGNORE_REGEX)


class TestCpoutilFirmware:
    """cpoutil ELS firmware management integration tests."""

    # The cold reboot logs boot-time errors unrelated to cpoutil
    @pytest.mark.disable_loganalyzer
    @pytest.mark.disable_memory_utilization
    def test_els_firmware_upgrade_and_reboot(
        self, duthost, localhost, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware, els_indices,
    ):
        """TC-01: ELS firmware upgrade + reboot persistence + OE show fwversion.

        Steps:
            1. Record initial ELS firmware state.
            2. Upgrade one ELS to the image whose version differs from Active.
            3. Verify stdout OK message.
            4. Verify syslog started/completed NOTICE entries and no errors.
            5. Cold reboot DUT.
            6. Verify Active, Running and Committed image after reboot.
            7. Verify fwversion --json output matches text.
            8. Verify cpoutil show oe fwversion output format.
        """
        index = els_indices[0]
        target = f"els{index}"

        initial = cpoutil_show_fwversion(duthost, "els", index)[target]

        fw_path, fw_version = pick_different_firmware(els_firmware_binaries, initial[FW_ACTIVE])
        logger.info(f"Upgrading {target} from {initial[FW_ACTIVE]} to {fw_version}")

        # --- Step 2-3: upgrade and verify stdout ---
        upgrade_la = LogAnalyzer(ansible_host=duthost, marker_prefix="cpoutil_upgrade")
        upgrade_la.load_common_config()
        upgrade_la.expect_regex = [
            rf".*NOTICE cpoutil: ELS firmware upgrade started on ELS{index}\b.*",
            rf".*NOTICE cpoutil: ELS firmware upgrade completed on ELS{index}\b.*",
        ]
        upgrade_marker = upgrade_la.init()

        stdout = cpoutil_firmware(duthost, "upgrade", index, fw_path)
        assert "OK" in stdout, f"Upgrade stdout missing OK marker: {stdout}"

        # --- Step 4: verify syslog ---
        upgrade_la.analyze(upgrade_marker)

        # --- Step 5: cold reboot ---
        logger.info("Cold rebooting DUT to verify firmware persistence")
        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD)

        # --- Step 6: verify fwversion after reboot ---
        state = cpoutil_show_fwversion(duthost, "els", index)[target]
        assert_els_running(target, state, fw_version)
        assert state[FW_RUNNING_IMAGE] != initial[FW_RUNNING_IMAGE], (
            f"Running image did not switch: {state[FW_RUNNING_IMAGE]}"
        )

        # --- Step 7: verify fwversion --json ---
        json_state = cpoutil_show_fwversion(duthost, "els", index, json_output=True)[target]
        assert json_state[FW_ACTIVE] == state[FW_ACTIVE], (
            f"JSON active {json_state[FW_ACTIVE]} != text active {state[FW_ACTIVE]}"
        )

    def test_els_stepwise_lifecycle_all(
        self, duthost, tbinfo, ptfadapter, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware, els_indices,
    ):
        """TC-02: ELS stepwise firmware lifecycle using 'all', and traffic recovery.

        Steps:
            1. Record initial state for all ELS, verify 10 packets to each port.
            2. Download to all ELS, verify inactive updated.
            3. Run all ELS, verify active/running switched and the ports go down.
            4. Commit all ELS, verify committed equals running.
            5. Wait for ports to come back up.
            6. Verify 10 packets to each port are received again.
        """
        fw_path = els_firmware_binaries["target"]
        fw_version = els_firmware_binaries["target_version"]

        initial = cpoutil_show_fwversion(duthost, "els")
        log_els_state("before download", initial)

        # --- Step 1: baseline traffic to routable ELS ports ---
        all_ports = [p for idx in els_indices for p in els_ports(duthost, idx)]
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        # Filter ports that have IPv4 neighbors (routed or via PortChannel)
        pc_members = {
            m: pc["name"] for pc in mg_facts.get("minigraph_portchannels", {}).values() for m in pc["members"]
        }
        l3_intfs = {
            intf["attachto"] for intf in
            mg_facts["minigraph_interfaces"] + mg_facts["minigraph_portchannel_interfaces"]
            if ipaddress.ip_address(intf["peer_addr"]).version == 4
        }
        traffic_ports = [p for p in all_ports if p in l3_intfs or pc_members.get(p) in l3_intfs]
        assert traffic_ports, "No ELS ports with IPv4 neighbors found"

        src_port = next(
            (p for p in mg_facts["minigraph_ptf_indices"]
             if p not in all_ports and duthost.links_status_up([p])),
            None,
        )
        assert src_port, "No oper up port outside ELS ports to send traffic from"
        assert wait_until(
            120, 10, 0, _traffic_passes_all_ports, ptfadapter, duthost, mg_facts, src_port, traffic_ports,
        ), "Baseline traffic check failed"
        logger.info(f"Step 1: Traffic to {len(traffic_ports)}/{len(all_ports)} routable ports received")

        # --- Step 2: download all ---
        logger.info(f"Step 2: Downloading {fw_path} (version {fw_version}) to all {len(initial)} ELS")
        stdout = cpoutil_firmware(duthost, "download", "all", fw_path, )
        assert "OK" in stdout, f"Download stdout missing OK: {stdout}"
        logger.info("Step 2: Download all completed")

        after_dl = cpoutil_show_fwversion(duthost, "els")
        log_els_state("after download", after_dl)
        for target, init_state in initial.items():
            state = after_dl[target]
            assert state[FW_INACTIVE] == fw_version, (
                f"{target}: inactive {state[FW_INACTIVE]} != downloaded version {fw_version}"
            )
            assert state[FW_ACTIVE] == init_state[FW_ACTIVE], (
                f"{target}: active changed after download: "
                f"{state[FW_ACTIVE]} != {init_state[FW_ACTIVE]}"
            )
            assert state[FW_RUNNING_IMAGE] == init_state[FW_RUNNING_IMAGE], (
                f"{target}: running image changed after download"
            )
        logger.info("Step 2: Inactive is the downloaded version, Active and Running image unchanged on all ELS")

        # --- Step 3: run all ---
        logger.info("Step 3: Running firmware on all ELS")
        cpoutil_firmware(duthost, "run", "all", )
        logger.info("Step 3: Run all completed")

        after_run = cpoutil_show_fwversion(duthost, "els")
        log_els_state("after run", after_run)
        for target, init_state in initial.items():
            state = after_run[target]
            assert state[FW_RUNNING_IMAGE] != init_state[FW_RUNNING_IMAGE], (
                f"{target}: running image did not switch after run"
            )
            assert state[FW_ACTIVE] == fw_version, (
                f"{target}: active {state[FW_ACTIVE]} != downloaded version {fw_version}"
            )
        logger.info("Step 3: Running image switched and Active updated on all ELS after run")

        assert wait_until(PORT_LINK_TIMEOUT, 10, 0, duthost.links_status_down, all_ports), (
            "Ports of the ELS did not go oper down after run"
        )
        logger.info("Step 3: Ports of all ELS are oper down after run")

        # --- Step 4: commit all ---
        logger.info("Step 4: Committing firmware on all ELS")
        cpoutil_firmware(duthost, "commit", "all", )
        logger.info("Step 4: Commit all completed")

        after_commit = cpoutil_show_fwversion(duthost, "els")
        log_els_state("after commit", after_commit)
        for target in initial:
            state = after_commit[target]
            assert state[FW_COMMITTED_IMAGE] == state[FW_RUNNING_IMAGE], (
                f"{target}: committed {state[FW_COMMITTED_IMAGE]} != "
                f"running {state[FW_RUNNING_IMAGE]}"
            )
        logger.info("Step 4: Committed image equals Running image on all ELS after commit")

        # Start xcvrd so it can bring ports back up
        start_xcvrd(duthost)

        # --- Step 5: wait for routable ports to come back up ---
        if not wait_until(PORT_LINK_TIMEOUT, 10, 0, duthost.links_status_up, traffic_ports):
            down = duthost.show_interface(command="status", up_ports=traffic_ports)[
                "ansible_facts"]["ansible_interface_link_down_ports"]
            raise AssertionError(f"Ports not up after commit: {down}")
        logger.info(f"Step 5: {len(traffic_ports)} routable ports are oper up again")

        # --- Step 6: traffic recovers to routable ports ---
        assert wait_until(
            120, 10, 0, _traffic_passes_all_ports, ptfadapter, duthost, mg_facts, src_port, traffic_ports,
        ), "Traffic to some ports not received after recovery"
        logger.info(f"Step 6: Traffic to {len(traffic_ports)} routable ports received after recovery")

    def test_invalid_inputs_rejected(
        self, duthost, loganalyzer, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware, els_indices,
    ):
        """TC-03: Invalid inputs and corrupted firmware rejected.

        Steps:
            1. Record initial state.
            2. Test each invalid input, verify failure and state unchanged.
            3. The autouse loganalyzer verifies at teardown that the corrupted
               binary download logged its failure.
        """
        fw_path = els_firmware_binaries["target"]
        corrupted_path = els_firmware_binaries["corrupted"]
        first_index = els_indices[0]
        first_target = f"els{first_index}"

        if loganalyzer:
            loganalyzer[duthost.hostname].expect_regex.append(
                rf".*ERR cpoutil: ELS firmware download failed on ELS{first_index}\b.*"
            )

        initial = cpoutil_show_fwversion(duthost, "els", first_index)[first_target]

        test_cases = [
            (
                "Invalid index",
                f"cpoutil firmware download els 999 --raw {fw_path}",
            ),
            (
                "Missing --raw",
                "cpoutil firmware download els 0",
            ),
            (
                "Non-existent file",
                "cpoutil firmware download els 0 --raw /nonexistent/firmware.bin",
            ),
            (
                "Corrupted binary",
                f"cpoutil firmware download els {first_index} --raw {corrupted_path}",
            ),
        ]

        for desc, cmd in test_cases:
            logger.info(f"Testing negative case: {desc}")

            result = duthost.command(cmd, module_ignore_errors=True)
            assert result["rc"] != 0, (
                f"[{desc}] Expected non-zero rc, got rc={result['rc']}\n"
                f"stdout: {result['stdout']}\nstderr: {result['stderr']}"
            )
            logger.info(f"[{desc}] Command failed as expected (rc={result['rc']})")

            state = cpoutil_show_fwversion(duthost, "els", first_index)[first_target]
            assert state[FW_ACTIVE] == initial[FW_ACTIVE], (
                f"[{desc}] Active firmware changed: {state[FW_ACTIVE]} != {initial[FW_ACTIVE]}"
            )
            assert state[FW_RUNNING_IMAGE] == initial[FW_RUNNING_IMAGE], (
                f"[{desc}] Running image changed: "
                f"{state[FW_RUNNING_IMAGE]} != {initial[FW_RUNNING_IMAGE]}"
            )

    def test_firmware_lock(
        self, duthost, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware, els_indices,
    ):
        """TC-04: Concurrent firmware operations are rejected with busy error.

        Steps:
            1. Start a firmware download in the background.
            2. Attempt a concurrent download on the same ELS -> expect busy error.
            3. Wait for the background download to complete successfully.
        """
        fw_path = els_firmware_binaries["target"]
        idx = els_indices[0]

        logger.info(f"Starting background download on ELS {idx}")
        pool, async_result = duthost.shell(
            f"cpoutil firmware download els {idx} --raw {fw_path}",
            module_async=True,
        )
        try:
            time.sleep(3)
            assert not async_result.ready(), "Download finished too quickly to test concurrency"

            result = duthost.command(
                f"cpoutil firmware download els {idx} --raw {fw_path}",
                module_ignore_errors=True,
            )
            assert result["rc"] != 0 and BUSY_ERROR in result["stdout"] + result["stderr"], (
                f"Expected busy error, got rc={result['rc']} stdout={result['stdout']}"
            )
            logger.info("Concurrent download rejected as busy")

            download = async_result.get()
        finally:
            pool.terminate()
            pool.join()

        assert download["rc"] == 0, (
            f"Background download failed (rc={download['rc']}): {download['stdout']}"
        )

    def test_interrupted_download_recovery(
        self, duthost, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware, els_indices,
    ):
        """TC-05: Interrupted download recovery (Ctrl-C).

        Steps:
            1. Start download in background, send SIGINT after 3s.
            2. Verify running image unchanged.
            3. Retry download succeeds (lock released after interrupt).
        """
        index = els_indices[0]
        target = f"els{index}"
        fw_path = els_firmware_binaries["target"]

        initial = cpoutil_show_fwversion(duthost, "els", index)[target]

        # Start download in background with SIGINT handler restored
        logger.info(f"Starting download and interrupting with SIGINT on ELS {index}")
        sigint_wrapper = (
            "python3 -c 'import os, signal, sys; "
            "signal.signal(signal.SIGINT, signal.SIG_DFL); "
            "os.execvp(sys.argv[1], sys.argv[1:])'"
        )
        pid = duthost.shell(
            f"nohup {sigint_wrapper} cpoutil firmware download els {index} --raw {fw_path} "
            f"> /dev/null 2>&1 & echo $!"
        )["stdout"].strip()
        assert pid.isdigit(), f"Failed to start background download, got pid '{pid}'"

        time.sleep(3)
        assert duthost.shell(f"kill -0 {pid}", module_ignore_errors=True)["rc"] == 0, (
            "Download finished within 3s, cannot test interrupt"
        )
        duthost.shell(f"kill -INT {pid}")
        duthost.shell(f"timeout 60 tail --pid={pid} -f /dev/null", module_ignore_errors=True)

        state = cpoutil_show_fwversion(duthost, "els", index)[target]
        assert state[FW_RUNNING_IMAGE] == initial[FW_RUNNING_IMAGE], (
            "Running image changed after interrupt"
        )

        # Retry download to verify lock is released
        stdout = cpoutil_firmware(duthost, "download", index, fw_path)
        assert "OK" in stdout, f"Retry download failed: {stdout}"
        logger.info("Retry download succeeded after interrupt")
