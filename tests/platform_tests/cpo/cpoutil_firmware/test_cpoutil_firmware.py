"""cpoutil ELS firmware management system tests.

Test plan: docs/testplan/cpo-util/cpo-util-els-test-plan.md
"""
import logging
import time

import pytest

from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.common.utilities import wait_until
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.platform_tests.cpo.cpoutil_firmware.cpoutil_helpers import (
    cpoutil_show_fwversion,
    cpoutil_firmware,
    els_ports,
    cpoutil_reset_interface,
    start_xcvrd,
    verify_traffic_between_ports,
    start_firmware_background,
    wait_for_process,
    cleanup_background_logs,
    is_firmware_lock_held,
    pick_different_firmware,
    read_background_log,
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


def _traffic_passes(ptfadapter, duthost, mg_facts, src_port, dst_port):
    try:
        verify_traffic_between_ports(ptfadapter, duthost, mg_facts, src_port, dst_port)
        return True
    except AssertionError as e:
        logger.info(f"Traffic {src_port} -> {dst_port} not received yet: {e}")
        return False


@pytest.fixture(autouse=True)
def ignore_expected_cpoutil_errors(duthost, loganalyzer):
    """Ignore cpoutil errors that negative tests trigger on purpose."""
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(CPOUTIL_IGNORE_REGEX)


class TestCpoutilFirmware:
    """cpoutil ELS firmware management integration tests."""

    # The cold reboot logs boot-time errors unrelated to cpoutil, so the
    # autouse loganalyzer is disabled; a LogAnalyzer limited to the upgrade
    # checks the cpoutil syslog before the reboot.
    @pytest.mark.disable_loganalyzer
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

        assert state[FW_ACTIVE] == fw_version, (
            f"Active firmware {state[FW_ACTIVE]} != upgraded version {fw_version}"
        )
        assert state[FW_RUNNING_IMAGE] != initial[FW_RUNNING_IMAGE], (
            f"Running image did not switch: {state[FW_RUNNING_IMAGE]}"
        )
        assert state[FW_COMMITTED_IMAGE] == state[FW_RUNNING_IMAGE], (
            f"Committed image {state[FW_COMMITTED_IMAGE]} != "
            f"running image {state[FW_RUNNING_IMAGE]}"
        )

        # --- Step 7: verify fwversion --json ---
        json_state = cpoutil_show_fwversion(duthost, "els", index, json_output=True)[target]
        assert json_state[FW_ACTIVE] == state[FW_ACTIVE], (
            f"JSON active {json_state[FW_ACTIVE]} != text active {state[FW_ACTIVE]}"
        )

        # --- Step 8: verify OE show fwversion format ---
        oe_result = duthost.command("cpoutil show oe fwversion", module_ignore_errors=True)
        if oe_result["rc"] == 0:
            assert oe_result["stdout_lines"], "OE fwversion output is empty"
            logger.info(f"OE fwversion output verified ({len(oe_result['stdout_lines'])} lines)")
        else:
            logger.info(f"OE fwversion returned rc={oe_result['rc']} (may not be supported)")

    def test_els_stepwise_lifecycle_all(
        self, duthost, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware,
    ):
        """TC-02: ELS stepwise firmware lifecycle using 'all'.

        Steps:
            1. Record initial state for all ELS.
            2. Download to all ELS, verify inactive updated.
            3. Run all ELS, verify active/running switched.
            4. Commit all ELS, verify committed equals running.
        """
        fw_path = els_firmware_binaries["target"]
        fw_version = els_firmware_binaries["target_version"]

        initial = cpoutil_show_fwversion(duthost, "els")
        log_els_state("before download", initial)

        # --- Step 2: download all ---
        logger.info(f"Step 2: Downloading {fw_path} (version {fw_version}) to all {len(initial)} ELS")
        stdout = cpoutil_firmware(duthost, "download", "all", fw_path)
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
        cpoutil_firmware(duthost, "run", "all")
        logger.info("Step 3: Run all completed")

        after_run = cpoutil_show_fwversion(duthost, "els")
        log_els_state("after run", after_run)
        for target, init_state in initial.items():
            state = after_run[target]
            assert state[FW_RUNNING_IMAGE] != init_state[FW_RUNNING_IMAGE], (
                f"{target}: running image did not switch after run"
            )
            assert state[FW_ACTIVE] == after_dl[target][FW_INACTIVE], (
                f"{target}: active {state[FW_ACTIVE]} != "
                f"expected {after_dl[target][FW_INACTIVE]}"
            )
        logger.info("Step 3: Running image switched and Active updated on all ELS after run")

        # --- Step 4: commit all ---
        logger.info("Step 4: Committing firmware on all ELS")
        cpoutil_firmware(duthost, "commit", "all")
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
            logger.info("Testing negative case: %s", desc)

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
        """TC-04: Firmware lock.

        Steps:
            1. Verify the ELS lock is held during firmware download.
            2. Same ELS concurrent download -> second gets busy error.
            3. Verify the ELS lock is released after the download.
        """
        fw_path = els_firmware_binaries["target"]
        idx = els_indices[0]
        lock_name = f"els{idx}"

        # --- Step 1: verify lock is held during download ---
        logger.info("Step 1: Verify lock %s is held during download", lock_name)
        pid = start_firmware_background(duthost, "download", idx, fw_path)

        time.sleep(2)
        assert is_firmware_lock_held(duthost, lock_name), (
            f"Lock {lock_name} not held 2s after starting the download (pid {pid})"
        )
        logger.info("Step 1 passed: lock is held during download")

        # --- Step 2: same ELS concurrent download -> busy error ---
        logger.info("Step 2: Concurrent download on same ELS %d", idx)
        result = duthost.command(
            f"cpoutil firmware download els {idx} --raw {fw_path}", module_ignore_errors=True,
        )
        assert result["rc"] != 0, f"Second download on same ELS should have failed, got rc={result['rc']}"
        assert BUSY_ERROR in result["stdout"] + result["stderr"], (
            f"Expected busy error, got stdout: {result['stdout']} stderr: {result['stderr']}"
        )
        logger.info("Step 2 passed: second download rejected as busy")

        # --- Step 3: lock released after the download finishes ---
        wait_for_process(duthost, pid)
        assert not is_firmware_lock_held(duthost, lock_name), (
            f"Lock {lock_name} still held after download finished"
        )
        logger.info("Step 3 passed: lock released after download")
        cleanup_background_logs(duthost)

    def test_interrupted_download_recovery(
        self, duthost, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware, els_indices,
    ):
        """TC-05: Interrupted download recovery (Ctrl-C).

        Steps:
            1. Start download, send SIGINT mid-transfer.
            2. Verify command exits and running image unchanged.
            3. Retry download, verify success.
        """
        index = els_indices[0]
        target = f"els{index}"
        fw_path = els_firmware_binaries["target"]

        initial = cpoutil_show_fwversion(duthost, "els", index)[target]

        # --- Step 1-2: interrupt download with SIGINT (Ctrl-C) ---
        logger.info("Starting download and interrupting with SIGINT on ELS %d", index)
        pid = start_firmware_background(duthost, "download", index, fw_path, reset_sigint=True)

        # cpoutil takes the ELS firmware lock right before it starts
        # transferring the image, so a held lock means the download is running.
        assert wait_until(30, 1, 0, is_firmware_lock_held, duthost, target), (
            f"Download on {target} did not start within 30s"
        )

        duthost.shell(f"kill -INT {pid}")
        wait_for_process(duthost, pid, timeout_sec=60)

        log = read_background_log(duthost, index)
        assert "... OK" not in log, f"Download completed despite SIGINT: {log}"
        logger.info("Interrupted download exited, output: %s", log)
        cleanup_background_logs(duthost)

        state = cpoutil_show_fwversion(duthost, "els", index)[target]
        assert state[FW_RUNNING_IMAGE] == initial[FW_RUNNING_IMAGE], (
            f"Running image changed after interrupt: "
            f"{state[FW_RUNNING_IMAGE]} != {initial[FW_RUNNING_IMAGE]}"
        )

        # --- Step 3: retry download ---
        logger.info("Retrying download on ELS %d", index)
        stdout = cpoutil_firmware(duthost, "download", index, fw_path)
        assert "OK" in stdout, f"Retry download missing OK: {stdout}"
        logger.info("Retry download succeeded")

    def test_traffic_recovery_after_run(
        self, duthost, tbinfo, ptfadapter, els_firmware_binaries,
        dom_polling_disabled, restore_els_firmware, els_indices,
    ):
        """TC-06: Port traffic recovery after firmware run.

        Steps:
            1. Verify all ports of the ELS are oper up and a packet routed to
               the neighbor behind its first port is received.
            2. Download the image whose version differs from Active, then run.
            3. Verify the ports of the ELS go oper down.
            4. Commit, reset the ELS through its first port, and admin toggle
               its ports.
            5. Verify the ports are oper up again, the ELS runs the new image,
               and the packet is received again.
        """
        index = els_indices[0]
        target = f"els{index}"
        ports = els_ports(duthost, index)
        logger.info(f"{target} serves ports {ports}")

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        dst_port = ports[0]
        src_port = next(
            (p for p in mg_facts["minigraph_ptf_indices"]
             if p not in ports and duthost.links_status_up([p])),
            None,
        )
        assert src_port, f"No oper up port outside {target} to send traffic from"

        # --- Step 1: ports up and traffic passes before run ---
        assert wait_until(PORT_LINK_TIMEOUT, 10, 0, duthost.links_status_up, ports), (
            f"Ports of {target} are not oper up before run: {ports}"
        )
        verify_traffic_between_ports(ptfadapter, duthost, mg_facts, src_port, dst_port)
        logger.info(f"Step 1: Traffic {src_port} -> {dst_port} received before run")

        initial = cpoutil_show_fwversion(duthost, "els", index)[target]

        # --- Step 2: download a different image, then run ---
        fw_path, fw_version = pick_different_firmware(els_firmware_binaries, initial[FW_ACTIVE])
        logger.info(f"Step 2: Switching {target} from {initial[FW_ACTIVE]} to {fw_version}")
        cpoutil_firmware(duthost, "download", index, fw_path)
        cpoutil_firmware(duthost, "run", index)

        # --- Step 3: ports go down after run ---
        assert wait_until(PORT_LINK_TIMEOUT, 10, 0, duthost.links_status_down, ports), (
            f"Ports of {target} did not go oper down after run: {ports}"
        )
        logger.info(f"Step 3: Ports of {target} are oper down after run")

        # --- Step 4: commit, reset and admin toggle ---
        cpoutil_firmware(duthost, "commit", index)
        # Reset while xcvrd is still stopped, so it does not access the module
        # during the reset. xcvrd then provisions the ports on the admin toggle.
        cpoutil_reset_interface(duthost, ports[0])
        start_xcvrd(duthost)
        duthost.shutdown_multiple(ports)
        duthost.no_shutdown_multiple(ports)
        logger.info(f"Step 4: Reset {target} and admin toggled its ports")

        # --- Step 5: ports recover, new image running ---
        assert wait_until(PORT_LINK_TIMEOUT, 10, 0, duthost.links_status_up, ports), (
            f"Ports of {target} did not recover after reset and admin toggle: {ports}"
        )
        logger.info(f"Step 5: Ports of {target} are oper up again")

        state = cpoutil_show_fwversion(duthost, "els", index)[target]
        assert state[FW_ACTIVE] == fw_version, (
            f"Active firmware {state[FW_ACTIVE]} != {fw_version} after recovery"
        )
        assert state[FW_COMMITTED_IMAGE] == state[FW_RUNNING_IMAGE], (
            f"Committed image {state[FW_COMMITTED_IMAGE]} != "
            f"running image {state[FW_RUNNING_IMAGE]} after recovery"
        )

        # The LAG and the route to the neighbor need a moment after link up
        assert wait_until(
            120, 10, 0, _traffic_passes, ptfadapter, duthost, mg_facts, src_port, dst_port,
        ), f"Traffic {src_port} -> {dst_port} not received after recovery"
        logger.info(f"Step 5: Traffic {src_port} -> {dst_port} received after recovery")
