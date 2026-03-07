import logging
import re
import pytest
from multiprocessing.pool import ThreadPool
from tests.common.reboot import reboot_ss_ctrl_dict as reboot_dict, REBOOT_TYPE_HISTOYR_QUEUE, \
    sync_reboot_history_queue_with_dut, execute_reboot_smartswitch_command
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_UNKNOWN = "unknown"
REBOOT_TYPE_KERNEL_PANIC = "Kernel Panic"
REBOOT_TYPE_WATCHDOG = "Watchdog"

# gNOI DPU reboot constants (ptf_gnoi-based, metadata for SmartSwitch routing)
SS_TARGET_TYPE_HDR = "x-sonic-ss-target-type"
SS_TARGET_INDEX_HDR = "x-sonic-ss-target-index"
_GNOI_DPU_REBOOT_MESSAGE = "gNOI cold reboot test"
_GNOI_DPU_REBOOT_READINESS_TIMEOUT_SEC = 300
_GNOI_DPU_REBOOT_READINESS_INTERVAL_SEC = 15
_GNOI_REBOOT_CONNECTION_DROP_TERMS = (
    "unavailable", "connection reset", "eof",
    "transport closing", "broken pipe",
)


def _build_smartswitch_metadata(target_type, target_index):
    return [(SS_TARGET_TYPE_HDR, str(target_type)), (SS_TARGET_INDEX_HDR, str(target_index))]


def _check_gnoi_time_ready(ptf_gnoi, metadata):
    """Returns True if gNOI System.Time succeeds (DPU reachable via NPU)."""
    try:
        ptf_gnoi.system_time(metadata=metadata)
        return True
    except Exception:
        return False


def perform_gnoi_reboot_dpu(ptf_gnoi, dpu_index, dpu_name, method="COLD",
                            message=_GNOI_DPU_REBOOT_MESSAGE,
                            timeout=_GNOI_DPU_REBOOT_READINESS_TIMEOUT_SEC):
    """
    Performs a gNOI cold reboot on a DPU via NPU (ptf_gnoi with metadata).
    PTF connects to NPU gRPC; NPU routes to DPU based on metadata headers.
    """
    md = _build_smartswitch_metadata("dpu", dpu_index)
    logger.info("Initiating gNOI reboot for DPU %s (index=%d) via ptf_gnoi", dpu_name, dpu_index)
    try:
        ptf_gnoi.system_reboot(method=method, delay=0, message=message, metadata=md)
    except Exception as e:
        if any(t in str(e).lower() for t in _GNOI_REBOOT_CONNECTION_DROP_TERMS):
            logger.info("Reboot initiated (connection drop expected): %s", e)
        else:
            logger.error("gNOI reboot failed for %s: %s", dpu_name, e)
            return False
    logger.info("Waiting for %s (index=%d) to come back online (timeout=%ds)...",
                dpu_name, dpu_index, timeout)
    came_up = wait_until(timeout, _GNOI_DPU_REBOOT_READINESS_INTERVAL_SEC, 0,
                         _check_gnoi_time_ready, ptf_gnoi, md)
    if not came_up:
        logger.error("%s did not come back online within %ds after gNOI reboot", dpu_name, timeout)
        return False
    logger.info("gNOI reboot complete: %s is back online", dpu_name)
    return True


def log_and_perform_reboot(duthost, reboot_type, dpu_name):
    """
    Logs and initiates the reboot process based on the host type.
    Skips the test if the host is a DPU.

    @param duthost: DUT host object
    @param reboot_type: Type of reboot to perform
    @param dpu_name: Name of the DPU (optional)
    """
    hostname = duthost.hostname

    if reboot_type == REBOOT_TYPE_COLD:
        if duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_smartswitch"):
            if dpu_name is None:
                logger.info("Sync reboot cause history queue with DUT reboot cause history queue")
                sync_reboot_history_queue_with_dut(duthost)

                with ThreadPool(processes=1) as pool:
                    async_result = pool.apply_async(execute_reboot_smartswitch_command,
                                                    (duthost, reboot_type, hostname))
                    pool.terminate()

                return {"failed": False,
                        "result": async_result}

            else:
                logger.info("Rebooting the DPU {} with type {}".format(dpu_name, reboot_type))
                return duthost.command("sudo reboot -d {}".format(dpu_name))
        elif duthost.facts['is_dpu']:
            pytest.skip("Skipping the reboot test as the DUT is a DPU")
    else:
        pytest.skip("Skipping the reboot test as the reboot type {} is not supported".format(reboot_type))


def perform_reboot(duthost,
                   reboot_type=REBOOT_TYPE_COLD,
                   dpu_name=None,
                   invocation_type="cli_based",
                   ptf_gnoi=None):
    """
    Performs a reboot and validates the DPU status after reboot.

    @param duthost: DUT host object
    @param reboot_type: Reboot type
    @param dpu_name: DPU name
    @param invocation_type: "cli_based" or "gnoi_based"
    @param ptf_gnoi: PtfGnoi client (required when invocation_type is "gnoi_based")
    """
    if reboot_type not in reboot_dict:
        pytest.skip("Skipping the reboot test as the reboot type {} is not supported".format(reboot_type))

    if invocation_type == "gnoi_based":
        if dpu_name is None:
            pytest.skip("gNOI-based reboot is not yet supported for switch-level reboot")
        if ptf_gnoi is None:
            pytest.skip("ptf_gnoi is required for gNOI-based reboot")
        logger.info(
            "[gNOI] perform_reboot: dpu_name=%s reboot_type=%s",
            dpu_name, reboot_type,
        )
        dpu_index = int(re.search(r'\d+', dpu_name).group())
        success = perform_gnoi_reboot_dpu(ptf_gnoi, dpu_index, dpu_name)
        if not success:
            pytest.fail("gNOI cold reboot failed for DPU {}".format(dpu_name))
        return

    # cli_based path
    res = log_and_perform_reboot(duthost, reboot_type, dpu_name)
    if res.get('failed', res.get('rc', 0) != 0):
        if dpu_name is None:
            pytest.fail("Failed to reboot the {} with type {}".format(duthost.hostname, reboot_type))
        else:
            pytest.fail("Failed to reboot the DPU {} with type {}".format(dpu_name, reboot_type))

    if dpu_name is None:
        logger.info("Appending the last reboot type to the queue")
        REBOOT_TYPE_HISTOYR_QUEUE.append(reboot_type)
