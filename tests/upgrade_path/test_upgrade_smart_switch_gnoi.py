import logging
import random
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('smartswitch'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def rand_one_dpu_index_0_5():
    """Random DPU index in [0, 5] (inclusive)."""
    return random.randint(0, 5)


def _dpu_time_ready(ptf_gnoi, idx: int) -> bool:
    """Probe DPU readiness via gNOI System.Time."""
    try:
        resp = ptf_gnoi.system_time(ss_dpu_index=idx)
        return isinstance(resp, dict) and "time" in resp
    except Exception:
        return False


@pytest.mark.device_type("smartswitch")
def test_smartswitch_single_dpu_cold_reboot_via_gnoi(
    localhost,
    duthosts,
    ptfhost,
    rand_one_dut_hostname,
    nbrhosts,
    fanouthosts,
    tbinfo,
    request,
    restore_image,         # noqa: F811
    verify_dut_health,     # noqa: F811
    ptf_gnoi,
    rand_one_dpu_index_0_5,
):
    """
    SmartSwitch: single DPU cold reboot via gNOI.

    - Pre: System.Time succeeds on target DPU (selected via SmartSwitch metadata headers)
    - Action: System.Reboot(method=COLD)
    - Post: System.Time succeeds again (DPU is back)
    - Optional: Time value changed (best-effort sanity)
    """
    duthost = duthosts[rand_one_dut_hostname]
    dpu_index = rand_one_dpu_index_0_5

    logger.info("Selected DUT=%s, DPU index=%s", duthost.hostname, dpu_index)

    # 1) Precheck: Time must work
    pre = ptf_gnoi.system_time(ss_dpu_index=dpu_index)
    logger.info("Pre-reboot Time(DPU=%s): %s", dpu_index, pre)
    pytest_assert(isinstance(pre, dict) and "time" in pre, f"Pre-reboot Time failed: {pre}")
    pre_time = pre.get("time")

    # 2) Trigger cold reboot (connection drop / non-JSON output may happen)
    try:
        resp = ptf_gnoi.system_reboot(
            method="COLD",
            delay_ns=0,
            message="Rebooting DPU for maintenance",
            force=False,
            ss_dpu_index=dpu_index,
        )
        logger.info("Reboot(COLD) resp(DPU=%s): %s", dpu_index, resp)
    except Exception as e:
        # grpcurl may timeout/disconnect or return non-JSON during reboot, which is often expected
        logger.info("Reboot(COLD) call exception (often expected during reboot): %s", e)

    # 3) Wait for DPU back via Time probe
    pytest_assert(
        wait_until(900, 15, 0, _dpu_time_ready, ptf_gnoi, dpu_index),
        f"DPU index {dpu_index} did not become reachable via Time after cold reboot"
    )

    # 4) Postcheck: Time must work
    post = ptf_gnoi.system_time(ss_dpu_index=dpu_index)
    logger.info("Post-reboot Time(DPU=%s): %s", dpu_index, post)
    pytest_assert(isinstance(post, dict) and "time" in post, f"Post-reboot Time failed: {post}")

    # Optional best-effort sanity: time changed
    post_time = post.get("time")
    if pre_time is not None and post_time is not None:
        pytest_assert(
            post_time != pre_time,
            f"Time did not change across reboot (pre={pre_time}, post={post_time})"
        )
