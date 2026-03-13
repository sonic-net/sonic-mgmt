import logging
import pytest

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    ptf_grpc, ptf_gnoi, setup_gnoi_tls_server
)
from tests.common.helpers.upgrade_helpers import (
    GnoiUpgradeConfig,
    perform_gnoi_upgrade_smartswitch_dpu,
    perform_gnoi_upgrade_smartswitch_dpus_parallel,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('smartswitch'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


def _build_dpu_metadata(dpu_index: int):
    return [
        ("x-sonic-ss-target-type", "dpu"),
        ("x-sonic-ss-target-index", str(dpu_index)),
    ]


@pytest.fixture(scope="module")
def smartswitch_gnoi_upgrade_lists(request):
    """
    Same style as tests/upgrade_path/test_upgrade_gnoi.py:
      - upgrade_type: warm/cold -> passed into cfg.upgrade_type (helper maps to reboot method)
      - target_image_list: used for TransferToRemote remote_download.path
      - target_version: used for SetPackage package.version
    SmartSwitch-only:
      - ss_target_index: single DPU index
      - ss_target_indices: comma-separated list for parallel
      - ss_dut_image_path: local_path on DPU
      - ss_reboot_ready_timeout: wait for gNOI Time back
      - ss_max_workers: thread count for parallel
    """
    upgrade_type = request.config.getoption("upgrade_type")          # "warm" / "cold"
    from_image = request.config.getoption("base_image_list")
    to_image = request.config.getoption("target_image_list")
    to_version = request.config.getoption("target_version")

    ss_target_index = request.config.getoption("ss_target_index")          # int
    ss_target_indices = request.config.getoption("ss_target_indices")      # "0,1,2,3"
    ss_reboot_ready_timeout = 600
    ss_max_workers = request.config.getoption("ss_max_workers")

    ss_dut_image_path = "/var/tmp/sonic_image.bin"

    # defaults
    if ss_target_index in (None, ""):
        ss_target_index = 0
    if not ss_reboot_ready_timeout:
        ss_reboot_ready_timeout = 1200

    parsed_indices = None
    if ss_target_indices:
        parsed_indices = [int(x.strip()) for x in ss_target_indices.split(",") if x.strip()]
        if not parsed_indices:
            parsed_indices = None

    return (
        upgrade_type,
        from_image,
        to_image,
        to_version,
        ss_dut_image_path,
        int(ss_target_index),
        parsed_indices,
        int(ss_reboot_ready_timeout),
        int(ss_max_workers) if ss_max_workers else None,
    )


@pytest.mark.device_type("smartswitch")
def test_upgrade_one_dpu_via_gnoi(
    localhost, duthosts, ptfhost, enum_rand_one_per_hwsku_hostname,
    tbinfo, request,
    smartswitch_gnoi_upgrade_lists, ptf_gnoi  # noqa: F811
):
    """
    SmartSwitch: upgrade ONE DPU via gNOI (plaintext + DPU routing headers).
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    (
        upgrade_type, from_image, to_image, to_version,
        dut_image_path, dpu_index, _, reboot_ready_timeout, _
    ) = smartswitch_gnoi_upgrade_lists

    assert to_image, "target_image_list must be set (used as TransferToRemote remote_download.path)"
    assert to_version, "target_version must be set (used as SetPackage package.version)"

    logger.info("SmartSwitch DPU gNOI upgrade: from=%s to=%s version=%s dpu_index=%s",
                from_image, to_image, to_version, dpu_index)

    # Best-effort cleanup (may run on NPU; harmless)
    duthost.shell(f"rm -f {dut_image_path}", module_ignore_errors=True)

    cfg = GnoiUpgradeConfig(
        to_image=to_image,
        dut_image_path=dut_image_path,
        upgrade_type=upgrade_type,
        protocol="HTTP",
        allow_fail=False,
        to_version=to_version,
        metadata=_build_dpu_metadata(dpu_index),
        ss_reboot_ready_timeout=reboot_ready_timeout,
        ss_reboot_message="Rebooting DPU for maintenance (gNOI upgrade)",
    )

    perform_gnoi_upgrade_smartswitch_dpu(
        duthost=duthost,
        tbinfo=tbinfo,
        ptf_gnoi=ptf_gnoi,
        cfg=cfg,
    )


@pytest.mark.device_type("smartswitch")
def test_upgrade_multiple_dpus_via_gnoi_parallel(
    localhost, duthosts, ptfhost, enum_rand_one_per_hwsku_hostname,
    tbinfo, request,
    smartswitch_gnoi_upgrade_lists, ptf_gnoi  # noqa: F811
):
    """
    SmartSwitch: upgrade MULTIPLE DPUs via gNOI in parallel.

    This test is skipped unless --ss-target-indices is provided
    to avoid accidentally upgrading many DPUs.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    (
        upgrade_type, from_image, to_image, to_version,
        dut_image_path, _, dpu_indices, reboot_ready_timeout, max_workers
    ) = smartswitch_gnoi_upgrade_lists

    if not dpu_indices:
        pytest.skip("--ss-target-indices not set; skipping parallel multi-DPU gNOI upgrade")

    assert to_image, "target_image_list must be set"
    assert to_version, "target_version must be set"

    workers = max_workers or len(dpu_indices)

    logger.info("SmartSwitch DPU gNOI parallel upgrade: to=%s version=%s dpu_indices=%s workers=%s",
                to_image, to_version, dpu_indices, workers)

    # Build one cfg per DPU (NO override logic in helper)
    cfgs = []
    for idx in dpu_indices:
        cfgs.append(GnoiUpgradeConfig(
            to_image=to_image,
            dut_image_path=dut_image_path,
            upgrade_type=upgrade_type,
            protocol="HTTP",
            allow_fail=False,
            to_version=to_version,
            metadata=_build_dpu_metadata(idx),
            ss_reboot_ready_timeout=reboot_ready_timeout,
            ss_reboot_message="Rebooting DPU for maintenance (gNOI upgrade parallel)",
        ))

    perform_gnoi_upgrade_smartswitch_dpus_parallel(
        duthost=duthost,
        tbinfo=tbinfo,
        ptf_gnoi=ptf_gnoi,
        cfgs=cfgs,
        max_workers=workers,
    )
