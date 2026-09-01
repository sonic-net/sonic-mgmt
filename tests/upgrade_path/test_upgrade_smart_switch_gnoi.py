import logging
from collections import namedtuple

import pytest

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    gnmi_tls, ptf_grpc, ptf_gnoi, setup_gnoi_tls_server, reprovision_gnoi_tls
)
from tests.common.helpers.upgrade_helpers import (
    GnoiUpgradeConfig,
    perform_gnoi_upgrade,
    perform_gnoi_upgrade_smartswitch_dpu,
    perform_gnoi_upgrade_smartswitch_dpus_parallel,
)
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.device_utils import resolve_upgrade_dpu_indices

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


# Unified parameter set shared by all SmartSwitch upgrade tests.
#   DPU image/version : --target_image_list / --target_version
#   NPU image/version : --ss_npu_target_image / --ss_npu_target_version
#   ss_target_index   : single DPU index (default 3)
#   dpu_indices       : DPU indices to upgrade (--ss_target_indices if given, else admin-up DPUs from CONFIG_DB)
SmartSwitchUpgradeParams = namedtuple("SmartSwitchUpgradeParams", [
    "upgrade_type",
    "from_image",
    "dpu_to_image",
    "dpu_to_version",
    "npu_to_image",
    "npu_to_version",
    "dut_image_path",
    "ss_target_index",
    "dpu_indices",
    "reboot_ready_timeout",
    "max_workers",
])


@pytest.fixture(scope="module")
def smartswitch_upgrade_params(request, duthost):
    """Unified parameters for all SmartSwitch upgrade tests.

    DPU indices come from the explicit --ss_target_indices option when provided;
    otherwise they are the admin-up DPU indices discovered from the CONFIG_DB
    DPU(S) table (parsed from the actual DPU identities).
    """
    ss_target_index = request.config.getoption("ss_target_index")
    if ss_target_index in (None, ""):
        ss_target_index = 3

    ss_max_workers = request.config.getoption("ss_max_workers")

    ss_target_indices = request.config.getoption("ss_target_indices")
    # Explicit --ss_target_indices wins; otherwise auto-discover admin-up DPUs from CONFIG_DB.
    dpu_indices = resolve_upgrade_dpu_indices(duthost, ss_target_indices)
    logger.debug("smartswitch_upgrade_params: dpu_indices=%s", dpu_indices)

    return SmartSwitchUpgradeParams(
        upgrade_type=request.config.getoption("upgrade_type"),
        from_image=request.config.getoption("base_image_list"),
        dpu_to_image=request.config.getoption("target_image_list"),
        dpu_to_version=request.config.getoption("target_version"),
        npu_to_image=request.config.getoption("ss_npu_target_image"),
        npu_to_version=request.config.getoption("ss_npu_target_version"),
        dut_image_path="/var/tmp/sonic_image.bin",
        ss_target_index=int(ss_target_index),
        dpu_indices=dpu_indices,
        reboot_ready_timeout=600,
        max_workers=int(ss_max_workers) if ss_max_workers else None,
    )


@pytest.mark.device_type("smartswitch")
def test_upgrade_one_dpu_via_gnoi(
    localhost, duthosts, ptfhost, enum_rand_one_per_hwsku_hostname,
    tbinfo, request,
    smartswitch_upgrade_params, ptf_gnoi  # noqa: F811
):
    """
    SmartSwitch: upgrade ONE DPU via gNOI (plaintext + DPU routing headers).
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    p = smartswitch_upgrade_params
    upgrade_type = p.upgrade_type
    from_image = p.from_image
    to_image = p.dpu_to_image
    to_version = p.dpu_to_version
    dut_image_path = p.dut_image_path
    dpu_index = p.ss_target_index
    reboot_ready_timeout = p.reboot_ready_timeout

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
        ss_target_index=dpu_index,
        metadata=_build_dpu_metadata(dpu_index),
        ss_reboot_ready_timeout=reboot_ready_timeout,
        ss_reboot_message="Rebooting DPU for maintenance (gNOI upgrade)",
    )

    perform_gnoi_upgrade_smartswitch_dpu(
        duthost=duthost,
        tbinfo=tbinfo,
        ptf_gnoi=ptf_gnoi,
        cfg=cfg,
        localhost=localhost,
        duthosts=duthosts,
    )


@pytest.mark.device_type("smartswitch")
def test_upgrade_multiple_dpus_via_gnoi_parallel(
    localhost, duthosts, ptfhost, enum_rand_one_per_hwsku_hostname,
    tbinfo, request,
    smartswitch_upgrade_params, ptf_gnoi  # noqa: F811
):
    """
    SmartSwitch: upgrade MULTIPLE DPUs via gNOI in parallel.

    This test is skipped unless --ss-target-indices is provided
    to avoid accidentally upgrading many DPUs.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    p = smartswitch_upgrade_params
    upgrade_type = p.upgrade_type
    to_image = p.dpu_to_image
    to_version = p.dpu_to_version
    dut_image_path = p.dut_image_path
    dpu_indices = p.dpu_indices
    reboot_ready_timeout = p.reboot_ready_timeout
    max_workers = p.max_workers

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
            ss_target_index=idx,
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
        localhost=localhost,
        duthosts=duthosts,
    )


@pytest.mark.device_type("smartswitch")
def test_upgrade_smartswitch_all_dpus_then_npu(
    localhost, duthosts, ptfhost, enum_rand_one_per_hwsku_hostname,
    tbinfo, conn_graph_facts, xcvr_skip_list, request,
    smartswitch_upgrade_params, gnmi_tls  # noqa: F811
):
    """
    Full SmartSwitch upgrade: stage all DPUs first, then upgrade the NPU.

    Phase 1 - Stage image on all DPUs in parallel (no reboot):
              Each DPU gets TransferToRemote + SetPackage with skip_reboot=True.

    Phase 2 - Upgrade the NPU:
              TransferToRemote + SetPackage + Reboot on the NPU.
              The NPU reboot also reboots all DPUs automatically.

    Phase 3 - Wait for all DPUs to come back up.

    Required CLI args:
      --target_image_list       DPU image URL
      --target_version          DPU version string
      --ss_npu_target_image     NPU image URL
      --ss_npu_target_version   NPU version string
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    p = smartswitch_upgrade_params
    upgrade_type = p.upgrade_type
    dpu_to_image = p.dpu_to_image
    dpu_to_version = p.dpu_to_version
    npu_to_image = p.npu_to_image
    npu_to_version = p.npu_to_version
    dpu_indices = p.dpu_indices
    reboot_ready_timeout = p.reboot_ready_timeout
    dut_image_path = p.dut_image_path

    if not dpu_indices:
        pytest.fail(
            "Could not determine DPU indices: CONFIG_DB DPU(S) table is empty or no "
            "configured DPU has a verifiable CHASSIS_MODULE admin_status of 'up', and "
            "--ss_target_indices was not provided. Pass e.g. --ss_target_indices=0,1,2,3"
        )

    assert dpu_to_image, "--target_image_list is required (DPU image URL)"
    assert npu_to_image, "--ss_npu_target_image is required (NPU image URL)"

    # ------------------------------------------------------------------
    # Phase 1: Stage image on all DPUs in parallel (no reboot yet).
    # skip_reboot=True means only TransferToRemote + SetPackage run.
    # The DPUs will reboot in Phase 2 when the NPU reboots.
    # ------------------------------------------------------------------
    logger.info("Phase 1: Staging image on all %d DPUs (no reboot)", len(dpu_indices))

    dpu_cfgs = [
        GnoiUpgradeConfig(
            to_image=dpu_to_image,
            dut_image_path=dut_image_path,
            upgrade_type=upgrade_type,
            to_version=dpu_to_version,
            metadata=_build_dpu_metadata(idx),
            ss_reboot_ready_timeout=reboot_ready_timeout,
            skip_reboot=True,
        )
        for idx in dpu_indices
    ]
    perform_gnoi_upgrade_smartswitch_dpus_parallel(
        duthost=duthost,
        tbinfo=tbinfo,
        ptf_gnoi=gnmi_tls.gnoi,
        cfgs=dpu_cfgs,
        max_workers=len(dpu_indices),
    )
    logger.info("Phase 1 complete: image staged on all DPUs")

    # ------------------------------------------------------------------
    # Phase 2: Upgrade the NPU.
    # NPU reboot automatically reboots all DPUs.
    # perform_gnoi_upgrade waits for the NPU to come back before returning.
    # ------------------------------------------------------------------
    logger.info("Phase 2: Upgrading NPU (will also reboot all DPUs)")

    npu_cfg = GnoiUpgradeConfig(
        to_image=npu_to_image,
        dut_image_path=dut_image_path,
        upgrade_type=upgrade_type,
        to_version=npu_to_version,
        ss_reboot_ready_timeout=reboot_ready_timeout,
    )
    perform_gnoi_upgrade(
        ptf_gnoi=gnmi_tls.gnoi,
        duthost=duthost,
        tbinfo=tbinfo,
        cfg=npu_cfg,
        localhost=localhost,
        conn_graph_facts=conn_graph_facts,
        xcvr_skip_list=xcvr_skip_list,
        duthosts=duthosts,
    )
    logger.info("Phase 2 complete: NPU is back up")

    # NPU rebooted into a new image — its gNMI is no longer using our certs.
    # Re-provision before talking to the NPU/DPU gNOI in Phase 3.
    reprovision_gnoi_tls(duthost, ptfhost)

    # ------------------------------------------------------------------
    # Phase 3: Wait for each DPU to come back up.
    # Since the NPU reboot also reboots all DPUs, they should come up
    # shortly after the NPU. We poll gNOI System.Time per DPU to confirm.
    # ------------------------------------------------------------------
    logger.info("Phase 3: Waiting for all DPUs to come back up")

    for idx in dpu_indices:
        logger.info("Waiting for DPU %d...", idx)
        ok = wait_until(reboot_ready_timeout, 10, 0, gnmi_tls.gnoi.system_time,
                        metadata=_build_dpu_metadata(idx))
        pytest_assert(ok, "DPU {} did not come back up within {}s after NPU reboot".format(idx, reboot_ready_timeout))
        logger.info("DPU %d is back up", idx)

    logger.info("Phase 3 complete: all %d DPUs are back up", len(dpu_indices))
