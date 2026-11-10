"""Opt-in policy setup for the actual SetPackage download target."""

import pytest

from tests.common.helpers.gnoi_download import temporary_image_policy, select_download_host
from tests.common.platform.device_utils import get_dpu_ip


def _download_policy(dpus=()):
    def configure(npu, image_url, metadata=None):
        host = npu
        target = dict(metadata or [])
        if target.get("x-sonic-ss-target-type") == "dpu":
            index = target.get("x-sonic-ss-target-index")
            if index is None or not str(index).isdigit():
                raise ValueError("DPU target index must be explicit")
            target_ip = get_dpu_ip(npu, int(index))
            if not target_ip:
                raise ValueError("DPU midplane address is unavailable")
            host = select_download_host(dpus, target_ip)
        return temporary_image_policy(host, image_url)
    return configure


@pytest.fixture
def gnoi_download_policy():
    """Return a context factory; do not keep test trust through a reboot."""
    return _download_policy()


@pytest.fixture
def gnoi_dpu_download_policy(dpuhosts):
    """Initialize DPU fixtures before any parallel upgrade workers start."""
    return _download_policy(dpuhosts)
