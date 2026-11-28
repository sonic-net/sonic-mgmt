"""Opt-in policy setup for the actual SetPackage download target."""

import re

import pytest

from tests.common.devices.duthosts import DutHosts
from tests.common.helpers.gnoi_download import temporary_image_policy, snapshot_download_hosts
from tests.common.utilities import get_duts_from_host_pattern


def _download_policy(dpus=()):
    hosts = snapshot_download_hosts(dpus)

    def configure(npu, image_url, metadata=None):
        host = npu
        target = dict(metadata or [])
        if target.get("x-sonic-ss-target-type") == "dpu":
            index = target.get("x-sonic-ss-target-index")
            if index is None or not str(index).isdigit():
                raise ValueError("DPU target index must be explicit")
            target_ip = npu.command(argv=[
                "sonic-db-cli", "STATE_DB", "HGET",
                "CHASSIS_MIDPLANE_TABLE|DPU{}".format(index), "ip_address",
            ])["stdout"].strip()
            if not target_ip:
                raise ValueError("DPU midplane address is unavailable")
            if target_ip not in hosts:
                raise ValueError("Cannot map SetPackage target to an inventory DPU")
            host = hosts[target_ip]
        return temporary_image_policy(host, image_url)
    return configure


@pytest.fixture
def gnoi_download_policy():
    """Return a context factory; do not keep test trust through a reboot."""
    return _download_policy()


@pytest.fixture
def gnoi_dpu_download_policy(request, ansible_adhoc, tbinfo, enhance_inventory):
    """Prepare only the test's selected targets before starting workers."""
    def prepare(npu, indices):
        indices = [int(index) for index in indices]
        if not indices:
            return _download_policy()
        if len(set(indices)) != len(indices):
            raise ValueError("Duplicate DPU target indices")
        pattern = request.config.getoption("--dpu-pattern")
        names = tbinfo["duts"] if pattern == "all" else (
            get_duts_from_host_pattern(pattern) if pattern not in (None, "", "None") else []
        )
        selected = {}
        for name in names:
            match = re.fullmatch(re.escape(npu.hostname) + r"[-_]dpu[-_]?(\d+)", name)
            if match and int(match.group(1)) in indices:
                index = int(match.group(1))
                if index in selected:
                    raise ValueError("Ambiguous DPU inventory index")
                selected[index] = name
        if set(selected) != set(indices):
            raise ValueError("Selected DPU indices are unavailable in the requested inventory")
        request.getfixturevalue("enable_nat_for_dpuhosts")
        dpus = DutHosts(ansible_adhoc, tbinfo, request, [selected[index] for index in indices])
        return _download_policy(dpus)
    return prepare
