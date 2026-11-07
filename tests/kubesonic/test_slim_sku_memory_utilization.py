import logging

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

# Maximum allowed RAM utilization (in percent) for slim SKU devices. Kubesonic
# brings up an on-device kubelet and runs daemonset pods, which increases the
# memory footprint. Slim SKUs are the memory-constrained platforms that run the
# slim image, so we require their baseline utilization to stay under this
# threshold to leave enough headroom for the kubesonic workload.
MEMORY_UTILIZATION_THRESHOLD_PERCENT = 60

# HwSKUs that run the slim image. These are the memory-constrained platforms for
# which the kubesonic memory headroom needs to be validated. Any device whose
# HwSKU is in this list is treated as a slim SKU device.
SLIM_HWSKUS = [
    "Arista-7050-QX-32S",
    "Arista-7050-Q16S64",
    "Arista-7050QX-32S-S4Q31",
    "Arista-7050QX32S-Q32",
    "Celestica-E1031-T48S4",
]


def get_dut_hwsku(duthost):
    """Return the HwSKU of the DUT, falling back to sonic-cfggen if facts miss it."""
    hwsku = duthost.facts.get("hwsku") if hasattr(duthost, "facts") else None
    if not hwsku:
        result = duthost.shell("sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku",
                               module_ignore_errors=True)
        hwsku = result.get("stdout", "").strip()
    return hwsku


def is_slim_sku(duthost):
    """Return True if the DUT is a slim SKU device."""
    return get_dut_hwsku(duthost) in SLIM_HWSKUS


def get_memory_utilization_percent(duthost):
    """Compute RAM utilization (percent) on the DUT from /proc/meminfo.

    Utilization is (MemTotal - MemAvailable) / MemTotal * 100, matching the
    computation used by the dut_monitor plugin.
    """
    meminfo = duthost.shell("cat /proc/meminfo")["stdout"]
    total_mem_in_kb = None
    available_mem_in_kb = None
    for line in meminfo.splitlines():
        if line.startswith("MemTotal"):
            total_mem_in_kb = int(line.split()[1])
        elif line.startswith("MemAvailable"):
            available_mem_in_kb = int(line.split()[1])

    pytest_assert(total_mem_in_kb, "Failed to read MemTotal from /proc/meminfo")
    pytest_assert(available_mem_in_kb is not None,
                  "Failed to read MemAvailable from /proc/meminfo")

    used_mem_in_kb = total_mem_in_kb - available_mem_in_kb
    used_percent = used_mem_in_kb * 100.0 / total_mem_in_kb
    logger.info(
        f"Memory utilization: {used_percent:.2f}% "
        f"(total={total_mem_in_kb} kB, available={available_mem_in_kb} kB)")
    return used_percent


def test_slim_sku_memory_utilization(duthost):
    """Ensure memory utilization on slim SKU devices stays under the threshold.

    On slim SKU (memory-constrained) devices, verify that the RAM utilization is
    under MEMORY_UTILIZATION_THRESHOLD_PERCENT of the available memory so there is
    enough headroom to run the kubesonic workload. The test is skipped on any
    device that is not a slim SKU.
    """
    hwsku = get_dut_hwsku(duthost)
    if not is_slim_sku(duthost):
        pytest.skip(f"HwSKU {hwsku} is not a slim SKU, skipping memory utilization check")

    logger.info(f"Checking memory utilization on slim SKU device with HwSKU {hwsku}")
    used_percent = get_memory_utilization_percent(duthost)
    pytest_assert(
        used_percent < MEMORY_UTILIZATION_THRESHOLD_PERCENT,
        f"Memory utilization {used_percent:.2f}% on slim SKU device {hwsku} "
        f"exceeds the {MEMORY_UTILIZATION_THRESHOLD_PERCENT}% threshold")
    logger.info(
        f"Memory utilization {used_percent:.2f}% is within the "
        f"{MEMORY_UTILIZATION_THRESHOLD_PERCENT}% threshold on slim SKU device {hwsku}")
