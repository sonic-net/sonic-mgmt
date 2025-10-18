import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0', 't1', 'm0', 'mx', 'm1'),
]

logger = logging.getLogger(__name__)

NEXTHOP_GROUP_TOTAL = 256

SKU_NEXTHOP_THRESHOLDS = {
    'arista-720dt-g48s4': 15,
    'nokia-m0-7215': 126,
    'nokia-7215-a1': 126,
    'nokia-7215': 126,
    'arista-7050cx3-32s-c28s4': 255,
    'Arista-7050CX3-32S-C32': 255,
    'arista-7050cx3-32s-s128': 255,
    'arista-7050cx3-32s-c6s104': 255,
    'arista-7050cx3-32s-c28s16': 255,
    'arista-7050cx3-32c-c28s4': 255,
    'Arista-7050CX3-32c-C32': 255,
    'arista-7050cx3-32c-s128': 255,
    'arista-7050cx3-32c-c6s104': 255,
    'arista-7050cx3-32c-c28s16': 255,
}

DEFAULT_NEXTHOP_THRESHOLD = 256


def test_crm_next_hop_group(duthosts, enum_rand_one_per_hwsku_frontend_hostname, crm_resources):
    """
    test that runs `crm show resources` and parses next-hop group usage.
    """
    # Example check: ensure next-hop group usage is below a certain threshold
    # This is a placeholder for the actual resource name; adjust as needed
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    hwsku = duthost.facts["hwsku"].lower()
    lower_sku_nexthop_thresholds = {k.lower(): v for k, v in SKU_NEXTHOP_THRESHOLDS.items()}
    nexthop_group_threshold = lower_sku_nexthop_thresholds.get(hwsku, DEFAULT_NEXTHOP_THRESHOLD)

    resource_name = "nexthop_group"
    if resource_name in crm_resources:
        used = crm_resources[resource_name]["used"]
        available = crm_resources[resource_name]["available"]
        total = used + available
        pytest_assert(total >= nexthop_group_threshold,
                      f"next-hop groups ({total}) should be greater than or equal to {nexthop_group_threshold} on platform '{hwsku}'") # noqa
    else:
        pytest.fail(f"Resource '{resource_name}' not found in CRM resources output on platform '{hwsku}'.")
