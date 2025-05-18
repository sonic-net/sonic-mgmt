import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0', 't1', 'm0', 'mx', 'm1', 'm2', 'm3'),
]

logger = logging.getLogger(__name__)

NEXTHOP_GROUP_TOTAL = 256

SKU_NEXTHOP_THRESHOLDS = {
    'arista-720dt-g48s4': 15,
    'nokia-m0-7215': 126,
    'nokia-7215-a1': 126,
    'nokia-7215': 126,
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

    nexthop_group_threshold = SKU_NEXTHOP_THRESHOLDS.get(hwsku, DEFAULT_NEXTHOP_THRESHOLD)

    resource_name = "nexthop_group"
    if resource_name in crm_resources:
        used = crm_resources[resource_name]["used"]
        available = crm_resources[resource_name]["available"]
        total = used + available
        pytest_assert(total >= nexthop_group_threshold,
                      f"next-hop groups ({total}) should be greater than or equal to {nexthop_group_threshold} on platform '{hwsku}'") # noqa
    else:
        pytest.fail(f"Resource '{resource_name}' not found in CRM resources output on platform '{hwsku}'.")
