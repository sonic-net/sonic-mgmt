"""
Test to verify that BGP-learned routes in APPL_DB ROUTE_TABLE have the
'weight' attribute set for their nexthops.

Addresses test gap issue #18208.

Without the weight attribute, weighted ECMP cannot function correctly
as routes may be added to the ASIC without any weight for their nexthops.
"""
import logging
import json
import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2'),
    pytest.mark.device_type('vs')
]

CHECK_SCRIPT = """\
import json, subprocess, sys

result = subprocess.run(
    ['sonic-db-cli', 'APPL_DB', 'keys', 'ROUTE_TABLE:*'],
    capture_output=True, text=True
)
all_keys = [k for k in result.stdout.strip().split('\\n') if k]

af = sys.argv[1]  # 'ipv4' or 'ipv6'
checked = 0
missing = []
mismatched = []
sample = None

for key in all_keys:
    prefix = key.replace('ROUTE_TABLE:', '')
    if af == 'ipv4':
        if ':' in prefix or prefix == '0.0.0.0/0' or prefix.startswith('169.254.'):
            continue
    else:
        if ':' not in prefix or prefix == '::/0' or prefix.lower().startswith('fe80'):
            continue

    r = subprocess.run(
        ['sonic-db-cli', 'APPL_DB', 'hgetall', key],
        capture_output=True, text=True
    )
    # Parse the python dict string output
    try:
        entry = eval(r.stdout.strip())
    except Exception:
        continue

    if entry.get('protocol') != 'bgp':
        continue

    checked += 1
    weight = entry.get('weight', '')
    nexthop = entry.get('nexthop', '')

    if not weight:
        missing.append(prefix)
    elif nexthop:
        nh_count = len(nexthop.split(','))
        w_count = len(weight.split(','))
        if nh_count != w_count:
            mismatched.append({
                'prefix': prefix,
                'nh_count': nh_count,
                'w_count': w_count
            })

    if sample is None and weight:
        sample = {'prefix': prefix, 'weight': weight, 'nexthop': nexthop}

    # Check up to 50 BGP routes
    if checked >= 50:
        break

print(json.dumps({
    'checked': checked,
    'missing': missing[:10],
    'mismatched': mismatched[:10],
    'sample': sample
}))
"""


def _run_weight_check(duthost, asic, address_family):
    """Run the weight check script on the DUT and return results."""
    # Write script to DUT and execute
    asic.shell("cat > /tmp/check_weight.py << 'PYEOF'\n{}\nPYEOF".format(
        CHECK_SCRIPT))
    output = asic.shell(
        "python3 /tmp/check_weight.py {}".format(address_family))['stdout'].strip()
    asic.shell("rm -f /tmp/check_weight.py")

    result = json.loads(output)
    logger.info("%s: checked %d BGP routes", address_family, result['checked'])

    if result.get('sample'):
        logger.info(
            "Sample route: %s weight=%s nexthop=%s",
            result['sample']['prefix'],
            result['sample']['weight'],
            result['sample']['nexthop'])

    return result


def test_bgp_route_weight_ipv4(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                               enum_frontend_asic_index):
    """Verify that IPv4 BGP-learned routes have the 'weight' attribute set
    in APPL_DB ROUTE_TABLE.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)

    result = _run_weight_check(duthost, asic, 'ipv4')

    assert result['checked'] > 0, "No IPv4 BGP-learned routes found in APPL_DB ROUTE_TABLE"

    assert not result['missing'], (
        "IPv4 BGP routes missing 'weight' attribute: {}".format(result['missing'])
    )

    assert not result['mismatched'], (
        "IPv4 BGP routes with weight/nexthop count mismatch: {}".format(
            result['mismatched'])
    )

    logger.info("All %d sampled IPv4 BGP routes have valid weight attributes",
                result['checked'])


def test_bgp_route_weight_ipv6(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                               enum_frontend_asic_index):
    """Verify that IPv6 BGP-learned routes have the 'weight' attribute set
    in APPL_DB ROUTE_TABLE.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)

    result = _run_weight_check(duthost, asic, 'ipv6')

    assert result['checked'] > 0, "No IPv6 BGP-learned routes found in APPL_DB ROUTE_TABLE"

    assert not result['missing'], (
        "IPv6 BGP routes missing 'weight' attribute: {}".format(result['missing'])
    )

    assert not result['mismatched'], (
        "IPv6 BGP routes with weight/nexthop count mismatch: {}".format(
            result['mismatched'])
    )

    logger.info("All %d sampled IPv6 BGP routes have valid weight attributes",
                result['checked'])
