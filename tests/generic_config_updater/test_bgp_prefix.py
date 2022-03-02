import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_failure, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t0'),  #TODO: t0?
]

logger = logging.getLogger(__name__)

PREFIXES_V4_INIT  = "10.20.0.0/16"
PREFIXES_V6_INIT  = "fc01:20::/64"
PREFIXES_V4_DUMMY = "10.30.0.0/16"
PREFIXES_V6_DUMMY = "fc01:30::/64"

PREFIXES_V4_RE    = "ip prefix-list PL_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_empty_V4 seq \d+ permit {}"
PREFIXES_V6_RE    = "ipv6 prefix-list PL_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_empty_V6 seq \d+ permit {}"

@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for bgp prefix config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)

def bgp_prefix_test_setup(duthost):
    """ Clean up bgp prefix config before test
    """
    cmds = 'sonic-db-cli CONFIG_DB del "BGP_ALLOWED_PREFIXES|DEPLOYMENT_ID|0"'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "bgp prefix test setup failed."
    )

def show_bgp_running_config(duthost):
    return duthost.shell("show runningconfiguration bgp")['stdout']

def bgp_prefix_tc1_add_config(duthost):
    """ Test to add prefix config
    """
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_ALLOWED_PREFIXES",
            "value": {
                "DEPLOYMENT_ID|0": {
                    "prefixes_v4": [
                        PREFIXES_V4_INIT
                    ],
                    "prefixes_v6": [
                        PREFIXES_V6_INIT
                    ]
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(re.search(PREFIXES_V4_RE.format(PREFIXES_V4_INIT), bgp_config),
            "Failed to add bgp prefix v4 config."
        )
        pytest_assert(re.search(PREFIXES_V6_RE.format(PREFIXES_V6_INIT), bgp_config),
            "Failed to add bgp prefix v6 config."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)

def bgp_prefix_tc1_xfail(duthost):
    """ Test input with invalid prefixes
    """
    xfail_input = [
        ("add", "10.256.0.0/16", PREFIXES_V6_DUMMY),     # Invalid v4 prefix
        ("add", PREFIXES_V4_DUMMY, "fc01:xyz::/64"),     # Invalid v6 prefix
        ("remove", PREFIXES_V4_DUMMY, PREFIXES_V6_INIT), # Unexisted v4 prefix
        ("remove", PREFIXES_V4_INIT, PREFIXES_V6_DUMMY)  # Unexisted v6 prefix
    ]
    for op, prefixes_v4, prefixes_v6 in xfail_input:
        json_patch = [
            {
                "op": op,
                "path": "/BGP_ALLOWED_PREFIXES",
                "value": {
                    "DEPLOYMENT_ID|0": {
                        "prefixes_v4": [
                            prefixes_v4
                        ],
                        "prefixes_v6": [
                            prefixes_v6
                        ]
                    }
                }
            }
        ]

        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_failure(output)

        finally:
            delete_tmpfile(duthost, tmpfile)

def bgp_prefix_tc1_replace(duthost):
    """ Test to replace prefixes
    """
    json_patch = [
        {
            "op": "replace",
            "path": "/BGP_ALLOWED_PREFIXES/DEPLOYMENT_ID|0/prefixes_v6/0",
            "value": PREFIXES_V6_DUMMY
        },
        {
            "op": "replace",
            "path": "/BGP_ALLOWED_PREFIXES/DEPLOYMENT_ID|0/prefixes_v4/0",
            "value": PREFIXES_V4_DUMMY
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(
            not re.search(PREFIXES_V4_RE.format(PREFIXES_V4_INIT), bgp_config) and
            re.search(PREFIXES_V4_RE.format(PREFIXES_V4_DUMMY), bgp_config),
            "Failed to replace bgp prefix v4 config."
        )
        pytest_assert(
            not re.search(PREFIXES_V6_RE.format(PREFIXES_V6_INIT), bgp_config) and
            re.search(PREFIXES_V6_RE.format(PREFIXES_V6_DUMMY), bgp_config),
            "Failed to replace bgp prefix v6 config."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)

def bgp_prefix_tc1_remove(duthost):
    """ Test to remove prefix config
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_ALLOWED_PREFIXES"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(
            not re.search(PREFIXES_V4_RE.format(PREFIXES_V4_DUMMY), bgp_config),
            "Failed to remove bgp prefix v4 config."
        )
        pytest_assert(
            not re.search(PREFIXES_V6_RE.format(PREFIXES_V6_DUMMY), bgp_config),
            "Failed to remove bgp prefix v6 config."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)

def test_bgp_prefix_tc1_suite(duthost):
    """  Test suite for bgp prefix for v4 and v6
    """
    bgp_prefix_test_setup(duthost)
    bgp_prefix_tc1_add_config(duthost)
    bgp_prefix_tc1_xfail(duthost)
    bgp_prefix_tc1_replace(duthost)
    bgp_prefix_tc1_remove(duthost)
