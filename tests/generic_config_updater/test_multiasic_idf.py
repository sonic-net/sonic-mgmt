import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import (create_checkpoint, delete_checkpoint, rollback_or_reload)

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


def apply_patch_and_verify(duthost, json_patch, tmpfile):
    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    if output['rc'] or "Patch applied successfully" not in output['stdout']:
        err_msg = f"Patching failed: {output['stdout']}"
        logger.info(err_msg)
        pytest_assert(False, err_msg)
    return output


def verify_asic_state(duthost, asic_id, expected_state):
    cmds = (f'sonic-db-cli -n asic{asic_id} CONFIG_DB hget "BGP_DEVICE_GLOBAL|STATE" idf_isolation_state')
    redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
    pytest_assert(redis_value == expected_state, f"Config IDF ISOLATION failed for asic{asic_id}")


def verify_idf_status(duthost, expected_states):
    if duthost.facts['router_type'] != 'spinerouter':
        return
    status_output = duthost.shell("sudo idf_isolation status", module_ignore_errors=False)['stdout']

    if isinstance(expected_states, dict):
        expected_lines = [
            f"BGP{asic_id}: IDF isolation state: {state}"
            for asic_id, state in expected_states.items()
        ]
    else:
        expected_lines = expected_states

    for line in expected_lines:
        pytest_assert(
            line in status_output,
            f"IDF isolation status check failed: {line} not found"
        )


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """Setup/teardown fixture for each test"""
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)
    yield
    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture
def setup_tmpfile(duthost):
    """Fixture to handle tmpfile creation/cleanup"""
    tmpfile = generate_tmpfile(duthost)
    yield tmpfile
    delete_tmpfile(duthost, tmpfile)


test_params = [
    pytest.param(
        [],
        None,
        id="empty_patch"
    ),
    pytest.param(
        [
            {
                "op": "add",
                "path": "/asic0/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "isolated_no_export"
            },
            {
                "op": "add",
                "path": "/asic1/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "isolated_withdraw_all"
            }
        ],
        {
            0: "isolated_no_export",
            1: "isolated_withdraw_all"
        },
        id="basic_isolation"
    ),
    pytest.param(
        [
            {
                "op": "add",
                "path": f"/asic{i}/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "unisolated"
            }
            for i in [0, 1]
        ],
        {
            0: "unisolated",
            1: "unisolated"
        },
        id="unisolation"
    ),
    pytest.param(
        [
            {
                "op": "add",
                "path": f"/asic{i}/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "isolated_no_export"
            }
            for i in [0, 1]
        ],
        {
            0: "isolated_no_export",
            1: "isolated_no_export"
        },
        id="no_export_all"
    )
]


@pytest.mark.parametrize("json_patch,expected_states", test_params)
def test_idf_isolation_states(duthost, setup_tmpfile, json_patch, expected_states):
    """Parameterized test for various IDF isolation states"""
    tmpfile = setup_tmpfile

    # For basic isolation test, show current config
    if expected_states and 0 in expected_states:
        if (expected_states[0] == "isolated_no_export" and
                expected_states[1] == "isolated_withdraw_all"):
            logger.info("The current running config is:")
            logger.info(
                duthost.shell("show run all", module_ignore_errors=False)['stdout']
            )

    apply_patch_and_verify(duthost, json_patch, tmpfile)

    if expected_states:
        # Verify states for each ASIC
        for asic_id, expected_state in expected_states.items():
            verify_asic_state(duthost, asic_id, expected_state)
        # Verify type of expected_states
        pytest_assert(isinstance(expected_states, dict), "expected_states must be a dictionary")
        # Verify status output
        verify_idf_status(duthost, expected_states)


# Mixed states test cases
mixed_states_params = [
    # asic0: no_export, asic1: withdraw_all
    {
        "patch": [
            {
                "op": "add",
                "path": "/asic0/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "isolated_no_export"
            },
            {
                "op": "add",
                "path": "/asic1/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "isolated_withdraw_all"
            }
        ],
        "expected_states": {
            0: "isolated_no_export",
            1: "isolated_withdraw_all"
        }
    },
    # asic0: withdraw_all, asic1: no_export
    {
        "patch": [
            {
                "op": "add",
                "path": "/asic0/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "isolated_withdraw_all"
            },
            {
                "op": "add",
                "path": "/asic1/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
                "value": "isolated_no_export"
            }
        ],
        "expected_states": {
            0: "isolated_withdraw_all",
            1: "isolated_no_export"
        }
    }
]


@pytest.mark.parametrize("test_case", mixed_states_params)
def test_idf_isolation_mixed_states(duthost, setup_tmpfile, test_case):
    """Test different isolation states on different ASICs"""
    tmpfile = setup_tmpfile

    apply_patch_and_verify(duthost, test_case["patch"], tmpfile)

    # Verify states
    for asic_id, expected_state in test_case["expected_states"].items():
        verify_asic_state(duthost, asic_id, expected_state)

    # Verify status output
    verify_idf_status(duthost, test_case["expected_states"])
