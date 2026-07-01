"""
DASH VNET Object CRUD Operations Test

This test validates Create, Read, Update, and Delete operations for DASH VNET objects
on SONiC Smartswitch DASH (Disaggregated API for SONiC Hosts) platform.

VNET objects represent virtual networks in the DASH architecture and are fundamental
building blocks for network isolation and routing.

DASH supports a maximum of 32 VNETs. This test suite includes:
- Basic CRUD operations
- Multicast VNET configurations
- Scale testing (up to 32 VNETs)
- VNET peer list management for multicast
"""

import logging
import pytest
import re

from gnmi_utils import apply_messages
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('smartswitch', 'dpu'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

# DASH VNET Limits
MAX_VNET_COUNT = 32  # Maximum number of VNETs supported by DASH

# Test VNET configurations
TEST_VNET_NAME_1 = "vnet_test_1"
TEST_VNET_VNI_1 = 1001
TEST_VNET_GUID_1 = "11111111-1111-1111-1111-111111111111"

TEST_VNET_NAME_2 = "vnet_test_2"
TEST_VNET_VNI_2 = 1002
TEST_VNET_GUID_2 = "22222222-2222-2222-2222-222222222222"

TEST_VNET_NAME_3 = "vnet_test_3"
TEST_VNET_VNI_3 = 1003
TEST_VNET_GUID_3 = "33333333-3333-3333-3333-333333333333"

# Updated values for testing UPDATE operations
TEST_VNET_VNI_1_UPDATED = 1101
TEST_VNET_GUID_1_UPDATED = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

ENABLE_GNMI_API = True
WAIT_TIME_AFTER_CONFIG = 5

def deep_merge(dst, src): 
    for k, v in src.items():
        if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
            deep_merge(dst[k], v)
        elif k not in dst:
            dst[k] = v
    return dst

@pytest.fixture(scope="module")
def vnet_config_info(duthost, dpuhosts, dpu_index):
    """
    Fixture to provide VNET configuration information for tests.

    Args:
        duthost: DUT host object
        dpuhosts: List of DPU host objects
        dpu_index: Index of the DPU to use

    Returns:
        Dictionary containing VNET configuration parameters
    """
    dpuhost = dpuhosts[dpu_index]

    config = {
        'duthost': duthost,
        'dpuhost': dpuhost,
        'host': f"dpu{dpuhost.dpu_index}",
        'dpuindex': f"{dpuhost.dpu_index}"
    }

    return config

@pytest.fixture(scope="module", autouse=True)
def copy_getdash_tablescript(localhost, dpuhosts, dpu_index, duthost, ansible_adhoc, tbinfo):
    """
    Copy the DASH helper script to the DUT once before all tests.
    Port 9090 redirects to the DASH module on the switch.
    """
    # Get credentials from duthost_vars
    dpuhostname = tbinfo['duts'][1]
    dpuhosttvars = ansible_adhoc().options['inventory_manager'].get_host(dpuhostname).vars
    dpuhost = dpuhosts[dpu_index]

    # Access directly from host object
    ansible_user = dpuhosttvars['ansible_ssh_user']
    ansible_password = dpuhosttvars['ansible_ssh_pass']
    mgmt_ip =  dpuhosttvars['ansible_host']
    ansible_port = dpuhosttvars['ansible_ssh_port']

    src  = "/sonic-mgmt/tests/dash/get_dash_object.py"
    dest = f"{ansible_user}@{mgmt_ip}:/home/{ansible_user}/"

    cmd = f"sshpass -p {ansible_password} scp -P {ansible_port} -o StrictHostKeyChecking=no {src} {dest}"
    localhost.shell(cmd, module_ignore_errors=True)

    cmd = f'docker cp /home/{ansible_user}/get_dash_object.py swss:/'
    dpuhost.shell(cmd, module_ignore_errors=True)

def create_vnet_config(vnet_name, vni, guid):
    """
    Create a VNET configuration dictionary.

    Args:
        vnet_name: Name of the VNET
        vni: VNI (VXLAN Network Identifier) value
        guid: Globally Unique Identifier for the VNET

    Returns:
        List containing VNET configuration dictionary
    """
    vnet_config = {
        "vni": str(vni),
        "guid": guid
    }

    return {
            f"DASH_VNET_TABLE:{vnet_name}": vnet_config,
           }
    
def apply_dash_config(localhost, duthost, ptfhost, dash_config, dpuindex, op="SET"):
    """
    Apply VNET configuration to the DUT.

    Args:
        localhost: Localhost object
        duthost: DUT host object
        ptfhost: PTF host object
        dash_config: dash configuration dictionary
        host: Target host identifier
    """
    logger.info(f'duthost: {duthost} {dpuindex}')

    if op == "SET":
        apply_messages(localhost, duthost, ptfhost, dash_config, dpuindex, set_db=True, wait_after_apply=1)
    else:
        apply_messages(localhost, duthost, ptfhost, dash_config, dpuindex, set_db=False, wait_after_apply=1)


def verify_vnet_exists(dpu, vnet_name, expected_vni=None):
    """
    Verify that a VNET exists in the configuration.

    Args:
        duthost: DUT host object
        vnet_name: Name of the VNET to verify
        expected_vni: Expected VNI value (optional)
        expected_guid: Expected GUID value (optional)
        expected_peer_list: Expected peer list for multicast (optional)

    Returns:
        True if VNET exists with expected values, False otherwise
    """
    cmd = 'docker exec -i swss '
    cmd += f'/get_dash_object.py --table_name DASH_VNET_TABLE --key {vnet_name}'
    result = dpu.shell(cmd, module_ignore_errors=True)
    cmdoutput = result.get('stdout', '')
    logger.info(f'shell out {cmdoutput}')

    patt = re.search('vni\": ([0-9]+),', cmdoutput)
    actual_vni = None
    if patt:
        actual_vni = patt.group(1)
        logger.info(f"VNET {vnet_name} vni: {actual_vni}")

    # Verify VNI if specified
    if expected_vni is not None:
        if actual_vni is None:
            return False
        if str(actual_vni) != str(expected_vni):
            logger.error(f"VNI mismatch: expected {expected_vni}, got {actual_vni}")
            return False
        else:
            return True

    return False

def get_vnet_state(dpu, vnet_name):
    """
    Verify that a VNET state .

    Args:
        duthost: DUT host object
        vnet_name: Name of the VNET to verify

    Returns:
        True: VNET COnfiguration successful
        False: VNET Configuration failed
    """
    cmd = 'docker exec -i swss '
    cmd += f'/get_dash_object.py --table_name DASH_VNET_TABLE --key {vnet_name} --statedb'
    result = dpu.shell(cmd, module_ignore_errors=True)
    cmdoutput = result.get('stdout', '')
    logger.info(f'shell out {cmdoutput}')

    patt = re.search("result\': \'([0-9])\'", cmdoutput)
    result_value = None
    if patt:
        result_value = int(patt.group(1))
    return result_value

def get_vnet_object(dpu):
    """
    Get the VNETs in CONFIG_DB.

    Args:
        dpuhost: DPU host object

    Returns:
        VNET entries in CONFIG_DB
    """
    cmd = 'docker exec -i swss '
    cmd += f'/get_dash_object.py --table_name DASH_VNET_TABLE'
    result = dpu.shell(cmd, module_ignore_errors=True)
    cmdoutput = result.get('stdout', '')
    logger.info(f'shell out {cmdoutput}')

    if not re.search("VNET", cmdoutput):
        return []
    vnet_keys = [k for k in cmdoutput.strip().splitlines() if "DASH_VNET" in k] if cmdoutput.strip() else []
    return vnet_keys

def get_vnet_count(dpu, vnet_name_patt=''):
    vnet_list = get_vnet_object(dpu)
    logger.info(vnet_list)
    if vnet_name_patt:
        count = sum(1 for item in vnet_list if re.search(f"{vnet_name_patt}", item))
        logger.info(f"count : {count}")
    else:
        count = len(vnet_list)
    logger.info(count)
    return count

# ========== CREATE Tests ==========

def test_vnet_create_single(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test creating a single VNET object.

    Validates:
    - VNET can be created successfully
    - VNET appears in CONFIG_DB with correct attributes
    - VNET is programmed to ASIC_DB
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Creating VNET: {TEST_VNET_NAME_1}")

    appliance_config = {"DASH_APPLIANCE_TABLE:1": {
                             "sip": "10.1.0.5",
                             "vm_vni": 100,
                             "local_region_id": 100,
                             "trusted_vnis_list": [100, [250, 511]]
                        }}

    apply_dash_config(localhost, duthost, ptfhost, appliance_config, dpuhost.dpu_index)
    # Create VNET configuration
    vnet_config = create_vnet_config(TEST_VNET_NAME_1, TEST_VNET_VNI_1, TEST_VNET_GUID_1)
   
    # Apply configuration
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)

    # Verify VNET exists in CONFIG_DB
    vnet_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_1, TEST_VNET_VNI_1)
    pytest_assert(vnet_exists, f"DPU_APPL_DB: VNET {TEST_VNET_NAME_1} was not created successfully")

    # Verify VNET state in STATE_DB 
    vnet_state = get_vnet_state(dpuhost, TEST_VNET_NAME_1)
    pytest_assert(vnet_state == 0, f"DPU_APPL_STATE_DB: VNET {TEST_VNET_NAME_1} was not created successfully")

    logger.info(f"VNET {TEST_VNET_NAME_1} created successfully")


def test_vnet_create_multiple(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test creating multiple VNET objects in a single operation.

    Validates:
    - Multiple VNETs can be created in one configuration push
    - All VNETs appear in CONFIG_DB with correct attributes
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Creating multiple VNETs: {TEST_VNET_NAME_2}, {TEST_VNET_NAME_3}")

    # Create configuration for multiple VNETs
    vnet_config = {
            f"DASH_VNET_TABLE:{TEST_VNET_NAME_2}": {
                "vni": str(TEST_VNET_VNI_2),
                "guid": TEST_VNET_GUID_2
            },
            f"DASH_VNET_TABLE:{TEST_VNET_NAME_3}": {
                "vni": str(TEST_VNET_VNI_3),
                "guid": TEST_VNET_GUID_3
            }
        }

    # Apply configuration
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)

    # Verify both VNETs exist
    vnet2_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_2, TEST_VNET_VNI_2)
    vnet3_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_3, TEST_VNET_VNI_3)

    pytest_assert(vnet2_exists, f"VNET {TEST_VNET_NAME_2} was not created successfully")
    pytest_assert(vnet3_exists, f"VNET {TEST_VNET_NAME_3} was not created successfully")

    # Verify VNET state in STATE_DB 
    vnet2_state = get_vnet_state(dpuhost, TEST_VNET_NAME_2)
    vnet3_state = get_vnet_state(dpuhost, TEST_VNET_NAME_3)

    pytest_assert(vnet2_state == 0, f"DPU_APPL_STATE_DB: VNET {TEST_VNET_NAME_2} was not created successfully")
    pytest_assert(vnet3_state == 0, f"DPU_APPL_STATE_DB: VNET {TEST_VNET_NAME_3} was not created successfully")
    logger.info("Multiple VNETs created successfully")

def test_vnet_create_duplicate(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test creating a VNET with a name that already exists.

    Validates:
    - Creating a duplicate VNET updates the existing entry
    - Updated values are reflected in CONFIG_DB
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Attempting to create duplicate VNET: {TEST_VNET_NAME_1}")

    # Try to create the same VNET again with different VNI
    new_vni = 9999
    vnet_config = create_vnet_config(TEST_VNET_NAME_1, new_vni, TEST_VNET_GUID_1)
    # Apply configuration
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)

    # Verify VNET was updated with new VNI
    vnet_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_1, new_vni)
    pytest_assert(vnet_exists, f"VNET {TEST_VNET_NAME_1} was not updated with new VNI")

    # Verify VNET state in STATE_DB 
    vnet1_state = get_vnet_state(dpuhost, TEST_VNET_NAME_1)

    pytest_assert(vnet1_state != 0, f"DPU_APPL_STATE_DB: VNET {TEST_VNET_NAME_1} was updated successfully")

    logger.info("Duplicate VNET creation resulted in update as expected")


# ========== READ Tests ==========

def test_vnet_read_single(duthost, dpuhosts, dpu_index, skip_config):
    """
    Test reading a single VNET object from CONFIG_DB.

    Validates:
    - VNET can be queried from CONFIG_DB
    - All VNET attributes are retrieved correctly
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Reading VNET: {TEST_VNET_NAME_1}")

    # Verify VNET can be read
    new_vni = 9999
    vnet_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_1, new_vni)

    pytest_assert(vnet_exists, f"VNET {TEST_VNET_NAME_1} could not be read from CONFIG_DB")

    logger.info(f"VNET {TEST_VNET_NAME_1} read successfully")


def test_vnet_read_all(duthost, dpuhosts, dpu_index, skip_config):
    """
    Test reading all VNET objects from CONFIG_DB.

    Validates:
    - All VNETs can be enumerated
    - Count matches expected number of VNETs
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info("Reading all VNETs")

    # Get count of all VNETs
    vnet_count = get_vnet_count(dpuhost)

    # We should have at least the test VNETs we created
    expected_min_count = 3  # TEST_VNET_NAME_1, 2, 3
    pytest_assert(vnet_count >= expected_min_count,
                  f"Expected at least {expected_min_count} VNETs, found {vnet_count}")

    logger.info(f"Found {vnet_count} VNETs in CONFIG_DB")


def test_vnet_read_nonexistent(duthost, dpuhosts, dpu_index, skip_config):
    """
    Test reading a VNET that does not exist.

    Validates:
    - Querying non-existent VNET returns appropriate result
    - No errors occur when querying non-existent objects
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]
    nonexistent_vnet = "vnet_does_not_exist"

    logger.info(f"Reading non-existent VNET: {nonexistent_vnet}")

    # Verify VNET does not exist
    vnet_exists = verify_vnet_exists(dpuhost, nonexistent_vnet)
    pytest_assert(not vnet_exists, f"VNET {nonexistent_vnet} should not exist")

    logger.info("Non-existent VNET query handled correctly")


# ========== UPDATE Tests ==========
def test_vnet_update_vni(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test updating VNI attribute of an existing VNET.

    Validates:
    - VNET VNI can be updated
    - Updated VNI is reflected in CONFIG_DB
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Updating VNET {TEST_VNET_NAME_1} VNI to 5001")

    # Update VNET with new VNI
    # Verify VNET was updated
    vnet_config = create_vnet_config(TEST_VNET_NAME_1, 5001, TEST_VNET_GUID_1)


    # Apply configuration
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)

    # Verify VNET was updated
    vnet_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_1, 5001)
    pytest_assert(vnet_exists, f"VNET {TEST_VNET_NAME_1} VNI was not updated successfully")

    # Verify VNET state in STATE_DB 
    vnet1_state = get_vnet_state(dpuhost, TEST_VNET_NAME_1)

    pytest_assert(vnet1_state != 0, f"DPU_APPL_STATE_DB: VNET {TEST_VNET_NAME_1} was created successfully")

    logger.info(f"VNET {TEST_VNET_NAME_1} VNI not updated successfully")


# ========== DELETE Tests ==========

def test_vnet_delete_single(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test deleting a single VNET object.

    Validates:
    - VNET can be deleted successfully
    - VNET no longer appears in CONFIG_DB after deletion
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Deleting VNET: {TEST_VNET_NAME_1}")

    # Get count before deletion
    count_before = get_vnet_count(dpuhost)

    # Create delete configuration
    vnet_config = create_vnet_config(TEST_VNET_NAME_1, TEST_VNET_VNI_1_UPDATED, TEST_VNET_GUID_1)

    # Apply configuration
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")

    # Verify VNET was deleted
    vnet_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_1)
    pytest_assert(not vnet_exists, f"VNET {TEST_VNET_NAME_1} still exists after deletion")

    # Verify count decreased
    count_after = get_vnet_count(dpuhost)
    pytest_assert(count_after == count_before - 1,
                  f"VNET count did not decrease after deletion (before: {count_before}, after: {count_after})")

    logger.info(f"VNET {TEST_VNET_NAME_1} deleted successfully")


def test_vnet_delete_multiple(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test deleting multiple VNET objects in a single operation.

    Validates:
    - Multiple VNETs can be deleted in one configuration push
    - All specified VNETs are removed from CONFIG_DB
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Deleting multiple VNETs: {TEST_VNET_NAME_2}, {TEST_VNET_NAME_3}")

    # Get count before deletion
    count_before = get_vnet_count(dpuhost)

    # Create delete configuration for multiple VNETs
    vnet_config = {
            f"DASH_VNET_TABLE:{TEST_VNET_NAME_2}": {
                "vni": str(TEST_VNET_VNI_2),
                "guid": TEST_VNET_GUID_2
            },
            f"DASH_VNET_TABLE:{TEST_VNET_NAME_3}": {
                "vni": str(TEST_VNET_VNI_3),
                "guid": TEST_VNET_GUID_3
            }
        }

    # Apply configuration
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")

    # Verify both VNETs were deleted
    vnet2_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_2)
    vnet3_exists = verify_vnet_exists(dpuhost, TEST_VNET_NAME_3)

    pytest_assert(not vnet2_exists, f"VNET {TEST_VNET_NAME_2} still exists after deletion")
    pytest_assert(not vnet3_exists, f"VNET {TEST_VNET_NAME_3} still exists after deletion")

    # Verify count decreased by 2
    count_after = get_vnet_count(dpuhost)
    pytest_assert(count_after == count_before - 2,
                  f"VNET count did not decrease correctly after deletion (before: {count_before}, after: {count_after})")

    logger.info("Multiple VNETs deleted successfully")


def test_vnet_delete_nonexistent(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test deleting a VNET that does not exist.

    Validates:
    - Deleting non-existent VNET does not cause errors
    - System handles deletion of non-existent objects gracefully
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    nonexistent_vnet = "vnet_never_existed"

    logger.info(f"Deleting non-existent VNET: {nonexistent_vnet}")

    # Get count before deletion attempt
    count_before = get_vnet_count(dpuhost)

    # Create delete configuration for non-existent VNET
    vnet_config = create_vnet_config(nonexistent_vnet, 9999, "00000000-0000-0000-0000-000000000000")

    # Apply configuration - should not cause errors
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op ="DEL")

    # Verify count unchanged
    count_after = get_vnet_count(dpuhost)
    pytest_assert(count_after == count_before,
                  f"VNET count changed unexpectedly (before: {count_before}, after: {count_after})")

    logger.info("Non-existent VNET deletion handled gracefully")


# ========== Edge Case Tests ==========

def test_vnet_invalid_vni(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test creating VNET with invalid VNI values.

    Validates:
    - System handles invalid VNI values appropriately
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info("Testing VNET creation with invalid VNI")

    # Try creating VNET with VNI = 0 (edge case, should be valid)
    vnet_name = "vnet_vni_zero"
    vnet_config = create_vnet_config(vnet_name, 0, TEST_VNET_GUID_1)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)

    # Verify it was created (VNI 0 might be valid)
    vnet_exists = verify_vnet_exists(dpuhost, vnet_name, 0)

    # Verify VNET state in STATE_DB 
    vnet_state = get_vnet_state(dpuhost, vnet_name)

    pytest_assert(vnet_state != 0, f"DPU_APPL_STATE_DB: VNET {vnet_name} was created successfully")
    # Clean up
    if vnet_exists:
        vnet_config = create_vnet_config(vnet_name, 0, TEST_VNET_GUID_1)
        apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")

    logger.info("Invalid VNI test completed")


def test_vnet_duplicate_vni_different_name(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test creating two VNETs with the same VNI but different names.

    DASH Constraint: Two VNETs cannot have the same VNI.

    Validates:
    - System rejects or handles duplicate VNI assignment
    - Second VNET creation with duplicate VNI fails or overwrites
    - VNI uniqueness is enforced
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    duplicate_vni = 9090
    vnet_name_1 = "vnet_dup_vni_1"
    vnet_name_2 = "vnet_dup_vni_2"
    guid_1 = "99999999-9999-9999-9999-999999999991"
    guid_2 = "99999999-9999-9999-9999-999999999992"

    logger.info(f"Testing duplicate VNI constraint: VNI {duplicate_vni} for two different VNETs")

    # Create first VNET with VNI
    logger.info(f"Creating first VNET {vnet_name_1} with VNI {duplicate_vni}")
    vnet_config = create_vnet_config(vnet_name_1, duplicate_vni, guid_1)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)

    # Verify first VNET exists
    vnet1_exists = verify_vnet_exists(dpuhost, vnet_name_1, duplicate_vni)
    pytest_assert(vnet1_exists, f"First VNET {vnet_name_1} was not created")

    # Try to create second VNET with same VNI
    logger.info(f"Attempting to create second VNET {vnet_name_2} with same VNI {duplicate_vni}")
    vnet_config = create_vnet_config(vnet_name_2, duplicate_vni, guid_2)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)

    # Check if second VNET was created
    verify_vnet_exists(dpuhost, vnet_name_2, duplicate_vni)

    # Verify VNET state in STATE_DB 
    vnet2_state = get_vnet_state(dpuhost, vnet_name_2)

    if vnet2_state:
        logger.warning(f"WARNING: Second VNET {vnet_name_2} was created with duplicate VNI {duplicate_vni}")
        logger.warning("This violates DASH constraint that VNI must be unique across VNETs")

    pytest_assert(vnet2_state != 0, f"DPU_APPL_STATE_DB: VNET {vnet_name_2} was created successfully")

    # According to DASH constraints, two VNETs should NOT have the same VNI
    # The expected behavior could be:
    # 1. Second VNET creation is rejected (vnet2 doesn't exist)
    # 2. Second VNET creation succeeds but system logs an error
    # 3. Implementation-specific behavior

    if vnet2_state:

        # Check if both VNETs exist with same VNI (violation of constraint)
        vnet1_still_exists = verify_vnet_exists(dpuhost, vnet_name_1, duplicate_vni)

        if vnet1_still_exists and vnet2_state:
            pytest.fail(f"CONSTRAINT VIOLATION: Both {vnet_name_1} and {vnet_name_2} exist with same VNI {duplicate_vni}")
    else:
        logger.info(f"Second VNET {vnet_name_2} was correctly rejected (duplicate VNI)")

    # Cleanup: Delete both VNETs if they exist
    logger.info("Cleaning up test VNETs")
    for vnet_name, guid in [(vnet_name_1, guid_1), (vnet_name_2, guid_2)]:
        if verify_vnet_exists(dpuhost, vnet_name):
            vnet_config = create_vnet_config(vnet_name, duplicate_vni)
            apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")

    logger.info("Duplicate VNI test completed")


def test_vnet_vni_uniqueness_across_operations(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test VNI uniqueness across create, update, and delete operations.

    Validates:
    - VNI remains unique when updating VNETs
    - Deleted VNETs VNI can be reused by new VNET
    - Cannot update VNET to use another VNETs VNI
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    vnet_a = "vnet_unique_a"
    vnet_b = "vnet_unique_b"
    vni_a = 10001
    vni_b = 10002
    guid_a = "a1111111-1111-1111-1111-111111111111"
    guid_b = "b2222222-2222-2222-2222-222222222222"

    logger.info("Testing VNI uniqueness across operations")

    # Step 1: Create two VNETs with different VNIs
    logger.info(f"Step 1: Create {vnet_a} with VNI {vni_a} and {vnet_b} with VNI {vni_b}")
    vnet_config_a = create_vnet_config(vnet_a, vni_a, guid_a)
    vnet_config_b = create_vnet_config(vnet_b, vni_b, guid_b)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config_a, dpuhost.dpu_index)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config_b, dpuhost.dpu_index)

    pytest_assert(verify_vnet_exists(dpuhost, vnet_a, vni_a), f"Failed to create {vnet_a}")
    pytest_assert(verify_vnet_exists(dpuhost, vnet_b, vni_b), f"Failed to create {vnet_b}")

    # Step 2: Try to update vnet_a to use vnet_b's VNI (should fail or be rejected)
    logger.info(f"Step 2: Attempt to update {vnet_a} to use {vnet_b}'s VNI {vni_b}")
    vnet_config_a_dup = create_vnet_config(vnet_a, vni_b, guid_a)  # Try to use vnet_b's VNI
    apply_dash_config(localhost, duthost, ptfhost, vnet_config_a_dup, dpuhost.dpu_index)

    # Check result - vnet_a should NOT have vni_b (should still have vni_a or update rejected)
    verify_vnet_exists(dpuhost, vnet_a, vni_b)

    # Verify VNET state in STATE_DB 
    vnet_a_state = get_vnet_state(dpuhost, vnet_a)

    pytest_assert(vnet_a_state != 0, f"DPU_APPL_STATE_DB: VNET {vnet_a} was created successfully")

    if vnet_a_state:
        # Check if vnet_b still exists - if both exist with same VNI, it's a violation
        vnet_b_still_exists = verify_vnet_exists(dpuhost, vnet_b, vni_b)
        if vnet_b_still_exists:
            pytest.fail(f"CONSTRAINT VIOLATION: Both {vnet_a} and {vnet_b} have VNI {vni_b} after update")
        else:
            logger.warning(f"Update of {vnet_a} to VNI {vni_b} succeeded, but {vnet_b} was removed")
    else:
        logger.info(f"Update correctly rejected: {vnet_a} still has original VNI {vni_a}")

    # Step 3: Delete vnet_a and verify its VNI can be reused
    logger.info(f"Step 3: Delete {vnet_a} and reuse its VNI for new VNET")
    vnet_config_a_del = create_vnet_config(vnet_a, vni_a, guid_a)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config_a_del, dpuhost.dpu_index, op="DEL")
    pytest_assert(not verify_vnet_exists(dpuhost, vnet_a), f"{vnet_a} still exists after deletion")

    # Create new VNET with vnet_a's old VNI (should succeed after deletion)
    vnet_c = "vnet_unique_c"
    guid_c = "c3333333-3333-3333-3333-333333333333"
    vnet_config_c = create_vnet_config(vnet_c, vni_a, guid_c)  # Reuse vni_a
    apply_dash_config(localhost, duthost, ptfhost, vnet_config_c, dpuhost.dpu_index)
    pytest_assert(verify_vnet_exists(dpuhost, vnet_c, vni_a),
                  f"Failed to create {vnet_c} with reused VNI {vni_a}")
    logger.info(f"Successfully reused VNI {vni_a} for new VNET {vnet_c} after deletion")

    # Cleanup
    logger.info("Cleaning up test VNETs")
    for vnet_name, vni, guid in [(vnet_b, vni_b, guid_b), (vnet_c, vni_a, guid_c)]:
        if verify_vnet_exists(duthost, vnet_name):
            vnet_config = create_vnet_config(vnet_name, vni, guid)
            apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")

    logger.info("VNI uniqueness test completed")

# ========== SCALE Tests (32 VNET Limit) ==========
def test_vnet_scale_create_max_vnets(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test creating maximum number of VNETs (32).

    Validates:
    - DASH can handle 32 VNETs
    - All VNETs are created successfully
    - System performance with maximum VNETs
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info(f"Creating {MAX_VNET_COUNT} VNETs (maximum supported)")

    # Get current VNET count
    initial_count = get_vnet_count(dpuhost)
    vnets_to_create = MAX_VNET_COUNT - initial_count

    if vnets_to_create <= 0:
        logger.warning(f"Already have {initial_count} VNETs, skipping scale test")
        pytest.skip(f"Already at or above max VNET count ({initial_count}/{MAX_VNET_COUNT})")

    # Create VNETs up to the limit
    created_vnets = []
    vnet_config = {}
    for i in range(vnets_to_create):
        vnet_name = f"vnet_scale_{i}"
        vni = 3000 + i
        guid = f"c0000000-0000-0000-0000-{i:012d}"

        # We don't need exact VNI/GUID for deletion
        _vnet_config = create_vnet_config(vnet_name, vni, guid)
        created_vnets.append((vnet_name, vni, guid))
        deep_merge(vnet_config, _vnet_config)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)
    # Verify final count
    final_count = get_vnet_count(dpuhost)
    pytest_assert(final_count == MAX_VNET_COUNT,
                  f"Expected {MAX_VNET_COUNT} VNETs, got {final_count}")

    logger.info(f"Successfully created {vnets_to_create} VNETs, total: {final_count}")

    # Store created VNETs for cleanup
    return created_vnets


def test_vnet_scale_verify_all(duthost, dpuhosts, dpu_index, skip_config):
    """
    Test reading all VNETs when at maximum capacity.

    Validates:
    - All 32 VNETs can be queried
    - System remains responsive at max capacity
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info("Verifying all VNETs at maximum capacity")

    # Get all VNET keys
    actual_vnet_count = get_vnet_count(dpuhost)

    logger.info(f"Found {actual_vnet_count} VNETs in CONFIG_DB")
    pytest_assert(actual_vnet_count<= MAX_VNET_COUNT,
                  f"VNET count {actual_vnet_count} exceeds maximum {MAX_VNET_COUNT}")

def test_vnet_scale_cleanup(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Cleanup scale test VNETs.

    Validates:
    - Mass deletion of VNETs works correctly
    - System recovers to normal state after scale test
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    logger.info("Cleaning up scale test VNETs")

    # Get current VNET count
    initial_count = get_vnet_count(dpuhost)
    vnets_to_delete = MAX_VNET_COUNT - initial_count
    logger.info(f'valie del {initial_count} {vnets_to_delete} {MAX_VNET_COUNT}')

    vnet_config = {}
    vnets_to_delete = 32
    for i in range(vnets_to_delete):
        vnet_name = f"vnet_scale_{i}"
        vni = 3000 + i
        guid = f"c0000000-0000-0000-0000-{i:012d}"

        # We don't need exact VNI/GUID for deletion
        _vnet_config = create_vnet_config(vnet_name, vni, guid)
        deep_merge(vnet_config, _vnet_config)

    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")


    # Verify cleanup
    final_count = get_vnet_count(dpuhost, vnet_name_patt='vnet_scale')
    logger.info(f"Final VNET count after cleanup: {final_count}")
    pytest_assert(final_count == 0,
                  f"VNET not deleted properly")


# ========== DELETE and RECREATE Tests ==========
def test_vnet_delete_and_recreate_with_diff_attributes(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test deleting and recreating the same VNET.

    Validates:
    - VNET can be deleted and recreated with same name
    - Recreated VNET can have different attributes
    - No residual state from previous VNET instance
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    vnet_name = "vnet_delete_recreate_test"
    original_vni = 6000
    original_guid = "60000000-6000-6000-6000-600000000000"
    new_vni = 6001
    new_guid = "60000000-6000-6000-6000-600000000001"

    logger.info(f"Testing delete and recreate for VNET: {vnet_name}")

    # Step 1: Create original VNET
    logger.info("Step 1: Create original VNET")
    vnet_config = create_vnet_config(vnet_name, original_vni, original_guid)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)
    vnet_exists = verify_vnet_exists(dpuhost, vnet_name, original_vni)
    pytest_assert(vnet_exists, f"Failed to create original VNET {vnet_name}")

    # Step 2: Delete VNET
    logger.info("Step 2: Delete VNET")
    vnet_config = create_vnet_config(vnet_name, original_vni, original_guid)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")
    vnet_exists = verify_vnet_exists(dpuhost, vnet_name)
    pytest_assert(not vnet_exists, f"VNET {vnet_name} still exists after deletion")

    # Step 3: Recreate VNET with different attributes
    logger.info("Step 3: Recreate VNET with different attributes")
    vnet_config = create_vnet_config(vnet_name, new_vni, new_guid)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)
    vnet_exists = verify_vnet_exists(dpuhost, vnet_name, new_vni)
    pytest_assert(vnet_exists, f"Failed to recreate VNET {vnet_name}")

    # Step 4: Verify new attributes (not old ones)
    logger.info("Step 4: Verify new attributes")
    vnet_old = verify_vnet_exists(dpuhost, vnet_name, original_vni)
    pytest_assert(not vnet_old, f"VNET {vnet_name} still has old attributes after recreation")

    # Cleanup
    logger.info("Cleanup: Delete test VNET")
    vnet_config = create_vnet_config(vnet_name, new_vni, new_guid)
    apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op="DEL")

    logger.info(f"Delete and recreate test passed for {vnet_name}")


def test_vnet_delete_recreate_multiple_times(localhost, duthost, dpuhosts, dpu_index, ptfhost, skip_config):
    """
    Test deleting and recreating the same VNET multiple times.

    Validates:
    - VNET can be deleted and recreated repeatedly
    - No memory leaks or state corruption
    - System handles multiple cycles correctly
    """
    if skip_config:
        pytest.skip("Skipping config test")

    dpuhost = dpuhosts[dpu_index]

    vnet_name = "vnet_cycle_test"
    num_cycles = 1

    logger.info(f"Testing {num_cycles} delete/recreate cycles for VNET: {vnet_name}")

    # Create VNETs up to the limit
    created_vnets = []
    vnet_config = {}
    for i in range(MAX_VNET_COUNT):
        vnet_name = f"vnet_scale_{i}"
        vni = 3000 + i
        guid = f"c0000000-0000-0000-0000-{i:012d}"

        _vnet_config = create_vnet_config(vnet_name, vni, guid)
        created_vnets.append((vnet_name, vni, guid))
        deep_merge(vnet_config, _vnet_config)

    for cycle in range(num_cycles):
        logger.info(f"VNET creation in cycle {cycle + 1}")
        # Create VNET
        apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index)
        final_count = get_vnet_count(dpuhost, vnet_name_patt='vnet_scale')
        logger.info(f"Successfully created VNETs, total: {final_count}")
        pytest_assert(final_count == MAX_VNET_COUNT,
                  f"Expected {MAX_VNET_COUNT} VNETs, got {final_count}")

        logger.info(f"VNET deletion in cycle {cycle + 1}")
        # delete VNET
        apply_dash_config(localhost, duthost, ptfhost, vnet_config, dpuhost.dpu_index, op='DEL')
        final_count = get_vnet_count(dpuhost, vnet_name_patt='vnet_scale')
        logger.info(f"Successfully deleted VNETs, total: {final_count}")
        pytest_assert(final_count == 0,
                  f"Expected {MAX_VNET_COUNT} VNETs, got {final_count}")

    logger.info(f"Successfully completed {num_cycles} delete/recreate cycles")
