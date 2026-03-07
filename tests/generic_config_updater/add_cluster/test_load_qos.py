import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, delete_tmpfile, expect_op_success, generate_tmpfile
from tests.generic_config_updater.add_cluster.helpers import add_content_to_patch_file, \
    change_interface_admin_state_for_namespace, get_cfg_info_from_dut

pytestmark = [
        pytest.mark.topology("t2")
        ]

logger = logging.getLogger(__name__)


# -----------------------------
# Helper functions that modify configuration via apply-patch
# -----------------------------

def apply_patch_remove_qos_for_namespace(duthost,
                                         namespace,
                                         apply=True,
                                         verify=True,
                                         patch_file=""):
    """
    Applies a patch to remove QoS configurations for a specific namespace on the DUT host.

    This function removes QoS configurations from the specified namespace by applying a patch on the DUT host.
    It can optionally verify that the QoS settings have been removed after the operation.

    Applies changes at configuration paths:
     - /<namespace>/BUFFER_PG
     - /<namespace>/PORT_QOS_MAP
    """

    logger.info("{}: Removing QoS for ASIC namespace {}".format(
        duthost.hostname, namespace)
        )
    json_patch = []
    paths_to_remove = ['BUFFER_PG', 'PORT_QOS_MAP']
    for path in paths_to_remove:
        json_patch.append({
            "op": "remove",
            "path": "/{}/{}".format(namespace, path)
        })

    tmpfile = generate_tmpfile(duthost)

    if apply:

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                # verify CONFIG_DB
                for path in paths_to_remove:
                    logger.info("Verifying CONFIG_DB is cleared for path {}.".format(path))
                    pytest_assert(not get_cfg_info_from_dut(duthost, path, namespace),
                                  "Found unexpected QoS config for {} in CONFIG_DB.".format(path))
                logger.info("CONFIG_DB successfully verified that doesn't contain QoS config.")
                # verify APPL_DB
                appl_db_tables = ['BUFFER_PG_TABLE']
                for table in appl_db_tables:
                    cmd = "sonic-db-cli -n {} APPL_DB keys {}:*".format(namespace, table)
                    logger.info("Verifying APPL_DB table {} is cleared.".format(table))
                    pytest_assert(not duthost.shell(cmd)["stdout"],
                                  "Found unexpected QoS config for {} in APPL_DB.".format(table))
                logger.info("APPL_DB successfully verified that doesn't contain QoS config.")
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


def apply_patch_add_qos_for_namespace(duthost,
                                      namespace,
                                      qos_config,
                                      apply=True,
                                      verify=True,
                                      patch_file=""):
    """
    Applies a patch to add QoS configuration for a specific namespace on the DUT host that had been previously removed
    from function 'apply_patch_remove_qos_for_namespace'.

    This function adds QoS configuration for the specified namespace by applying a patch on the DUT host.
    It utilizes the qos_config dictionary that includes all the required information to add.
    Optionally, it can verify the applied changes to ensure they meet the expected parameters.

    Args:
        duthost (object): DUT host object where the patch to add interfaces will be applied.
        namespace (str): The namespace where the network interfaces should be added.
        qos_config (dict): A dictionary containing the QoS configuration parameters to be applied.
        verify (bool, optional): If True, verifies the configuration after applying the patch. Defaults to True.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """
    logger.info("{}: Adding QoS for ASIC namespace {}".format(
        duthost.hostname, namespace)
        )
    json_patch = []
    for path, value in list(qos_config.items()):
        json_patch.append({
            "op": "add",
            "path": "/{}/{}".format(namespace, path),
            "value": value
        })

    if apply:

        tmpfile = generate_tmpfile(duthost)
        logger.info("Temporary file: {}".format(tmpfile))
        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                # verify CONFIG_DB
                for path, value in list(qos_config.items()):
                    logger.info("Verifying CONFIG_DB is added back for path {}.".format(path))
                    pytest_assert(get_cfg_info_from_dut(duthost, path, namespace) == value,
                                  "Didn't find expected QoS config for {} in CONFIG_DB.".format(path))
                logger.info("CONFIG_DB successfully verified to contain expected QoS config.")
                # verify APPL_DB
                appl_db_tables = ['BUFFER_PG']
                for table in appl_db_tables:
                    cmd = "sonic-db-cli -n {} APPL_DB keys {}_TABLE:*".format(namespace, table)
                    logger.info("Verifying APPL_DB table {} includes valid config.".format(table))
                    pytest_assert(len(duthost.shell(cmd)["stdout"].split('\n')) == len(qos_config.get(table)),
                                  "Didn't find expected config for {} in APPL_DB.".format(table))
                logger.info("APPL_DB successfully verified to include QoS config.")
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


# -----------------------------
# Test Definitions
# -----------------------------

@pytest.mark.disable_loganalyzer
def test_load_qos(duthosts,
                  rand_one_dut_front_end_hostname,
                  enum_rand_one_asic_namespace):
    """
    Verifies QoS changes in the configuration path via the `apply-patch` mechanism,
    specifically for the following configuration tables:
    BUFFER_PG, PORT_QOS_MAP.

    Steps involved:
    1. **Backup of existing configuration**: The current configuration in the aforementioned tables is saved.
    2. **Removal operation**: The `apply-patch remove` command is used to delete any info related to these config paths.
    3. **Addition operation**: The initial saved configuration is restored using the `apply-patch add` command.

    During both the removal and addition phases, the following verifications are performed:
    - Ensure the changes have been correctly applied.
    - Confirm that the changes are properly reflected in `CONFIG_DB`.
    - Validate the propagation of changes to relevant tables in `APPL_DB`.

    Parameters:
    - `duthosts`: The DUT (Device Under Test) hosts participating in the test.
    - `rand_one_dut_front_end_hostname`: The randomly selected hostname of one front-end DUT.
    - `enum_rand_one_asic_namespace`: The randomly selected asic namespace.

    """

    duthost = duthosts[rand_one_dut_front_end_hostname]

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", namespace=enum_rand_one_asic_namespace
        )['ansible_facts']

    buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
    port_qos_map_info = get_cfg_info_from_dut(duthost, 'PORT_QOS_MAP', enum_rand_one_asic_namespace)
    qos_config = {'BUFFER_PG': buffer_pg_info,
                  'PORT_QOS_MAP': port_qos_map_info}

    # shutdown interfaces for namespace
    change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               status='down',
                                               apply=True,
                                               verify=True)
    # remove qos for namespace
    apply_patch_remove_qos_for_namespace(duthost,
                                         enum_rand_one_asic_namespace,
                                         apply=True,
                                         verify=True)
    # add qos for namespace
    apply_patch_add_qos_for_namespace(duthost,
                                      enum_rand_one_asic_namespace,
                                      qos_config,
                                      apply=True,
                                      verify=True)
    # startup interfaces for namespace
    change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               status='up',
                                               apply=True,
                                               verify=True)
