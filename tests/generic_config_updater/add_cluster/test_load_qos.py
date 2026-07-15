import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.gu_utils import apply_patch, delete_tmpfile, expect_op_success, generate_tmpfile
from tests.generic_config_updater.add_cluster.helpers import add_content_to_patch_file, \
    change_interface_admin_state_for_namespace, get_cfg_info_from_dut
from tests.common.utilities import wait_until

pytestmark = [
        pytest.mark.topology("t2")
        ]

logger = logging.getLogger(__name__)


# -----------------------------
# Helper functions that modify configuration via apply-patch
# -----------------------------

def apply_patch_remove_qos_for_namespace(duthost,
                                         namespace,
                                         qos_config,
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

    #  Read the current CONFIG_DB so that we know exactly which keys exist for
    buffer_pg_cfg = qos_config.get('BUFFER_PG') or {}
    port_qos_map_cfg = qos_config.get('PORT_QOS_MAP') or {}

    ns_path = '' if namespace is None else '/' + namespace

    def _build_remove_ops(table_name, table_cfg):
        """
        Build per-key 'remove' ops for one table, filtering out any keys that
        aren't per-port (e.g. 'global' in PORT_QOS_MAP, which we intentionally
        leave in place to avoid unbinding the switch-level DSCP_TO_TC map).
        If the set of keys we'd remove equals the full contents of the table
        in ConfigDb, the table would end up empty and SONiC's GCU validator
        rejects that ("empty tables ... not allowed in ConfigDb"). In that
        case, emit a single table-level remove instead.
        """
        per_key_ops = []
        keys_removed = []
        for k in table_cfg:
            if not k.startswith('Ethernet'):
                # Skip non-port keys such as 'global'.
                continue
            per_key_ops.append({
                "op": "remove",
                "path": "{}/{}/{}".format(ns_path, table_name, k),
            })
            keys_removed.append(k)
        if per_key_ops and len(keys_removed) == len(table_cfg):
            logger.info(
                "Every key in %s would be removed; using table-level remove "
                "to avoid the ConfigDb empty-table rejection.", table_name,
            )
            per_key_ops = [{
                "op": "remove",
                "path": "{}/{}".format(ns_path, table_name),
            }]
            # keys_removed already lists all per-port keys we're clearing,
            # keep it so the verify block below can still assert on them.
        return per_key_ops, keys_removed

    buffer_pg_ops, buffer_pg_removed = _build_remove_ops('BUFFER_PG', buffer_pg_cfg)
    port_qos_map_ops, port_qos_map_removed = _build_remove_ops('PORT_QOS_MAP', port_qos_map_cfg)
    json_patch = buffer_pg_ops + port_qos_map_ops

    pytest_assert(json_patch,
                  "No BUFFER_PG or PORT_QOS_MAP entries to remove "
                  "in namespace {}.".format(namespace))

    tmpfile = generate_tmpfile(duthost)

    if apply:
        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                # Verify CONFIG_DB - only the removed per-port keys should be gone.
                logger.info("Verifying CONFIG_DB no longer contains removed per-port entries.")
                buffer_pg_after = get_cfg_info_from_dut(duthost, 'BUFFER_PG', namespace) or {}
                port_qos_map_after = get_cfg_info_from_dut(duthost, 'PORT_QOS_MAP', namespace) or {}
                for buffer_key in buffer_pg_removed:
                    pytest_assert(
                        buffer_key not in buffer_pg_after,
                        "BUFFER_PG entry {} unexpectedly remained in CONFIG_DB.".format(buffer_key),
                    )
                for port_key in port_qos_map_removed:
                    pytest_assert(
                        port_key not in port_qos_map_after,
                        "PORT_QOS_MAP entry {} unexpectedly remained in CONFIG_DB.".format(port_key),
                    )
                logger.info("CONFIG_DB successfully verified: active-port QoS entries removed.")
                # Verify APPL_DB - the per-port BUFFER_PG_TABLE and
                # PORT_QOS_TABLE keys we removed from CONFIG_DB should be gone.
                # Also log everything that IS still present in these tables so
                # any leftover / unexpected entries are visible at a glance.

                ns_prefix = '' if namespace is None else '-n ' + namespace
                appl_targets = [
                    ('BUFFER_PG_TABLE', buffer_pg_removed),
                    ('PORT_QOS_TABLE', port_qos_map_removed),
                ]

                def _appl_keys(appl_table):
                    """Current list of APPL_DB keys under `appl_table`."""
                    cmd = "sonic-db-cli {} APPL_DB keys {}:*".format(
                        ns_prefix, appl_table)
                    return [
                        k for k in duthost.shell(cmd)["stdout"].splitlines()
                        if k
                    ]

                for appl_table, removed_keys in appl_targets:
                    expected_gone = {
                        "{}:{}".format(appl_table, cfg_key.replace('|', ':'))
                        for cfg_key in removed_keys
                    }
                    if expected_gone:
                        logger.info(
                            "Verifying APPL_DB %s no longer contains %d "
                            "removed key(s): %s",
                            appl_table, len(expected_gone),
                            sorted(expected_gone),
                        )
                        pytest_assert(
                            wait_until(
                                30, 2, 0,
                                lambda a=appl_table, e=expected_gone:
                                not (e & set(_appl_keys(a))),
                            ),
                            "APPL_DB {} still contains removed keys: {}".format(
                                appl_table,
                                sorted(expected_gone & set(_appl_keys(appl_table))),
                            ),
                        )
                    remaining = sorted(_appl_keys(appl_table))
                    logger.info(
                        "APPL_DB %s post-remove contents : %s",
                        appl_table,
                        remaining if remaining else "<empty>",
                    )
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

    ns_path = '' if namespace is None else '/' + namespace
    buffer_pg_saved = qos_config.get('BUFFER_PG') or {}
    port_qos_map_saved = qos_config.get('PORT_QOS_MAP') or {}

    # 2) Build the payload:
    #    a) If a table is currently absent in CONFIG_DB (because remove
    #       cleaned out its last key), first re-create it
    #    b) Then one "add" op per active-port key from qos_config.

    buffer_pg_current = get_cfg_info_from_dut(duthost, 'BUFFER_PG', namespace)
    port_qos_map_current = get_cfg_info_from_dut(duthost, 'PORT_QOS_MAP', namespace)

    json_patch = []
    if buffer_pg_saved and buffer_pg_current is None:
        json_patch.append({
            "op": "add",
            "path": "{}/BUFFER_PG".format(ns_path),
            "value": {},
        })
    if port_qos_map_saved and port_qos_map_current is None:
        json_patch.append({
            "op": "add",
            "path": "{}/PORT_QOS_MAP".format(ns_path),
            "value": {},
        })
    # BUFFER_PG per-key adds (key = "<port>|<pg_profile>").
    buffer_pg_added = []
    for buffer_key, value in buffer_pg_saved.items():
        json_patch.append({
            "op": "add",
            "path": "{}/BUFFER_PG/{}".format(ns_path, buffer_key),
            "value": value,
        })
        buffer_pg_added.append(buffer_key)
    # PORT_QOS_MAP per-key adds (key = "<port>").
    port_qos_map_added = []
    for port_key, value in port_qos_map_saved.items():
        if not port_key.startswith('Ethernet'):
            continue
        json_patch.append({
                "op": "add",
                "path": "{}/PORT_QOS_MAP/{}".format(ns_path, port_key),
                "value": value,
            })
        port_qos_map_added.append(port_key)
    pytest_assert(json_patch,
                  "No BUFFER_PG or PORT_QOS_MAP entries to re-add for active "
                  "interfaces in namespace {}.".format(namespace))

    if apply:
        tmpfile = generate_tmpfile(duthost)
        logger.info("Temporary file: {}".format(tmpfile))
        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                # Verify CONFIG_DB - the re-added per-port entries must match
                # the values we captured before removal.
                logger.info("Verifying CONFIG_DB contains the re-added per-port entries.")
                buffer_pg_after = get_cfg_info_from_dut(duthost, 'BUFFER_PG', namespace) or {}
                port_qos_map_after = get_cfg_info_from_dut(duthost, 'PORT_QOS_MAP', namespace) or {}
                for buffer_key in buffer_pg_added:
                    pytest_assert(
                        buffer_pg_after.get(buffer_key) == buffer_pg_saved[buffer_key],
                        "BUFFER_PG entry {} in CONFIG_DB does not match expected value.".format(
                            buffer_key),
                    )
                for port_key in port_qos_map_added:
                    pytest_assert(
                        port_qos_map_after.get(port_key) == port_qos_map_saved[port_key],
                        "PORT_QOS_MAP entry {} in CONFIG_DB does not match expected value.".format(
                            port_key),
                    )
                logger.info("CONFIG_DB successfully verified: per-port QoS entries restored.")
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


def verify_qos_in_appl_db(duthost, namespace, qos_config, timeout=60, interval=5):
    """
    Verify APPL_DB reflects qos_config after interfaces are up.
    Uses wait_until to tolerate asynchronous propagation.
    """
    ns_prefix = "" if namespace is None else "-n " + namespace
    # PORT_QOS_MAP intentionally skipped as APPL_DB
    # do not maintain PORT_QOS_TABLE entries
    table_map = {'BUFFER_PG': 'BUFFER_PG_TABLE'}

    def _keys(appl_table):
        cmd = "sonic-db-cli {} APPL_DB keys {}:*".format(ns_prefix, appl_table)
        return [k for k in duthost.shell(cmd)["stdout"].splitlines() if k]
    for cfg_table, appl_table in table_map.items():
        expected = qos_config.get(cfg_table) or {}
        if not expected:
            continue
        logger.info("Verifying APPL_DB table {} matches CONFIG_DB {}.".format(appl_table, cfg_table))
        pytest_assert(
            wait_until(timeout, interval, 0,
                       lambda: len(_keys(appl_table)) == len(expected)),
            "APPL_DB table {} has {} keys, expected {}.".format(
                appl_table, len(_keys(appl_table)), len(expected)),
        )

# -----------------------------
# Test Definitions
# -----------------------------


@pytest.fixture(autouse=True)
def ignore_expected_qos_errors(loganalyzer, rand_one_dut_front_end_hostname):
    """Ignore errors that are expected while QoS is torn down and re-applied."""
    if loganalyzer:
        ignore_regexes = [
            # -----------------------------------------------------------
            # Broadcom T2: port-level DSCP_TC (SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP)
            # cannot be re-bound at runtime. QosOrch drops the batch and
            # syncd emits SAI_STATUS_NOT_IMPLEMENTED. NOTE: the switch-level
            # variant is no longer triggered because this test does not
            # remove/re-add PORT_QOS_MAP/'global'.
            # -----------------------------------------------------------
            r".*ERR syncd[0-9]*#syncd:.*sendApiResponse:.*SAI_COMMON_API_SET.*"
            r"SAI_STATUS_NOT_IMPLEMENTED.*",
            r".*ERR syncd[0-9]*#syncd:.*processQuadEvent:.*VID:.*RID:.*",
            r".*ERR swss[0-9]*#orchagent:.*doTask:.*Failed to process QOS task, drop it.*",
            # -----------------------------------------------------------
            # BUFFER_PG churn: whole-table remove then per-key add produces
            # transient errors from buffermgrd / BufferOrch.
            # -----------------------------------------------------------
            r".*ERR swss[0-9]*#buffermgrd.*",
            r".*ERR swss[0-9]*#orchagent.*BufferOrch.*",
            # -----------------------------------------------------------
            # QoS / port admin state cycling.
            # -----------------------------------------------------------
            r".*ERR swss[0-9]*#orchagent.*QosOrch.*",
            r".*ERR swss[0-9]*#orchagent.*setPortPfcAsym.*",
            r".*ERR syncd[0-9]*#syncd.*SAI_API_(BUFFER|QOS_MAP|QUEUE).*",
        ]
        loganalyzer[rand_one_dut_front_end_hostname].ignore_regex.extend(ignore_regexes)


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
    pytest_require(
        buffer_pg_info and port_qos_map_info,
        "Skipping: DUT {} namespace {} has no BUFFER_PG or PORT_QOS_MAP config to exercise.".format(
            duthost.hostname, enum_rand_one_asic_namespace),
    )
    qos_config = {'BUFFER_PG': buffer_pg_info,
                  'PORT_QOS_MAP': port_qos_map_info}

    # remove qos for namespace
    apply_patch_remove_qos_for_namespace(duthost,
                                         enum_rand_one_asic_namespace,
                                         qos_config,
                                         apply=True,
                                         verify=True)
    # shutdown interfaces for namespace
    change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               status='down',
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
    # verify APPL_DB
    verify_qos_in_appl_db(duthost, enum_rand_one_asic_namespace, qos_config)
