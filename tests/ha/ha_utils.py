import logging
import json

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def build_dash_ha_scope_args(fields):
    """
    Build args for DASH_HA_SCOPE_CONFIG_TABLE
    EXACTLY following the working CLI
    """

    version = str(fields["version"])
    if version.endswith(".0"):
        version = version[:-2]
    disabled_val = str(fields["disabled"]).lower()

    return (
        f'version \\"{version}\\" '
        f'disabled  {disabled_val} '
        f'desired_ha_state "{fields["desired_ha_state"]}" '
        f'ha_set_id "{fields["ha_set_id"]}" '
        f'owner "{fields["owner"]}"'
    )


def proto_utils_hset(duthost, table, key, args):
    """
    Wrapper around proto_utils.py hset

    Args:
        duthost: pytest duthost fixture
        table (str): Redis table name
        key (str): Redis key
        args (str): Already-built proto args string
    """
    cmd = (
        "docker exec swss python /etc/sonic/proto_utils.py hset "
        f'"{table}:{key}" {args}'
    )
    logger.debug(f"{duthost.hostname} running command: {cmd}")
    out = duthost.shell(cmd)
    logger.debug(f"{duthost.hostname} command output: {out}")


def build_dash_ha_set_args(fields):
    """
    Build args for DASH_HA_SET_CONFIG_TABLE
    EXACTLY following the working CLI
    """

    version = str(fields["version"])
    if version.endswith(".0"):
        version = version[:-2]
    vdpu_ids = fields.get("vdpu_ids", ["vdpu0_0", "vdpu1_0"])
    if isinstance(vdpu_ids, list):
        vdpu_ids_str = json.dumps(vdpu_ids)
    elif isinstance(vdpu_ids, str):
        # If already a JSON string, use as-is
        vdpu_ids_str = vdpu_ids
    else:
        raise TypeError(f"vdpu_ids must be list or string, got {type(vdpu_ids)}")
    standalone_index = fields.get("preferred_standalone_vdpu_index", 0)
    return (
        f'version \\"{version}\\" '
        f'vip_v4 "{fields["vip_v4"]}" '
        f'vip_v6 "{fields["vip_v6"]}" '
        f'scope "{fields["scope"]}" '
        f'preferred_vdpu_id "{fields["preferred_vdpu_id"]}" '
        f'preferred_standalone_vdpu_index {standalone_index} '
        f'vdpu_ids \'{vdpu_ids_str}\' '
    )


def extract_pending_operations(ids_str, types_str):
    """
    Parse pending_operation_ids and pending_operation_types from
    comma-separated STATE_DB field values and return list of
    (type, id) tuples.

    Args:
        ids_str: Comma-separated pending operation IDs
        types_str: Comma-separated pending operation types

    Returns:
        list[tuple[str, str]]: List of (op_type, op_id) tuples
    """
    if not ids_str or not types_str:
        return []

    try:
        ids = [x.strip() for x in ids_str.split(',') if x.strip()]
        types = [x.strip() for x in types_str.split(',') if x.strip()]
    except Exception:
        return []

    return list(zip(types, ids))


def get_pending_operation_id(duthost, scope_key, expected_op_type):
    """
    Get pending operation ID from STATE_DB DASH_HA_SCOPE_STATE (single query, no retry).

    Args:
        duthost: DUT host object
        scope_key: HA scope key (e.g., "vdpu0_0:haset0_0")
        expected_op_type: Expected operation type (e.g., "activate_role")

    Returns:
        str: Pending operation ID if found, None otherwise
    """
    db_key = f"DASH_HA_SCOPE_STATE|{scope_key}"

    try:
        ids_res = duthost.shell(
            f'sonic-db-cli STATE_DB HGET "{db_key}" pending_operation_ids'
        )
        types_res = duthost.shell(
            f'sonic-db-cli STATE_DB HGET "{db_key}" pending_operation_types'
        )

        if ids_res.get("rc", 0) != 0 or types_res.get("rc", 0) != 0:
            logger.debug(
                f"{duthost.hostname} STATE_DB query failed for scope {scope_key}: "
                f"ids_rc={ids_res.get('rc')}, types_rc={types_res.get('rc')}"
            )
            return None

        ids_str = ids_res["stdout"].strip()
        types_str = types_res["stdout"].strip()
        pending_ops = extract_pending_operations(ids_str, types_str)

        for op_type, op_id in pending_ops:
            if op_type == expected_op_type:
                logger.debug(
                    f"{duthost.hostname} Found pending_operation_id {op_id} "
                    f"for scope {scope_key}"
                )
                return op_id

        logger.debug(
            f"{duthost.hostname} No {expected_op_type} operation found. "
            f"Available: {pending_ops}"
        )
        return None

    except Exception as e:
        logger.debug(f"{duthost.hostname} Exception: {e}")
        return None


def build_dash_ha_scope_activate_args(fields, pending_id):
    disabled_val = str(fields["disabled"]).lower()
    return (
        f'version \\"{fields["version"]}\\" '
        f'disabled {disabled_val} '
        f'desired_ha_state "{fields["desired_ha_state"]}" '
        f'ha_set_id "{fields["ha_set_id"]}" '
        f'owner "{fields["owner"]}" '
        f'approved_pending_operation_ids '
        f'[\\\"{pending_id}\\\"]'
    )


def verify_ha_state(
    duthost,
    scope_key,
    expected_state,
    timeout=120,
    interval=5,
):
    """
    Wait until HA reaches the expected state by querying STATE_DB.
    """
    def _check_ha_state():
        db_key = f"DASH_HA_SCOPE_STATE|{scope_key}"
        res = duthost.shell(
            f'sonic-db-cli STATE_DB HGET "{db_key}" local_acked_asic_ha_state'
        )
        state = res["stdout"].strip()
        return state == expected_state

    success = wait_until(timeout, interval, 0, _check_ha_state)

    return success


def activate_primary_dash_ha(duthost, scope_key, expected_op_type):
    """
    Activate Role using pending_operation_ids
    """
    fields = {
                "version": "1",
                "disabled": "false",
                "desired_ha_state": "active",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            }
    return activate_dash_ha(duthost, scope_key, fields, expected_op_type)


def activate_secondary_dash_ha(duthost, scope_key, expected_op_type):
    """
    Activate Role using pending_operation_ids
    """
    fields = {
                "version": "1",
                "disabled": "false",
                "desired_ha_state": "unspecified",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            }
    return activate_dash_ha(duthost, scope_key, fields, expected_op_type)


def activate_dash_ha(duthost, scope_key, fields, expected_op_type):

    proto_utils_hset(
            duthost,
            table="DASH_HA_SCOPE_CONFIG_TABLE",
            key=scope_key,
            args=build_dash_ha_scope_args(fields),
        )

    pending_id = wait_for_pending_operation_id(duthost, scope_key, expected_op_type, timeout=60)
    assert pending_id, (
        f"Timed out waiting for active pending_operation_id "
        f"for scope {scope_key}"
    )
    proto_utils_hset(
        duthost,
        table="DASH_HA_SCOPE_CONFIG_TABLE",
        key=scope_key,
        args=build_dash_ha_scope_activate_args(fields, pending_id),
    )

    if verify_ha_state(
        duthost,
        scope_key,
        expected_state="active",
        timeout=120,
        interval=5,
    ):
        logger.info(f"HA reached ACTIVE state for {scope_key}")
        return True
    else:
        logger.warning(f"HA did not reach ACTIVE state for {scope_key}")
        return False


def wait_for_pending_operation_id(
    duthost,
    scope_key,
    expected_op_type,
    timeout=60,
    interval=2,
):
    """
    Wait until the expected pending_operation_id appears.
    """
    pending_id = None

    def _condition():
        nonlocal pending_id
        pending_id = get_pending_operation_id(
            duthost,
            scope_key,
            expected_op_type,
        )
        return pending_id is not None

    success = wait_until(
        timeout,
        interval,
        0,           # REQUIRED delay argument
        _condition,  # condition callable
    )

    return pending_id if success else None

