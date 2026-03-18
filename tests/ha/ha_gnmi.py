import time

from tests.ha.gnmi_utils import GNMIEnvironment, write_gnmi_files
from tests.ha import proto_utils

DASH_HA_SET_CONFIG_TABLE = "DASH_HA_SET_CONFIG_TABLE"
DASH_HA_SCOPE_CONFIG_TABLE = "DASH_HA_SCOPE_CONFIG_TABLE"


def ha_set_config(
    ha_set_id,
    version,
    vip_v4,
    vip_v6,
    scope,
    preferred_vdpu_id,
    preferred_standalone_vdpu_index,
    vdpu_ids,
    **extra_fields,
):
    """
    Build a message for DASH_HA_SET_CONFIG_TABLE.
    """
    config = {
        "version": version,
        "vip_v4": vip_v4,
        "vip_v6": vip_v6,
        "scope": scope,
        "preferred_vdpu_id": preferred_vdpu_id,
        "preferred_standalone_vdpu_index": preferred_standalone_vdpu_index,
        "vdpu_ids": vdpu_ids,
    }
    config.update(extra_fields)
    return {f"{DASH_HA_SET_CONFIG_TABLE}:{ha_set_id}": config}


def ha_scope_config(
    vdpu_id,
    ha_set_id,
    version,
    disabled,
    desired_ha_state,
    owner,
    approved_pending_operation_ids=None,
    **extra_fields,
):
    """
    Build a message for DASH_HA_SCOPE_CONFIG_TABLE.
    """
    config = {
        "version": version,
        "disabled": disabled,
        "desired_ha_state": desired_ha_state,
        "ha_set_id": ha_set_id,
        "owner": owner,
    }
    if approved_pending_operation_ids is not None:
        config["approved_pending_operation_ids"] = (
            approved_pending_operation_ids
        )
    config.update(extra_fields)
    return {f"{DASH_HA_SCOPE_CONFIG_TABLE}:{vdpu_id}:{ha_set_id}": config}


def apply_ha_messages(
    localhost,
    duthost,
    ptfhost,
    messages,
    set_db=True,
    wait_after_apply=5,
    max_updates_in_single_cmd=1024,
):
    """
    Apply HA messages to APPL_DB over gNMI.

    {
        "DASH_HA_SET_CONFIG_TABLE:<key>": {...},
        "DASH_HA_SCOPE_CONFIG_TABLE:<key1>:<key2>": {...},
    }
    """
    if GNMIEnvironment is None or write_gnmi_files is None:
        raise ModuleNotFoundError(
            "Failed to import GNMIEnvironment/write_gnmi_files from tests/ha/gnmi_utils.py"
        )
    if proto_utils is None:
        raise ModuleNotFoundError(
            "Failed to import proto_utils for parse_dash_proto"
        )
    env = GNMIEnvironment(duthost)
    update_list = []
    delete_list = []
    for index, (key, config_dict) in enumerate(messages.items()):
        message = proto_utils.parse_dash_proto(key, config_dict)
        keys = key.split(":", 1)
        gnmi_key = keys[0] + "[key=" + keys[1] + "]"
        if set_db:
            filename = f"update{index}"
            path = env.work_dir + filename
            with open(path, "wb") as file:
                file.write(message.SerializeToString())
            update_list.append(
                f"/APPL_DB/localhost/{gnmi_key}:$/root/{filename}"
            )
            continue
        delete_list.append(f"/APPL_DB/localhost/{gnmi_key}")

    write_gnmi_files(
        localhost,
        duthost,
        ptfhost,
        env,
        delete_list,
        update_list,
        max_updates_in_single_cmd,
    )

    time.sleep(wait_after_apply)
