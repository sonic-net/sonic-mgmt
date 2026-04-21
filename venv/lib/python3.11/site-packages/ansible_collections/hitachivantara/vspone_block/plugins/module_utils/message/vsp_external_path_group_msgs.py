from enum import Enum


class VSPSExternalPathGroupValidateMsg(Enum):
    EXT_PATH_GROUP_ID_REQD = (
        "external_path_group_id is a required field, which is missing."
    )
    PATHS_REQD = "External path group specification must contain at least one external path. Please specify external_fc_paths or external_iscsi_target_paths."
    FC_PATH_FIELDS = "External FC path must contain port and external_wwn."
    ADD_FC_PATH_FAILED = (
        "Failed to add external FC path to path group: port = {}, external_wwn= {}."
    )
    DEL_FC_PATH_FAILED = "Failed to remove external FC path from path group: port = {}, external_wwn= {}."
    ISCSI_PATH_FIELDS = (
        "External iSCSI target path must contain external iSCSI IP address and name."
    )
    ADD_ISCSI_PATH_FAILED = "Failed to add external iSCSI target path to path group. port = {}, external_iscsi_ip_address = {}, external_iscsi_name = {}."
    DEL_ISCSI_PATH_FAILED = "Failed to remove external iSCSI target path from path group. port = {}, external_iscsi_ip_address = {}, external_iscsi_name = {}."
