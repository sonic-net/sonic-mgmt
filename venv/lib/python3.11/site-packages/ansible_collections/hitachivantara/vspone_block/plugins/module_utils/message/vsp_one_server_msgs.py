from enum import Enum


class VSPOneServerMessage(Enum):
    pass


class VSPOneServerMSG(Enum):
    # Server existence validation messages
    SERVER_WITH_NICKNAME_NOT_FOUND = "Server with nick_name '{nickname}' not found"
    SERVER_ID_OR_NICKNAME_REQUIRED = "Either server_id or nick_name must be provided"
    SERVER_WITH_ID_NOT_EXIST = "Server with ID {server_id} does not exist"
    ERROR_CHECKING_SERVER_EXISTENCE = (
        "Error occurred while checking server existence: {error}"
    )

    # Server creation messages
    ERROR_CREATING_SERVER = "Error creating server: {}"
    NAME_ERROR = (
        "Error in server nick_name parameter: You can use 1 through 229 "
        "alphanumeric characters, 0 through 9, A through Z, a through z), "
        "space characters, and symbols: Comma (,), Hyphen (-), periods (.), "
        "forward slash (/), colon (:), at sign (@), back slash (\\), "
        "underscore (_)"
    )

    # Server deletion messages
    SERVER_DELETED_SUCCESS = "Server deleted successfully."
    ERROR_DELETING_SERVER = "Error deleting server: {error}"
    SERVER_NOT_FOUND_OR_DELETED = "Server does not exist or has already been deleted."

    # Server update messages
    SERVER_UPDATED_SUCCESS = "Server updated successfully."
    ERROR_UPDATING_SERVER = "Error updating server: {error}"

    # Host group management messages
    HOST_GROUP_ADDED_SUCCESS = "Host group/iSCSI target added successfully."
    ERROR_ADDING_HOST_GROUP = "Error adding host group/iSCSI target: {error}"

    # Path management messages
    PATH_ADDED_SUCCESS = "Path {port_ids} added successfully."
    ERROR_VALIDATING_EXISTING_PATHS = "Error validating existing paths: {error}"
    PATH_REMOVED_SUCCESS = "Path with port ID {port_id} removed successfully."
    ERROR_REMOVING_PATH = "Error removing path: {error}"

    # Server nickname sync messages
    SERVER_NICKNAME_SYNCED_SUCCESS = "Server nick name synced successfully."

    # HBA management messages
    WWN_HBA_ADDED_SUCCESS = "WWNs of HBA or iSCSI names added successfully."
    NO_NEW_HBAS_TO_ADD = "No new HBAs or iSCSI names to add."
    WWN_HBA_REMOVED_SUCCESS = "{wwn_or_iscsi} removed successfully."
    ERROR_REMOVING_WWN_HBA = "Error removing WWN of HBA or iSCSI Name: {error}"

    # iSCSI target settings messages
    ISCSI_TARGET_PORT_ID_REQUIRED = (
        "Either port_id or iscsi_target must be provided in iscsi_target settings"
    )
    ISCSI_TARGET_BOTH_REQUIRED = (
        "Both port_id and iscsi_target_name must be provided in iscsi_target settings"
    )
    ISCSI_TARGET_CHANGED_SUCCESS = (
        "iSCSI target settings changed successfully for port {port_id}."
    )
    ERROR_CHANGING_ISCSI_TARGET = (
        "Error changing iSCSI target settings for port {port_id}: {error}"
    )

    # Example usage in the class (replace string literals with enum values):
    # spec.comments.append(VSPOneServerMSG.SERVER_DELETED_SUCCESS.value)
    # raise ValueError(VSPOneServerMSG.SERVER_ID_OR_NICKNAME_REQUIRED.value)
    SERVER_ID_NAME_REQUIRED = "Either server_id or nick_name must be provided"

    ISCSI_NAME_REQUIRED_FOR_ISCSI = (
        "list of iscsi_name(s) is required when protocol is 'iSCSI'."
    )
    HBA_WWN_REQUIRED_FOR_FC = "list of hba_wwn(s) is required when protocol is 'FC'."

    HBA_LIST_REQUIRED = (
        "hbas list cannot be empty when adding or removing HBAs to/from server."
    )
    PATHS_LIST_REQUIRED = (
        "paths list cannot be empty when adding or removing paths to/from server."
    )


class VSPOneServerValidationMsg(Enum):
    # Server validation messages
    SERVER_ID_REQUIRED = "server_id is required for this operation."
    NICKNAME_REQUIRED = "nick_name is required for server creation."
    PROTOCOL_REQUIRED = "protocol is required for server creation."
    INVALID_PROTOCOL = (
        "Invalid protocol '{protocol}'. Supported values are 'FC' and 'iSCSI'."
    )
    OS_TYPE_INVALID = "Invalid os_type '{os_type}'. Supported values are 'Linux', 'Windows', 'VMware', 'AIX', 'HP-UX', 'Solaris'."

    # HBA validation messages
    HBA_WWN_REQUIRED_FOR_FC = "hba_wwn is required when protocol is 'FC'."
    ISCSI_NAME_REQUIRED_FOR_ISCSI = "iscsi_name is required when protocol is 'iSCSI'."
    INVALID_WWN_FORMAT = (
        "Invalid HBA WWN format: '{wwn}'. Expected format: XX:XX:XX:XX:XX:XX:XX:XX"
    )
    INVALID_ISCSI_NAME_FORMAT = (
        "Invalid iSCSI name format: '{iscsi_name}'. Expected IQN format."
    )

    # Host group validation messages
    HOST_GROUP_PORT_ID_REQUIRED = "port_id is required for host group configuration."
    HOST_GROUP_ID_OR_NAME_REQUIRED = (
        "Either host_group_id or host_group_name must be provided."
    )

    # Path validation messages
    PATH_PORT_IDS_REQUIRED = "port_ids is required for path configuration."
    PATH_HBA_OR_ISCSI_REQUIRED = (
        "Either hba_wwn or iscsi_name must be provided for path configuration."
    )

    # iSCSI target validation messages
    ISCSI_TARGET_NAME_REQUIRED = (
        "iscsi_target_name is required for iSCSI target configuration."
    )
    ISCSI_TARGET_PORT_ID_REQUIRED = (
        "port_id is required for iSCSI target configuration."
    )
    INVALID_ISCSI_TARGET_FORMAT = (
        "Invalid iSCSI target name format: '{target_name}'. Expected IQN format."
    )

    # General validation messages
    CONFLICTING_PARAMETERS = "Conflicting parameters provided: {parameters}"
    MISSING_REQUIRED_PARAMETER = "Missing required parameter: {parameter}"
    INVALID_PARAMETER_VALUE = "Invalid value '{value}' for parameter '{parameter}'"
    PARAMETER_OUT_OF_RANGE = (
        "Parameter '{parameter}' value '{value}' is out of valid range {range}"
    )
