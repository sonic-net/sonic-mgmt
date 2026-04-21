TARGET_SUB_DIRECTORY = "ansible_collections/hitachivantara/vspone_block"


class Http(object):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    BASE_URL = "/ConfigurationManager/"
    CONTENT_TYPE = "Content-Type"
    APPLICATION_JSON = "application/json"
    RESPONSE_JOB_STATUS = "Response-Job-Status"
    COMPLETED = "Completed"
    HEADERS_JSON = {CONTENT_TYPE: APPLICATION_JSON, RESPONSE_JOB_STATUS: COMPLETED}
    HTTP = "http://"
    HTTPS = "https://"
    DEFAULT_PORT = 443
    DEFAULT_SSL_PORT = 443
    OPEN_URL_TIMEOUT = 300
    USER_AGENT = "automation-module"


class LogMessages(object):
    ENTER_METHOD = "Enter method: {}"
    LEAVE_METHOD = "Leave method: {}"
    API_REQUEST_START = "API Request: {} {}"
    API_RESPONSE = "API Response: {}"


class StateValue:
    """
    Enum class for volume state
    """

    QUERY = "query"
    PRESENT = "present"
    ABSENT = "absent"
    SPLIT = "split"
    SYNC = "sync"
    RESTORE = "restore"
    UPDATE = "update"
    RE_SYNC = "resync"
    RESIZE = "resize"
    EXPAND = "expand"
    CLONE = "clone"
    SWAP_RESYNC = "swap_resync"
    SWAP_SPLIT = "swap_split"
    EXPAND_JOURNAL = "expand_journal"
    SHRINK_JOURNAL = "shrink_journal"
    EXPAND_JOURNAL_VOLUME = "expand_journal_volume"
    SHRINK_JOURNAL_VOLUME = "shrink_journal_volume"
    MIGRATE = "migrate"
    RM_EXTERNAL_PATH = "remove_external_path"
    ADD_EXTERNAL_PATH = "add_external_path"
    DEFRAGMENT = "defragment"
    LOGIN_TEST = "login_test"
    REGISTER_EXTERNAL_ISCSI_TARGET = "register_external_iscsi_target"
    UNREGISTER_EXTERNAL_ISCSI_TARGET = "unregister_external_iscsi_target"
    DISCONNECT = "disconnect"
    TAKEOVER = "takeover"
    INIT_CAPACITY = "init_capacity_saving"
    RELOCATE = "tier_relocate"
    MONITOR = "monitor_performance"
    ASSIGN_LDEV = "assign_ldev"
    ASSIGN_CLPR_ID = "assign_clpr_id"
    TEST = "test"
    ASSIGN_EXTERNAL_PARITY_GROUP = "assign_external_parity_group"
    CHANGE_MP_BLADE = "change_mp_blade"
    MAINTENANCE = "maintenance"
    ADD_STORAGE_NODE = "add_storage_node"
    REMOVE_STORAGE_NODE = "remove_storage_node"
    DOWNLOAD_CONFIG_FILE = "download_config_file"
    STOP_REMOVING_STORAGE_NODE = "stop_removing_storage_node"
    REPLACE_STORAGE_NODE = "replace_storage_node"
    ATTACH_SERVER = "attach_server"
    DETACH_SERVER = "detach_server"
    SERVER_PRESENT = "server_present"
    UPDATE_QOS = "change_qos_settings"
    ASSIGN_VIRTUAL_LDEV = "assign_virtual_ldev"
    SYNC_SERVER_NICK_NAME = "sync_server_nick_name"
    ADD_HG_TO_SERVER = "add_host_groups"
    ADD_HBA = "add_hba"
    REMOVE_HBA = "remove_hba"
    ADD_PATH = "add_path"
    REMOVE_PATH = "remove_path"
    MAP = "map"
    CHANGE_ISCSI_TARGET_SETTINGS = "change_iscsi_target_settings"
    SOFTWARE_UPDATE_FILE_PRESENT = "software_update_file_present"
    RESUME_DRIVE_DATA_RELOCATION = "resume_drive_data_relocation"
    SUSPEND_DRIVE_DATA_RELOCATION = "suspend_drive_data_relocation"
    DELETE_ROOT_CERTIFICATE = "delete_root_certificate"
    IMPORT_ROOT_CERTIFICATE = "import_root_certificate"
    DOWNLOAD_ROOT_CERTIFICATE = "download_root_certificate"
    SYSTEM_REQUIREMENT_FILE_PRESENT = "system_requirement_file_present"
    STOP_STORAGE_CLUSTER = "stop_storage_cluster"
    ADD_REMOTE_PATH = "add_remote_path"
    REMOVE_REMOTE_PATH = "remove_remote_path"
    IMPORT_CERTIFICATE = "import_certificate"
    ADD_USER_GROUP = "add_user_group"
    REMOVE_USER_GROUP = "remove_user_group"


class CommonConstants:
    # UCP_NAME = 'ucp-ansible-test'
    UCP_NAME_PREFIX = "REMOTE_STORAGE_SYSTEM_"
    UCP_NAME = "Storage_System"
    UCP_SERIAL_PREFIX = "UCP-CI-"
    UCP_SERIAL = "UCP-CI-202404"
    UCP_REMOTE_SERIAL = "UCP-CI-881734"
    PARTNER_ID = "apiadmin"
    SUBSCRIBER_ID = "12345"
    ONBOARDING = "ONBOARDING"
    NORMAL = "NORMAL"


class ConnectionTypes:
    GATEWAY = "gateway"
    DIRECT = "direct"


class GatewayClassTypes:
    VSP_VOLUME = "vsp_volume"
    VSP_HOST_GROUP = "vsp_host_group"
    VSP_SNAPSHOT = "vsp_snapshot"
    VSP_SHADOW_IMAGE_PAIR = "vsp_shadow_image_pair"
    VSP_STORAGE_SYSTEM = "vsp_storage_system"
    VSP_ISCSI_TARGET = "vsp_iscsi_target"
    VSP_STORAGE_POOL = "vsp_storage_pool"
    VSP_JOURNAL_VOLUME = "vsp_journal_volume"
    VSP_PARITY_GROUP = "vsp_parity_group"
    VSP_TRUE_COPY = "vsp_true_copy"
    VSP_HUR = "vsp_hur"
    VSP_VOL_TIER = "vsp_vol_tier"
    VSP_GAD_PAIR = "vsp_gad_pair"
    VSP_EXT_VOLUME = "vsp_external_volume"
    VSP_QUORUM_DISK = "vsp_quorum_disk"
    VSP_NVME_SUBSYSTEM = "vsp_one_nvme_subsystem"
    VSP_RESOURCE_GROUP = "vsp_resource_group"
    VSP_USER_GROUP = "vsp_user_group"
    VSP_USER = "vsp_user"
    VSP_COPY_GROUPS = "vsp_copy_groups"
    VSP_REMOTE_COPY_GROUPS = (
        "vsp_remote_copy_groups"  # TODO: sng1104 use VSP_COPY_GROUPS
    )
    VSP_LOCAL_COPY_GROUP = "vsp_local_copy_group"
    VSP_CLPR = "vsp_clpr"
    VSP_CMD_DEV = "vsp_cmd_dev"
    VSP_RG_LOCK = "vsp_rg_lock"
    VSP_CONFIG_MAP = "vsp_config_map"

    SDSB_CHAP_USER = "sdsb_chap_user"
    SDSB_EVENT_LOGS = "sdsb_event_logs"
    SDSB_BLOCK_DRIVES = "sdsb_block_drives"
    SDSB_FAULT_DOMAIN = "sdsb_fault_domain"
    SDSB_USER = "sdsb_user"
    SDSB_STORAGE_CONTROLLER = "sdsb_storage_controller"
    SDSB_CONTROL_PORT = "sdsb_control_port"
    SDSB_COMPUTE_NODE = "sdsb_compute_node"
    SDSB_VOLUME = "sdsb_volume"
    SDSB_STORAGE_SYSTEM = "sdsb_storage_system"
    SDSB_PORT_AUTH = "sdsb_port_auth"
    SDSB_PORT = "sdsb_port"
    SDSB_VPS = "sdsb_vps"
    SDSB_STORAGE_NODE = "sdsb_storage_node"
    SDSB_STORAGE_POOL = "sdsb_storage_pool"
    SDSB_CLUSTER = "sdsb_cluster"
    SDSB_CLUSTER_INFORMATION = "sdsb_cluster_information"
    SDSB_JOB = "sdsb_job"
    SDSB_BMC_ACCESS_SETTING = "sdsb_bmc_access_setting"
    SDSB_CAPACITY_MGMT_SETTING = "sdsb_capacity_mgmt_setting"
    SDSB_ESTIMATED_CAPACITY = "sdsb_estimated_capacity"
    SDSB_REMOTE_ISCSI_PORT = "sdsb_remote_iscsi_port"
    SDSB_SOFTWARE_UPDATE = "sdsb_software_update"
    SDSB_JOURNAL = "sdsb_journal"
    SDSB_LOGIN_MESSAGE = "sdsb_login_message"

    UAIG_SUBSCRIBER = "uaig_subscriber"
    UAIG_PASSWORD = "uaig_password"
    UAIG_SUBSCRIBER_RESOURCE = "uaig_subscriber_resource"
    STORAGE_PORT = "storage_port"
    VSP_STORAGE_POOL = "vsp_storage_pool"
    VSP_UNSUBSCRIBE = "vsp_unsubscribe"
    VSP_REMOTE_STORAGE_REGISTRATION = "vsp_remote_storage_registration"
    VSP_REMOTE_CONNECTION = "vsp_remote_connection"
    VSP_ISCSI_REMOTE_CONNECTION = "vsp_iscsi_remote_connection"
    VSP_DYNAMIC_POOL = "vsp_dynamic_pool"
    VSP_UVM = "vsp_universal_volume_manager"
    VSP_EXT_PARITY_GROUP = "vsp_external_parity_group"
    VSP_SPM = "vsp_server_priority_manager"
    VSP_STORAGE_MONITOR = "vsp storage system monitor"


class VSPHostGroupConstant:
    PORT_TYPE_ISCSI = "ISCSI"
    PORT_TYPE_FIBRE = "FIBRE"
    PORT_TYPE_FCOE = "FCoE"
    PORT_TYPE_HNASS = "HNASS"
    PORT_TYPE_HNASU = "HNASU"
    STATE_PRESENT_LDEV = "present_ldev"
    STATE_UNPRESENT_LDEV = "unpresent_ldev"
    STATE_SET_HOST_MODE = "set_host_mode_and_hmo"
    STATE_ADD_WWN = "add_wwn"
    STATE_REMOVE_WWN = "remove_wwn"


class VSPIscsiTargetConstant:
    PORT_TYPE_ISCSI = "ISCSI"
    AUTH_MODE_CHAP = "CHAP"
    AUTH_MODE_NONE = "NONE"
    AUTH_MODE_BOTH = "BOTH"
    AUTH_DIRECTION_ONE_WAY = "S"
    AUTH_DIRECTION_MUTUAL = "D"
    WAY_OF_CHAP_USER = "INI"
    STATE_ADD_INITIATOR = "add_iscsi_initiator"
    STATE_REMOVE_INITIATOR = "remove_iscsi_initiator"
    STATE_ATTACH_LDEV = "attach_ldev"
    STATE_DETACH_LDEV = "detach_ldev"
    STATE_ADD_CHAP_USER = "add_chap_user"
    STATE_REMOVE_CHAP_USER = "remove_chap_user"


class GatewayConstant:
    ADMIN_USER_NAME = "admin"


class HEADER_NAME_CONSTANT:
    PARTNER_ID = "partnerId"
    SUBSCRIBER_ID = "subscriberId"


class PoolType:
    HDT = "HDT"
    HDP = "HDP"
    HTI = "HTI"
    HRT = "HRT"
    RT = "RT"


# add to be ignored api end points details like which we not need to get the telemetry data
# Like below example , for UAIG add the api end points which don't have storage id in the url
IGNORED_APIS = [
    "sessions",
    "auth",
    "login",
    "logout",
    "porcelain/v2/systems",
    "jobs",
    "tasks",
    "common/config/property/outofband",
]
