import logging


class SDSBlockEndpoints(object):
    GET_SERVERS = "v1/objects/servers"
    POST_SERVERS = "v1/objects/servers"
    GET_SERVER_BY_ID = "v1/objects/servers/{}"
    GET_SERVERS_AND_QUERY_NICKNAME = "v1/objects/servers?nickname={}"
    GET_SERVERS_AND_QUERY_NICKNAMES = "v1/objects/servers?nicknames={}"
    GET_SERVERS_AND_QUERY_HBA_NAME = "v1/objects/servers?hbaName={}"
    DELETE_SERVERS = "v1/objects/servers/{}"
    PATCH_SERVERS = "v1/objects/servers/{}"
    GET_VOLUME_SERVER_CONNECTIONS_AND_ID = (
        "v1/objects/volume-server-connections?serverId={}"
    )
    DELETE_VOLUMES = "v1/objects/volumes/{}"
    POST_HBAS = "v1/objects/servers/{}/hbas"
    GET_HBAS = "v1/objects/servers/{}/hbas"
    DELETE_HBAS = "v1/objects/servers/{}/hbas/{}"
    GET_PORTS = "v1/objects/ports"
    GET_PORT_BY_ID = "v1/objects/ports/{}"
    GET_PORT_BY_NAME = "v1/objects/ports?name={}"
    GET_PORTS_AND_QUERY = "v1/objects/ports?{}={}"
    GET_PATHS = "v1/objects/servers/{}/paths"
    POST_PATHS = "v1/objects/servers/{}/paths"
    DELETE_PATHS = "v1/objects/servers/{}/paths/{},{}"
    GET_POOLS = "v1/objects/pools"
    GET_POOLS_AND_ID = "v1/objects/pools/{}"
    GET_POOLS_AND_QUERY = "v1/objects/pools?name={}"
    GET_VOLUMES = "v1/objects/volumes"
    POST_VOLUMES = "v1/objects/volumes"
    GET_VOLUMES_AND_QUERY = "v1/objects/volumes?{}={}"
    GET_VOLUMES_AND_NICKNAME = "v1/objects/volumes?nickname={}"
    GET_VOLUMES_AND_SERVERID = "v1/objects/volumes?serverId={}"
    GET_VOLUMES_BY_ID = "v1/objects/volumes/{}"
    PATCH_VOLUMES = "v1/objects/volumes/{}"
    POST_VOLUME_SERVER_CONNECTIONS = "v1/objects/volume-server-connections"
    DELETE_VOLUME_SERVER_CONNECTIONS = "v1/objects/volume-server-connections/{},{}"
    GET_VOLUME_SERVER_CONNECTIONS_FOR_SERVERID = (
        "v1/objects/volume-server-connections?serverId={}"
    )
    GET_VOLUME_SERVER_CONNECTIONS_FOR_VOLUMEID = (
        "v1/objects/volume-server-connections?volumeId={}"
    )
    POST_VOLUMES_EXPAND = "v1/objects/volumes/{}/actions/expand/invoke"
    GET_CHAP_USERS = "v1/objects/chap-users"
    GET_CHAP_USER_BY_ID = "v1/objects/chap-users/{}"
    GET_CHAP_USERS_AND_QUERY = "v1/objects/chap-users?targetChapUserName={}"
    POST_CHAP_USERS = "v1/objects/chap-users"
    DELETE_CHAP_USERS = "v1/objects/chap-users/{}"
    PATCH_CHAP_USERS = "v1/objects/chap-users/{}"
    GET_PORT_AUTH_SETTINGS = "v1/objects/port-auth-settings/{}"
    PATCH_PORT_AUTH_SETTINGS = "v1/objects/port-auth-settings/{}"
    GET_PORT_AUTH_SETTINGS_CHAP_USERS = "v1/objects/port-auth-settings/{}/chap-users"
    POST_PORT_AUTH_SETTINGS_CHAP_USERS = "v1/objects/port-auth-settings/{}/chap-users"
    DELETE_PORT_AUTH_SETTINGS_CHAP_USERS = (
        "v1/objects/port-auth-settings/{}/chap-users/{}"
    )

    # All parameters
    GET_FAULT_DOMAINS = "v1/objects/fault-domains"
    GET_FAULT_DOMAINS_ID = "v1/objects/fault-domains/{}"
    GET_CONTROL_PORTS = "v1/objects/control-ports"
    GET_CONTROL_PORTS_ID = "v1/objects/control-ports/{}"
    GET_INTERNODE_PORTS = "v1/objects/internode-ports"
    GET_INTERNODE_PORTS_ID = "v1/objects/internode-ports/{}"
    GET_STORAGE_NODE_NETWORK_SETTINGS = "v1/objects/storage-node-network-settings"
    GET_STORAGE_NODE_NETWORK_SETTINGS_ID = "v1/objects/storage-node-network-settings/{}"
    GET_JOBS = "v1/objects/jobs/{}"
    GET_STORAGE_NODES_AND_QUERY = "v1/objects/storage-nodes?protectionDomainId={}"
    GET_DRIVES = "v1/objects/drives"
    POST_POOLS_EXPAND = "v1/objects/pools/{}/actions/expand/invoke"
    GET_STORAGE_CONTROLLERS = "v1/objects/storage-controllers"
    GET_STORAGE_CLUSTER = "v1/objects/storage"
    GET_HEALTH_STATUS = "v1/objects/health-status"
    GET_STORAGE_TIME_SETTINGS = "v1/objects/storage-time-setting"
    GET_STORAGE_NETWORK_SETTING = "v1/objects/storage-network-setting"
    GET_PROCTECTION_DOMAINS = "v1/objects/protection-domains"
    # GET_USERS = "v1/objects/users"
    # GET_USERS_BY_ID = "v1/objects/users/{}"

    GET_VPS = "v1/objects/virtual-private-storages"
    GET_VPS_BY_ID = "v1/objects/virtual-private-storages/{}"
    DELETE_VPS = "v1/objects/virtual-private-storages/{}"
    POST_VPS = "v1/objects/virtual-private-storages"
    UPDATE_VPS = "v1/objects/virtual-private-storages/{}"

    # Ticket Management Endpoints
    POST_TICKET = "v1/objects/tickets"
    DISCARD_TICKETS = "v1/objects/tickets/actions/revoke-all/invoke"

    # snapshot Endpoints
    GET_SNAPSHOTS_VOLUMES = "v1/objects/volumes/{}/snapshot-volumes"
    CREATE_SNAPSHOT = "v1/objects/volumes/actions/create-snapshot/invoke"
    DELETE_SNAPSHOT = "v1/objects/volumes/actions/delete-snapshot/invoke"
    RESTORE_SNAPSHOT = "v1/objects/volumes/actions/restore-snapshot/invoke"
    GET_MASTER_VOLUME = "v1/objects/volumes/{}/master-volume"

    # Storage controller settings
    SNMP_SETTINGS = "v1/objects/snmp-setting"
    PROTECTION_DOMAIN_SETTINGS = "v1/objects/protection-domains/"
    PROTECTION_DOMAIN_SETTINGS_BY_ID = "v1/objects/protection-domains/{}"
    RESUME_DRIVE = (
        "v1/objects/protection-domains/{}/actions/resume-drive-data-relocation/invoke"
    )
    SUSPEND_DRIVE = (
        "v1/objects/protection-domains/{}/actions/suspend-drive-data-relocation/invoke"
    )
    DELETE_ROOT_CERTIFICATE = "v1/objects/bmc-root-certificate/actions/delete/invoke"
    IMPORT_ROOT_CERTIFICATE = "v1/objects/bmc-root-certificate/actions/import/invoke"
    GET_BMC_ROOT_CERTIFICATE = "v1/objects/bmc-root-certificate/download"
    SPARE_NODES = "v1/objects/spare-nodes"
    SPARE_NODES_SINGLE = "v1/objects/spare-nodes/{}"
    CACHE_PROTECTION = (
        "v1/objects/storage/actions/set-write-back-mode-with-cache-protection/invoke"
    )

    IMPORT_SERVER_CERTIFICATE = "v1/objects/server-certificate/actions/import/invoke"
    WEB_SERVER_ACCESS_SETTING = "v1/objects/web-server-access-setting"
    # journals Endpoints
    GET_JOURNAL = "v1/objects/journals"
    GET_JOURNAL_BY_ID = "v1/objects/journals/{}"
    SHRINK_JOURNAL = "v1/objects/journals/{}/actions/shrink/invoke"
    EXPAND_JOURNAL = "v1/objects/journals/{}/actions/expand/invoke"

    # Login Message Endpoints
    GET_LOGIN_MESSAGE = "configuration/login-message"


class Http(object):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    BASE_URL = "/ConfigurationManager/simple/"
    CONTENT_TYPE = "Content-Type"
    APPLICATION_JSON = "application/json"
    HEADERS_JSON = {CONTENT_TYPE: APPLICATION_JSON}
    HTTP = "http://"
    HTTPS = "https://"
    DEFAULT_PORT = 443
    DEFAULT_SSL_PORT = 443
    OPEN_URL_TIMEOUT = 300
    USER_AGENT = "automation-module"


class ModuleArgs(object):
    CONNECTION_ADDRESS = "connection_address"
    NULL = "None"
    CHECK_MODE = "check_mode"
    SERVER = "management_address"
    SERVER_PORT = "management_port"
    USER = "user"
    PASSWORD = "password"
    SERVER_NICKNAME = "server_nickname"
    OS_TYPE = "os_type"
    ISCSI_NAME = "iscsi_name"
    TARGET_PORT_NAME = "target_port_name"
    POOL_NAME = "pool_name"
    CAPACITY = "capacity_mb"
    NUMBER = "number"
    BASE_NAME = "base_name"
    START_NUMBER = "start_number"
    NUMBER_OF_DIGIT = "number_of_digit"
    VOLUME_NAME = "volume_name"
    TARGET_CHAP_USER_NAME = "target_chap_user_name"
    TARGET_CHAP_SECRET = "target_chap_secret"
    INITIATOR_CHAP_USER_NAME = "initiator_chap_user_name"
    INITIATOR_CHAP_USER_SECRET = "initiator_chap_secret"
    POOL_EXPAND_CAPACITY = "pool_expand_capacity"
    EXPAND_POOL_PROCESS1_INFO = "expand_pool_process1_info"
    DEVICE_COUNT = "device_count"
    EC2_INSTANCE_INFO = "ec2_instance_info"
    SYSTEM_CONFIGRATION_FILE = "system_configuration_file"
    VM_CONFIGRATION_FILE = "vm_configuration_file"
    DRIVE_COUNT_IN_NODE = "drive_count_in_node"
    ADDITINAL_DRIVE_COUNT_IN_NODE = "additional_drive_count_in_node"
    ADD_STORAGENODE_PROCESS1_INFO = "add_storagenode_process1_info"
    TIME_A = "time_a"
    TIME_B = "time_b"
    TIME_C = "time_c"
    TIME_D = "time_d"


class AutomationConstants(object):
    PORT_NUMBER_MIN = 0
    PORT_NUMBER_MAX = 49151
    NAME_PARAMS_MIN = 1
    NAME_PARAMS_MAX = 256
    MIN_SIZE_ALLOWED = 1
    MAX_SIZE_ALLOWED = 999999999999
    MAX_TIME_ALLOWED = 999
    MIN_TIME_ALLOWED = 1
    CHAP_SECRET_MIN = 12
    CHAP_SECRET_MAX = 32
    QOS_UPPER_LIMIT_IOPS_MIN = 100
    QOS_UPPER_LIMIT_IOPS_MAX = 2147483647
    QOS_UPPER_LIMIT_XFER_RATE_MIN = 1
    QOS_UPPER_LIMIT_XFER_RATE_MAX = 2097151
    QOS_UPPER_ALERT_ALLOWABLE_TIME_OUT_MIN = 1
    QOS_UPPER_ALERT_ALLOWABLE_TIME_OUT_MAX = 600
    JOB_COUNT_MIN = 1
    JOB_COUNT_MAX = 100


class EncryptionConstants(object):
    # Response field names
    ENCRYPTION_KEY_COUNTS = "encryption_key_counts"
    DEK = "dek"
    FREE = "free"
    ENCRYPTION_SETTINGS = "encryption_settings"
    IS_ENABLED = "is_enabled"
    KMS = "kms"
    WARNING_THRESHOLD_OF_FREE_KEYS = "warning_threshold_of_free_keys"

    # Transformed field names
    TOTAL_ALLOCATED_ENCRYPTION_TARGETS = "total_allocated_encryption_targets"
    TOTAL_UNALLOCATED_ENCRYPTION_TARGETS = "total_unallocated_encryption_targets"
    IS_ENCRYPTION_KEY_MANAGEMENT_SERVER_IN_USE = (
        "is_encryption_key_management_server_in_use"
    )
    FREE_KEYS_WARNING_THRESHOLD = "free_keys_warning_threshold"


class ErrorMessages(object):
    INVALID_PORT_NUMBER_ERR = (
        "The specified value is invalid"
        + " ({}: {}). Specify the value within a valid range (min: "
        + str(AutomationConstants.PORT_NUMBER_MIN)
        + ", max: "
        + str(AutomationConstants.PORT_NUMBER_MAX)
        + ")."
    )
    HTTP_4xx_ERRORS = (
        "Invalid request sent by the client."
        + " API responded with client error code ({}). Reason: {}"
    )
    HTTP_5xx_ERRORS = (
        "The server encountered an unexpected "
        + "condition. API responded with server error code ({}). Reason: {}"
    )
    API_COMMUNICATION_ERR = (
        "Communication with the target server" + " failed. Reason: {}"
    )
    NOT_AVAILABLE = "Not Available."
    REQUIRED_VALUE_ERR = (
        "The value for the parameter is" + " required. ({}) Specify a valid value."
    )
    API_TIMEOUT_ERR = (
        "A timeout occurred because no response" + " was received from the server."
    )
    INVALID_TYPE_VALUE = (
        "The specified value is not an integer"
        + " type ({}: {}). Specify an integer value."
    )
    INVALID_NAME_SIZE = (
        "The argument of the parameter name length is invalid"
        + " ({}: {}). Specify in a valid range characters"
    )
    INVALID_SIZE_VALUE = (
        "The specified size argument has an invalid range"
        + " ({}: {}). Specify in a valid range."
    )
    INVALID_TIME_VALUE = (
        "The specified time argument has an invalid range"
        + " ({}: {}). Specify in a valid range."
    )
    INVALID_SECRET_SIZE = (
        "The specified value is invalid" + " ({}: {}). Secret should be 12 to 32 chars."
    )


class LogMessages(object):
    ENTER_METHOD = "Enter method: {}"
    LEAVE_METHOD = "Leave method: {}"
    API_REQUEST_START = "API Request: {} {}"
    API_RESPONSE = "API Response: {}"


class Log(object):
    SYSLOG_IDENTIFIER = "SYSLOG_IDENTIFIER"
    PRIORITY = "PRIORITY"
    # There is no applicable level in Python for following priorities
    # 0(Emergency), 1(Alert), 5(Notice)
    ARGS = {
        logging.DEBUG: {PRIORITY: 7},
        logging.INFO: {PRIORITY: 6},
        logging.WARNING: {PRIORITY: 4},
        logging.ERROR: {PRIORITY: 3},
        logging.CRITICAL: {PRIORITY: 2},
    }
