import logging


class Endpoints(object):
    # GET_SNAPSHOTS = "v2/storage/devices/{}/snapshotpairs"
    GET_SNAPSHOTS_V3 = "v3/storage/devices/{}/snapshotpairs"
    GET_SNAPSHOT = "v2/storage/devices/{}/snapshotpair/{}"

    GET_SNAPSHOT_BY_PVOL = "v2/storage/devices/{}/snapshotpair/?primaryLunId={}"

    DELETE_SNAPSHOT = "v2/storage/devices/{}/snapshotpair/{}"
    CREATE_SNAPSHOT = "v2/storage/devices/{}/snapshotpair"
    CREATE_SNAPSHOT_V3 = "v3/storage/devices/{}/snapshotPair"
    RESYNC_SNAPSHOT = "v2/storage/devices/{}/snapshotpair/{}/resync"
    CLONE_SNAPSHOT = "v2/storage/devices/{}/snapshotpair/{}/clone"
    SPLIT_SNAPSHOT = "v2/storage/devices/{}/snapshotpair/{}/split"
    RESTORE_SNAPSHOT = "v2/storage/devices/{}/snapshotpair/{}/restore"
    GET_UCPSYSTEMS = "v2/systems"
    GET_UCPSYSTEM = "v2/systems/{}"
    GET_SUBSCRIBER = "v3/partner/{partnerId}/subscriber/{subscriberId}"
    GET_ALL_SUBSCRIBERS = "v3/partner/{partnerId}/subscribers"
    CREATE_SUBSCRIBER = "v3/register/subscriber"
    DELETE_SUBSCRIBER = "v3/unregister/subscriber/{subscriberId}"
    UPDATE_SUBSCRIBER = "v3/partner/{partnerId}/subscriber/{subscriberId}"
    GET_TASK = "v2/tasks/{}"
    GET_USERS = "v2/rbac/users"
    UPDATE_PASSWORD = "v2/rbac/users/{id}"

    #  Subscriber related endpoints
    GET_SUBSCRIBER_RESOURCES = "v3/partner/{}/subscriber/{}/resources"
    UNTAG_SUBSCRIBER_RESOURCE = "v3/storage/{}/resource/{}?type={}&subscriberId={}"
    GET_STORAGE_DEVICE_BY_ID = "v2/storage/devices/{}"

    #  Host Group
    GET_HOST_GROUPS = "v2/storage/devices/{}/hostGroups"
    GET_HOST_GROUP_BY_ID = "v2/storage/devices/{}/hostGroups/{}"
    CREATE_HOST_GROUP = "v2/storage/devices/{}/hostGroups"

    UAIG_GET_HOST_GROUPS = "v3/storage/devices/{}/hostGroups"
    UAIG_CREATE_HOST_GROUP = "v3/storage/devices/{}/hostGroups"

    #  Volumes
    GET_VOLUMES = "v2/storage/devices/{}/volumes"
    GET_VOLUME_BY_ID = "v2/storage/devices/{}/volumes/{}"
    UAIG_GET_VOLUMES = "v3/storage/{}/volume?fromLdevId=0&toLdevId=65535"

    #  Parity Group
    GET_PARITY_GROUPS = "v2/storage/devices/{}/parityGroups"

    #  Storage Ports
    GET_PORTS = "v2/storage/devices/{}/ports"
    UAIG_GET_PORTS = "v3/storage/{}/ports"
    UAIG_TAG_PORT = "v3/storage/{}/resource"

    GET_REPLICATION_PAIRS = "v2/storage/devices/{}/replicationPairs"
    GET_REPLICATION_PAIRS_REFRESH = (
        "v2/storage/devices/{}/replicationPairs?refresh=true"
    )
    GET_GAD_PAIRS_V3 = "v3/storage/devices/{}/gadpairs"
    GAD_SINGLE_PAIR_V3 = "v3/storage/devices/{}/gadpair/{}"
    SPLIT_GAD_PAIR = "v2/storage/devices/{}/gadpair/{}/split"
    RESYNC_GAD_PAIR = "v2/storage/devices/{}/gadpair/{}/resync"
    SWAP_SPLIT_GAD_PAIR = "v2/storage/devices/{}/gadpair/{}/swap-split"
    SWAP_RESYNC_GAD_PAIR = "v2/storage/devices/{}/gadpair/{}/swap-resync"
    SPLIT_GAD_PAIR_V3 = "v3/storage/devices/{}/gadpair/{}/split"
    RESYNC_GAD_PAIR_V3 = "v3/storage/devices/{}/gadpair/{}/resync"
    POST_GAD_PAIR = "v3/storage/devices/gadpair"
    GET_REPLICATION_PAIR_BY_ID = "v2/storage/devices/{}/replicationPair/{}"

    #  TrueCopy
    GET_TRUE_COPY_PAIRS = "v3/storage/devices/{}/truecopypairs"
    # CREATE_TRUE_COPY_PAIR = "v2/storage/devices/truecopypair"
    CREATE_TRUE_COPY_PAIR = "v3/storage/devices/truecopypair"
    DELETE_TRUE_COPY_PAIR = (
        "v3/storage/devices/{}/truecopypair/{}?isDelete=True&deleteLun={}"
    )
    # DELETE_TRUE_COPY_PAIR = "v2/storage/devices/{}/truecopypair/{}"
    RESYNC_TRUE_COPY_PAIR = "v2/storage/devices/{}/truecopypair/{}/resync"
    SPLIT_TRUE_COPY_PAIR = "v2/storage/devices/{}/truecopypair/{}/split"
    SWAP_SPLIT_TRUE_COPY_PAIR = "v2/storage/devices/{}/truecopypair/{}/swap-split"
    SWAP_RESYNC_TRUE_COPY_PAIR = "v2/storage/devices/{}/truecopypair/{}/swap-resync"

    GET_HUR_PAIRS = "v3/storage/devices/{}/hurpairs"
    GET_HUR_PAIR_BY_ID = "v2/storage/devices/{}/hurpair/{}"
    CREATE_HUR_PAIR_V2 = "v2/storage/devices/hurpair"
    CREATE_HUR_PAIR = "v3/storage/devices/hurpair"
    DELETE_HUR_PAIR = "v3/storage/devices/{}/hurpair/{}?isDelete=true"
    RESYNC_HUR_PAIR = "v2/storage/devices/{}/hurpair/{}/resync"
    SPLIT_HUR_PAIR = "v2/storage/devices/{}/hurpair/{}/split"
    SWAP_SPLIT_HUR_PAIR = "v2/storage/devices/{}/hurpair/{}/swap-split"
    SWAP_RESYNC_HUR_PAIR = "v2/storage/devices/{}/hurpair/{}/swap-resync"

    #  Pool management
    GET_POOLS = "v2/storage/devices/{}/pools"
    POST_POOLS = "v2/storage/devices/{}/pools"
    SINGLE_POOL = "v2/storage/devices/{}/pools/{}"
    SINGLE_POOL_V3 = "v3/storage/{}/pools/{}"
    STORAGE_POOL_DUP = "v2/storage/devices/{}/pools/{}/duplication"

    MT_STORAGE_POOL = "v3/storage/{}/pools"
    SINGLE_STORAGE_POOL = "v3/storage/{}/pools/{}"

    APPLY_VOL_TIERING = "v2/policies/luntiering"

    #  Journal Volume management
    GET_JOURNAL_VOLUMES = "v2/storage/devices/{0}/journalpool?ucpSystem={1}"
    POST_JOURNAL_VOLUMES = "v2/storage/devices/{0}/journalPool"
    UPDATE_JOURNAL_VOLUMES = "v2/storage/devices/{0}/journalPool/{1}"
    JOURNAL_VOLUMES_EXPAND = "v2/storage/devices/{0}/journalPool/{1}/expand"
    JOURNAL_VOLUMES_SHRINK = "v2/storage/devices/{0}/journalPool/{1}/shrink"
    JOURNAL_VOLUMES_MP_BLADE = "v2/storage/devices/{0}/journalPool/{1}/mpBlade"
    DELETE_JP = "v2/storage/devices/{0}/journalPool/{1}"


class Http(object):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    BASE_URL = "/ConfigurationManager/"
    CONTENT_TYPE = "Content-Type"
    APPLICATION_JSON = "application/json"
    RESPONSE_JOB_STATUS = "Response-Job-Status"
    COMPLETED = "Completed"
    HEADERS_JSON = {CONTENT_TYPE: APPLICATION_JSON, RESPONSE_JOB_STATUS: COMPLETED}
    HTTP = "http://"
    HTTPS = "https://"
    DEFAULT_PORT = 22015
    DEFAULT_SSL_PORT = 22016
    OPEN_URL_TIMEOUT = 300
    USER_AGENT = "automation-module"


class ModuleArgs(object):
    NULL = "None"
    SERVER = "management_address"
    SERVER_PORT = "management_port"
    USER = "user"
    PASSWORD = "password"
    CHECK_MODE = "check_mode"
    STORAGE_DEVICE_ID = "storage_device_id"
    POOL_ID = "pool_id"
    BLOCK_CAPACITY = "block_capacity"
    CAPACITY_MB = "capacity_mb"
    PORT_ID = "port_id"
    HOST_GROUP_NAME = "host_group_name"
    ISCSI_NAME = "iscsi_name"
    NICK_NAME = "nick_name"
    HOST_GROUP_NUMBER = "host_group_number"
    LDEV_ID = "ldev_id"
    DATA_REDUCTION_MODE = "data_reduction_mode"
    COPY_GROUP_NAME = "copy_group_name"
    PVOL_LDEV_ID = "pvol_ldev_id"
    SVOL_LDEV_ID = "svol_ldev_id"
    COPY_PACE = "copy_pace"
    CONSISTENCY_GROUP_ID = "consistency_group_id"
    SNAPSHOT_GROUP_NAME = "snapshot_group_name"
    SNAPSHOT_POOL_ID = "snapshot_pool_id"
    COPY_SPEED = "copy_speed"
    IS_CONSISTENCY_GROUP = "is_consistency_group"
    COPY_PAIR_NAME = "copy_pair_name"
    MU_NUMBER = "mu_number"
    GENERATIONS = "generations"
    EXTERNAL_PORT_ID = "external_port_id"
    EXTERNAL_LUN = "external_lun"
    EXTERNAL_PARITYGROUP_ID = "external_paritygroup_id"
    EXTERNAL_IP = "external_IP"
    EXTERNAL_PORT_NUMBER = "external_port_number"
    EXTERNAL_ISCSI_TARGET = "external_iscsi_target"
    EXTERNAL_PATHGROUP_ID = "external_pathgroup_id"
    ADVISOR_PORT = "advisor_port"
    CHAP_USER_NAME = "chap_user_name"
    WAY_OF_CHAP_USER = "way_of_chap_user"
    CHAP_PASSWORD = "chap_password"
    HOST_MODE = "host_mode"
    SHREDDING_PATTERN = "shredding_pattern"
    DELETE_LDEV = "delete_ldev"


class State(object):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"

    @staticmethod
    def is_failed(status):
        return status in [State.FAILED, State.CANCELED]

    @staticmethod
    def is_finished(status):
        return status in [State.COMPLETED, State.FAILED, State.CANCELED]


class AutomationConstants(object):
    PORT_NUMBER_MIN = 0
    PORT_NUMBER_MAX = 49151
    NAME_PARAMS_MIN = 1
    NAME_PARAMS_MAX = 256
    MIN_SIZE_ZERO_ALLOWED = 0
    MIN_SIZE_ALLOWED = 1
    MAX_SIZE_ALLOWED = 999999999999
    MAX_TIME_ALLOWED = 999
    MIN_TIME_ALLOWED = 1
    POOL_ID_MIN = 0
    POOL_ID_MAX = 256
    LDEV_ID_MIN = 0
    LDEV_ID_MAX = 65535


# class ErrorMessages(object):
#     INVALID_PORT_NUMBER_ERR = 'The specified value is invalid' +\
#         ' ({}: {}). Specify the value within a valid range (min: ' +\
#         str(AutomationConstants.PORT_NUMBER_MIN) + ', max: ' +\
#         str(AutomationConstants.PORT_NUMBER_MAX) + ').'
#     INVALID_LDEVID_NUMBER_ERR = 'The specified value is invalid' +\
#         ' ({}: {}). Specify the value within a valid range (min: ' +\
#         str(AutomationConstants.LDEV_ID_MIN) + ', max: ' +\
#         str(AutomationConstants.LDEV_ID_MAX) + ').'
#     INVALID_POOLID_NUMBER_ERR = 'The specified value is invalid' +\
#         ' ({}: {}). Specify the value within a valid range (min: ' +\
#         str(AutomationConstants.POOL_ID_MIN) + ', max: ' +\
#         str(AutomationConstants.POOL_ID_MAX) + ').'
#     INVALID_RANGE_VALUE = 'The specified value is invalid' +\
#         ' ({}: {}). Specify the value within a valid range (min: {}' +\
#         ', max: {}' +\
#         ').'
#     HTTP_4xx_ERRORS = 'Invalid request sent by the client.' +\
#         ' API responded with client error code ({}). Reason: {}'
#     HTTP_5xx_ERRORS = 'The server encountered an unexpected ' +\
#         'condition. API responded with server error code ({}). Reason: {}'
#     API_COMMUNICATION_ERR = 'Communication with the target server' +\
#         ' failed. Reason: {}'
#     NOT_AVAILABLE = 'Not Available.'
#     REQUIRED_VALUE_ERR = 'The value for the parameter is' +\
#         ' required. ({}) Specify a valid value.'
#     API_TIMEOUT_ERR = 'A timeout occurred because no response' +\
#         ' was received from the server.'
#     INVALID_TYPE_VALUE = 'The specified value is not an integer' +\
#         ' type ({}: {}). Specify an integer value.'
#     INVALID_NAME_SIZE = 'The argument of the parameter is invalid' +\
#         ' ({}: {}). The length must be between 1 and 256.'
#     INVALID_NAME_SIZE_ZERO = 'The argument of the parameter is invalid' +\
#         ' ({}: {}). The length must be between 0 and 256.'
#     INVALID_NAME_SIZE_1_8 = 'The argument of the parameter is invalid' +\
#         ' ({}: {}). The length must be between 1 and 8.'
#     INVALID_STR_LEN = 'The argument of the parameter is invalid' +\
#         ' ({}: {}). The length must be between {} and {}.'
#     INVALID_RANGE_VALUE_0_1023 = 'The argument of the parameter is invalid' +\
#         ' ({}: {}). The range must be between 0 and 1023.'
#     INVALID_SIZE_VALUE = 'The specified size argument has an invalid range' +\
#         ' ({}: {}). Specify in range in between 1 to 999999999999.'
#     INVALID_SIZE_VALUE_ZERO = 'The specified size argument has an invalid range' +\
#         ' ({}: {}). Specify in range in between 0 to 999999999999.'
#     INVALID_HEX_VALUE = 'The specified hexadecimal number argument is invalid' +\
#         ' ({}: {}).'
#     INVALID_TIME_VALUE = 'The specified time argument has an invalid range' +\
#         ' ({}: {}). Specify in range in between 1 to 999.'
#     INVALID_SECRET_SIZE = 'The specified value is invalid' +\
#         ' ({}: {}). Secret should be 12 to 32 chars.'


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


class StoragePoolPayloadConst:
    NAME = "name"
    TYPE = "type"
    POOL_VOLUMES = "poolVolumes"
    RESOURCE_GROUP_ID = "resourceGroupId"
    WARNING_THRESHOLD_RATE = "warningThresholdRate"
    DEPLETION_THRESHOLD_RATE = "depletionThresholdRate"
    UCP_SYSTEM = "ucpSystem"
    IS_ENABLE_DEDUPLICATION = "duplicationLdevIds"
    CAPACITY = "capacity"
    PARITY_GROUP_ID = "parityGroupId"

    # Direct Mapping
    POOL_ID = "poolId"
    POOL_NAME = "poolName"
    LDEV_IDS = "ldevIds"
    START_LDEV_ID = "startLdevId"
    END_LDEV_ID = "endLdevId"
    WARNING_THRESHOLD = "warningThreshold"
    DEPLETION_THRESHOLD = "depletionThreshold"
    POOL_TYPE = "poolType"
    PARAMETERS = "parameters"
    OPERATION_TYPE = "operationType"
    monitoringMode = "monitoringMode"
    tier = "tier"
    blockingMode = "blockingMode"
    virtualVolumeCapacityRate = "virtualVolumeCapacityRate"
    suspendSnapshot = "suspendSnapshot"
    tierNumber = "tierNumber"
    tablespaceRate = "tablespaceRate"
    bufferRate = "bufferRate"


class GADPairConst:
    PRIMARY_SERIAL_NUMBER = "primarySerialNumber"
    PRIMARY_LUN_ID = "primaryLunID"
    CONSISTENCY_GROUP_ID = "consistencyGroupId"
    NEW_CONSISTENCY_GROUP = "newConsistencyGroup"
    OPERATION = "operation"
    PRIMARY_HOSTGROUP_PAYLOADS = "primaryHostGroupPayloads"
    UCP_SYSTEM = "ucpSystem"
    REMOTE_UCP_SYSTEM = "remoteUcpSystem"

    SECONDARY_SERIAL_NUMBER = "secondarySerialNumber"
    SECONDARY_POOL_ID = "secondaryPoolID"
    SECONDARY_HOSTGROUP_PAYLOADS = "secondaryHostGroupPayloads"
    SET_ALUA_MODE = "setAluaMode"
    PRIMARY_RESOURCE_GROUP_PAYLOAD = "primaryResourceGroupPayload"
    VIRTUAL_RESOURCE_GROUP_PAYLOAD = "virtualResourceGroupPayload"
    QUORUM_DISK_ID = "quorumDiskID"
    NAME = "name"
    PORT = "port"
    HOST_GROUP_ID = "hostGroupID"
    RESOURCE_GROUP_ID = "resourceGroupID"
    ENABLE_PREFERRED_PATH = "enablePreferredPath"


class UAIGStorageHealthStatus:
    NORMAL = "NORMAL"
    REFRESHING = "REFRESHING"


class VSPJournalVolumeUAIGReq:
    ucpSystem = "ucpSystem"
    serialNumber = "serialNumber"
    journalPoolId = "journalPoolId"
    logicalUnitIds = "logicalUnitIds"
    isCacheModeEnabled = "isCacheModeEnabled"
    dataOverflowWatchSeconds = "dataOverflowWatchSeconds"
    mpBladeId = "mpBladeId"
