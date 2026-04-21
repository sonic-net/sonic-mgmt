import logging


PEGASUS_MODELS = ["VSP One B", "VSP E"]

BASIC_STORAGE_DETAILS = None

DEFAULT_NAME_PREFIX = "smrha"


def get_basic_storage_details():
    return BASIC_STORAGE_DETAILS


def set_basic_storage_details(storage_details):
    global BASIC_STORAGE_DETAILS
    BASIC_STORAGE_DETAILS = storage_details


class Endpoints(object):

    # vsp storage

    GET_STORAGE_INFO = "v1/objects/storages/instance"
    PEGASUS_JOB = "simple/v1/objects/command-status/{}"
    SESSIONS = "v1/objects/sessions"
    DELETE_SESSION = "v1/objects/sessions/{}"
    GET_TOTAL_EFFICIENCY = "v1/objects/total-efficiencies/instance"

    # Volumes
    POST_LDEVS = "v1/objects/ldevs"
    LDEVS_ONE = "v1/objects/ldevs/{}"
    SALAMENDER_GET_LDEVS_ONE = "simple/v1/objects/volumes/{}"
    SIMPLE_API_VOLUME_EXPAND = "simple/v1/objects/volumes/{}/actions/expand/invoke"
    SALAMENDER_GET_LDEVS_SERVER_CONNECTION = (
        "simple/v1/objects/volume-server-connections"
    )
    SALAMENDER_GET_LDEV_SERVER_CONNECTION = (
        "simple/v1/objects/volume-server-connections/{}"
    )
    SALAMENDER_UPDATE_QOS_SETTINGS = "simple/v1/objects/volumes/{}/qos-setting"
    ATTACH_SERVER_SIMPLE = "simple/v1/objects/volume-server-connections"
    DETACH_SERVER_SIMPLE = "simple/v1/objects/volume-server-connections/{}"
    LDEVS_JOURNAL_VOLUME = "v1/objects/ldevs/?journalId={}"
    PEGA_LDEVS_ONE = "simple/v1/objects/volumes/{}"
    GET_LDEVS = "v1/objects/ldevs{}"
    SALAMENDER_GET_LDEVS = "simple/v1/objects/volumes"
    SALAMENDER_GET_LDEVS_QUERY = "simple/v1/objects/volumes{}"
    PUT_LDEVS_CHANGE_STATUS = "v1/objects/ldevs/{}/actions/change-status/invoke"
    PUT_LDEVS_SHRED = "v1/objects/ldevs/{}/actions/shred/invoke"
    DELETE_LDEVS = "v1/objects/ldevs/{}"
    POST_EXPAND_LDEV = "v1/objects/ldevs/{}/actions/expand/invoke"
    POST_FORMAT_LDEV = "v1/objects/ldevs/{}/actions/format/invoke"
    POST_SHRED_LDEV = "v1/objects/ldevs/{}/actions/shred/invoke"
    POST_CHANGE_STATUS_LDEV = "v1/objects/ldevs/{}/actions/change-status/invoke"
    UAIG_GET_VOLUMES = "v3/storage/{}/volumes/details{}"
    UAIG_DELETE_ONE_VOLUME = "v3/storage/{}/volumes/{}?isDelete=true"
    GET_FREE_LDEV_FROM_META = (
        "v1/objects/ldevs?ldevOption=undefined&resourceGroupId=0&count=1"
    )
    GET_FREE_LDEVS_FROM_META = "v1/objects/ldevs?ldevOption=undefined&resourceGroupId=0"
    GET_FREE_LDEVS_FROM_META_RES = (
        "v1/objects/ldevs?ldevOption=undefined&resourceGroupId={}&count=16384"
    )
    GET_FREE_LDEVS_FROM_META_HEAD_LDEV = "v1/objects/ldevs?ldevOption=undefined&headLdevId={}&resourceGroupId={}&count=16384"
    GET_FREE_LDEVS_FROM_META_BASIC = (
        "v1/objects/ldevs?ldevOption=undefined&headLdevId={}&count={}"
    )
    GET_FREE_LDEV_MATCHING_PVOL = (
        "v1/objects/ldevs?ldevOption=undefined&count=1&headLdevId={}"
    )
    GET_FREE_LDEV_FROM_META_FOR_SVOL_RANGE = (
        "v1/objects/ldevs?ldevOption=undefined&headLdevId={}&count={}"
    )
    GET_LDEVS_BY_POOL_ID = "v1/objects/ldevs?poolId={}"
    POST_UNASSIGN_VLDEV = "v1/objects/ldevs/{}/actions/unassign-virtual-ldevid/invoke"
    POST_ASSIGN_VLDEV = "v1/objects/ldevs/{}/actions/assign-virtual-ldevid/invoke"
    POST_QOS_UPDATE = "v1/objects/ldevs/{}/actions/set-qos/invoke"
    GET_LDEV_EXT_VOL = "v1/objects/ldevs/{}?detailInfoType=externalVolume"
    GET_QOS_SETTINGS = "v1/objects/ldevs?headLdevId={}&count=1&detailInfoType=qos"
    SALAMENDER_GET_QOS_SETTINGS = "simple/v1/objects/volumes/{}/qos-setting"
    GET_CMD_DEVICE = "v1/objects/ldevs?headLdevId={}&count=1&detailInfoType=class"
    RECLAIM_ZERO_PAGES = "v1/objects/ldevs/{}/actions/discard-zero-page/invoke"
    CHANGE_MP_BLADE = "v1/objects/ldevs/{}/actions/assign-mp-blade/invoke"
    ASSIGN_LDEV = "v1/objects/ldevs/{}/actions/assign-clpr/invoke"
    # Port
    GET_PORTS = "v1/objects/ports"
    GET_PORTS_DETAILS = "v1/objects/ports?detailInfoType=portMode"
    GET_ONE_PORT = "v1/objects/ports/{}"
    GET_ONE_PORT_WITH_MODE = "v1/objects/ports/{}?detailInfoType=portMode"
    UPDATE_PORT = "v1/objects/ports/{}"
    UAIG_GET_PORTS_V2 = "v2/storage/devices/{}/ports{}"
    UAIG_GET_PORTS_V3 = "v3/storage/{}/ports{}"
    SEND_PING_COMMAND = "v1/objects/ports/{}/actions/ping/invoke"

    # HG
    POST_HOST_GROUPS = "v1/objects/host-groups"
    GET_WWNS = "v1/objects/host-wwns{}"
    POST_WWNS = "v1/objects/host-wwns"
    PATCH_WWNS = "v1/objects/host-wwns/{},{},{}"
    DELETE_WWNS = "v1/objects/host-wwns/{},{},{}"
    GET_HOST_GROUPS = "v1/objects/host-groups{}"
    GET_HOST_GROUP_BY_ID = "v1/objects/host-groups/{}"
    GET_HOST_GROUP_ONE = "v1/objects/host-groups/{},{}"
    DELETE_HOST_GROUPS = "v1/objects/host-groups/{},{}"
    PATCH_HOST_GROUPS = "v1/objects/host-groups/{},{}"
    GET_SPECIFIC_LUN = "v1/objects/luns/{},{},{}"
    SET_ALUA_PRIORITY = (
        "v1/services/lun-service/actions/change-asymmetric-access-state/invoke"
    )
    RELEASE_HOST_RES_STATUS_LU = (
        "v1/objects/luns/{},{},{}/actions/release-lu-host-reserve/invoke"
    )
    RELEASE_HOST_RES_STATUS = (
        "v1/objects/host-groups/{},{}/actions/release-lu-host-reserves/invoke"
    )

    # ISCSI
    GET_HOST_ISCSISS = "v1/objects/host-iscsis{}"
    GET_ONE_HOST_ISCSIS = "v1/objects/host-iscsis/{},{},{}"
    POST_HOST_ISCSIS = "v1/objects/host-iscsis"
    PUT_HOST_ISCSIS = "v1/objects/host-iscsis/{},{},{}"
    DELETE_HOST_ISCSIS = "v1/objects/host-iscsis/{},{},{}"
    UAIG_GET_ISCSIS = "v3/storage/{}/iscsiTargets/details{}"
    UAIG_POST_ISCSIS = "v3/storage/{}/iscsiTargets"
    UAIG_DELETE_ISCSIS = "v3/storage/{}/iscsiTargets/{}?isDelete=true"
    UAIG_POST_IQNS = "v3/storage/{}/iscsiTargets/{}/iqns"
    UAIG_DELETE_IQNS = "v3/storage/{}/iscsiTargets/{}/iqns"
    UAIG_POST_HOST_MODE = "v2/storage/devices/{}/iscsiTargets/{}/hostMode"
    UAIG_POST_CHAP_USER = "v2/storage/devices/{}/iscsiTargets/{}/chapUser"
    UAIG_PATCH_CHAP_USER = "v2/storage/devices/{}/iscsiTargets/{}/chapUser"
    UAIG_DELETE_CHAP_USER = "v2/storage/devices/{}/iscsiTargets/{}/chapUsers/{}"
    PATCH_IQN_NICK_NAME = "v1/objects/host-iscsis/{},{},{}"

    # CHAP
    POST_CHAP_USERS = "v1/objects/chap-users"
    PATCH_CHAP_USERS = "v1/objects/chap-users/{}"
    PUT_CHAP_USERS_SINGLE = "v1/objects/chap-users/{},{},{},{}"
    DELETE_CHAP_USERS = "v1/objects/chap-users/{},{},{},{}"
    GET_CHAP_USERS = "v1/objects/chap-users{}"
    GET_CHAP_USER = "v1/objects/chap-users/{},{},{},{}"

    # LUNS
    POST_LUNS = "v1/objects/luns"
    GET_LUNS = "v1/objects/luns{}"
    DELETE_LUNS = "v1/objects/luns/{},{},{}"
    UAIG_POST_LUNS = "v3/storage/{}/iscsiTargets/{}/volumes"
    UAIG_DELETE_LUNS = "v3/storage/{}/iscsiTargets/{}/volumes"
    UAIG_DELETE_LUNS_FROM_HG = "v3/storage/{}/hostGroups/{}/volumes"

    # CG
    GET_LOCAL_CLONE_COPYGROUPS = "v1/objects/local-clone-copygroups"
    POST_LOCAL_CLONE_COPYPAIRS = "v1/objects/local-clone-copypairs"
    GET_LOCAL_CLONE_COPYGROUPS_ONE = "v1/objects/local-clone-copygroups/{}"

    # CP
    POST_LOCAL_CLONE_COPYPAIRS_SPLIT = (
        "v1/objects/local-clone-copypairs/{}/actions/split/invoke"
    )
    POST_LOCAL_CLONE_COPYPAIRS_RESYNC = (
        "v1/objects/local-clone-copypairs/{}/actions/resync/invoke"
    )

    # SI
    POST_SNAPSHOTS = "v1/objects/snapshots"
    GET_SNAPSHOT_GROUPS = "v1/objects/snapshot-groups"
    GET_SNAPSHOT_GROUPS_ONE = "v1/objects/snapshot-groups/{}"
    POST_SNAPSHOTS_CLONE = "v1/objects/snapshots/{}/actions/clone/invoke"
    POST_SNAPSHOTS_SPLIT = "v1/objects/snapshots/{}/actions/split/invoke"
    POST_SNAPSHOTS_RESYNC = "v1/objects/snapshots/{}/actions/resync/invoke"
    POST_SNAPSHOTS_RESTORE = "v1/objects/snapshots/{}/actions/restore/invoke"
    GET_JOBS = "v1/objects/jobs/{}"
    PUT_ISCSI_PORTS_DISCOVER = "v1/objects/iscsi-ports/{}/actions/discover/invoke"
    PUT_ISCSI_PORTS_REGISTER = "v1/objects/iscsi-ports/{}/actions/register/invoke"
    PUT_ISCSI_PORTS_CHECK = "v1/objects/iscsi-ports/{}/actions/check/invoke"
    PUT_ISCSI_PORTS_REMOVE = "v1/objects/iscsi-ports/{}/actions/remove/invoke"
    GET_ISCSI_PORTS = "v1/objects/iscsi-ports/{}"
    GET_EXTERNAL_STORAGE_PORTS = "v1/objects/external-storage-ports{}"
    GET_EXTERNAL_STORAGE_LUNS = "v1/objects/external-storage-luns{}"
    GET_STORAGES_ONE = "v1/objects/storages/{}"
    GET_EXTERNAL_PATH_GROUPS_ONE = "simple/v1/objects/external-path-groups/{}"
    GET_EXTERNAL_PARITY_GROUPS_ONE = "simple/v1/objects/external-parity-groups/{}"
    GET_EXTERNAL_VOLUMES = "simple/v1/objects/external-volumes{}"
    POST_EXTERNAL_VOLUMES = "simple/v1/objects/external-volumes"
    POST_SESSIONS = "simple/v1/objects/sessions"
    DELETE_SESSIONS = "simple/v1/objects/sessions/{}"
    GET_COMMAND_STATUS = "simple/v1/objects/command-status/{}"
    DELETE_COMMAND_STATUS = "simple/v1/objects/command-status/{}"
    GET_HOST_ISCSI_PATHS = "v1/views/host-iscsi-paths?{}"
    GET_STORAGE_SYSTEMS = "v1/objects/storages"
    GET_STORAGE_SYSTEM = "v1/objects/storages/{}"
    GET_STORAGE_CAPACITY = "v1/objects/total-capacities/instance"
    GET_LICENSES = "v1/objects/licenses"
    GET_TOTAL_EFFICENCY = "v1/objects/storages/{}/total-efficiencies/instance"
    GET_QUORUM_DISKS = "v1/objects/quorum-disks"
    GET_SYSLOG_SERVERS = "v1/objects/auditlog-syslog-servers/instance"
    UAIG_GET_ALL_SHADOW_IMAGE_PAIR = "v3/storage/devices/{deviceId}/shadowimages"
    UAIG_GET_SHADOW_IMAGE_PAIR_BY_ID = (
        "v2/storage/devices/{deviceId}/shadowimage/{pairId}"
    )
    GET_STORAGE_SYSTEMS_INFO = "v1/objects/date-times/instance"
    GET_TIME_ZONE_LIST = "v1/objects/time-zones"
    SET_TIME_ZONE = "v1/objects/date-times/instance"
    # UAIG_CREATE_SHADOW_IMAGE_PAIR = 'v2/storage/devices/{deviceId}/shadowimage'
    UAIG_CREATE_SHADOW_IMAGE_PAIR = "v3/storage/devices/{deviceId}/shadowimage"
    UAIG_GET_SHADOW_IMAGE_PAIR_BY_PVOL = (
        "v2/storage/devices/{deviceId}/shadowimages/?primaryLunId={pvol}"
    )
    UAIG_SPLIT_SHADOW_IMAGE_PAIR = (
        "v2/storage/devices/{deviceId}/shadowimage/{pairId}/split"
    )
    UAIG_RESYNC_SHADOW_IMAGE_PAIR = (
        "v2/storage/devices/{deviceId}/shadowimage/{pairId}/resync"
    )
    UAIG_RESTORE_SHADOW_IMAGE_PAIR = (
        "v2/storage/devices/{deviceId}/shadowimage/{pairId}/restore"
    )
    # UAIG_DELETE_SHADOW_IMAGE_PAIR = 'v2/storage/devices/{deviceId}/shadowimage/{pairId}'
    UAIG_DELETE_SHADOW_IMAGE_PAIR = (
        "v3/storage/devices/{deviceId}/shadowimage/{pairId}?isDelete=true"
    )
    UAIG_GET_RESOURCE_MAPPING_INFO = (
        "v3/storage/{deviceId}/resource/{pairId}?type={type}"
    )
    DIRECT_GET_ALL_SHADOW_IMAGE_PAIR = "v1/objects/local-replications"
    DIRECT_GET_SHADOW_IMAGE_PAIR_BY_ID = "v1/objects/local-clone-copypairs/{pairId}"
    DIRECT_CREATE_SHADOW_IMAGE_PAIR = "v1/objects/local-clone-copypairs"
    DIRECT_SPLIT_SHADOW_IMAGE_PAIR = (
        "v1/objects/local-clone-copypairs/{pairId}/actions/split/invoke"
    )
    DIRECT_MIGRATE_SHADOW_IMAGE_PAIR = (
        "v1/objects/local-clone-copypairs/{pairId}/actions/migrate/invoke"
    )
    DIRECT_RESYNC_SHADOW_IMAGE_PAIR = (
        "v1/objects/local-clone-copypairs/{pairId}/actions/resync/invoke"
    )
    DIRECT_RESTORE_SHADOW_IMAGE_PAIR = (
        "v1/objects/local-clone-copypairs/{pairId}/actions/restore/invoke"
    )
    DIRECT_DELETE_SHADOW_IMAGE_PAIR = "v1/objects/local-clone-copypairs/{pairId}"
    DIRECT_GET_ALL_COPY_PAIR_GROUP = "v1/objects/local-clone-copygroups"
    DIRECT_GET_SI_BY_CPG = "v1/objects/local-clone-copypairs?localCloneCopyGroupId={}"

    # SnapShot
    ALL_SNAPSHOTS = "v1/objects/snapshot-replications"
    SNAPSHOTS = "v1/objects/snapshots"
    PEGASUS_SNAPSHOTS = "simple/v1/objects/snapshots"
    GET_ONE_SNAPSHOTS = "v1/objects/snapshots/{}"
    GET_SNAPSHOTS_QUERY = "v1/objects/snapshots?{}"
    GET_SNAPSHOT_GROUPS = "v1/objects/snapshot-groups"
    GET_SNAPSHOTS_BY_GROUP = "v1/objects/snapshot-groups/{}"
    GET_SNAPSHOT_GROUPS_ONE = "v1/objects/snapshot-groups/{}"
    POST_SNAPSHOTS_SPLIT = "v1/objects/snapshots/{}/actions/split/invoke"
    POST_SNAPSHOTS_SVOL_ADD = "v1/objects/snapshots/{}/actions/assign-volume/invoke"
    POST_SNAPSHOTS_SVOL_REMOVE = (
        "v1/objects/snapshots/{}/actions/unassign-volume/invoke"
    )
    POST_SNAPSHOTS_RESYNC = "v1/objects/snapshots/{}/actions/resync/invoke"
    POST_SNAPSHOTS_RESTORE = "v1/objects/snapshots/{}/actions/restore/invoke"
    SNAPSHOT_RETENTION = "v1/objects/snapshots/{}/actions/set-retention/invoke"
    DELETE_GARBAGE_DATA = "v1/services/snapshot-tree/actions/delete-garbage-data/invoke"
    DELETE_TI_BY_SS_TREE = "v1/services/snapshot-tree/actions/delete/invoke"

    SNAPSHOTS_BY_GROUP_ID = "v1/objects/snapshot-groups/{}"
    SNAPSHOTS_BY_GROUP_ID_WITH_RETAIN = (
        "v1/objects/snapshot-groups/{}?detailInfoType=retention"
    )
    GET_SNAPSHOTS_BY_GROUP = "v1/objects/snapshot-groups"
    SPLIT_SNAPSHOT_BY_GRP = "v1/objects/snapshot-groups/{}/actions/split/invoke"
    CLONE_SNAPSHOT_BY_GRP = "v1/objects/snapshot-groups/{}/actions/clone/invoke"
    RESYNC_SNAPSHOT_BY_GRP = "v1/objects/snapshot-groups/{}/actions/resync/invoke"
    RESTORE_SNAPSHOT_BY_GRP = "v1/objects/snapshot-groups/{}/actions/restore/invoke"
    SNAPSHOT_RETENTION_BY_GRP = (
        "v1/objects/snapshot-groups/{}/actions/set-retention/invoke"
    )

    # Pool
    GET_POOLS = "v1/objects/pools"
    POST_POOL = "v1/objects/pools"
    GET_POOL = "v1/objects/pools/{}"
    POOL_EXPAND = "v1/objects/pools/{}/actions/expand/invoke"
    PERFORMANCE_MONITORING = "v1/objects/pools/{}/actions/monitor/invoke"
    TIER_LOCATION = "v1/objects/pools/{}/actions/relocate/invoke"
    RESTORE_POOL = "v1/objects/pools/{}/actions/recover/invoke"
    INITIALIZE_CAPACITY_SAVINGS = (
        "v1/objects/pools/{}/actions/data-reduction-initialize/invoke"
    )

    # Journal Volumes
    GET_JOURNAL_POOLS = "v1/objects/journals"
    GET_JOURNAL_POOL = "v1/objects/journals/{}"
    POST_JOURNAL_POOLS = "v1/objects/journals"
    JOURNAL_POOL_EXPAND = "v1/objects/journals/{}/actions/expand/invoke"
    JOURNAL_POOL_SHRINK = "v1/objects/journals/{}/actions/shrink/invoke"
    JOURNAL_POOL_MP_BLADE = "v1/objects/journals/{}/actions/assign-mp-blade/invoke"

    # Parity group
    GET_PARITY_GROUPS = "v1/objects/parity-groups"
    GET_PARITY_GROUP = "v1/objects/parity-groups/{}"
    GET_EXTERNAL_PARITY_GROUPS = "v1/objects/external-parity-groups"
    GET_EXTERNAL_PARITY_GROUP = "v1/objects/external-parity-groups/{}"
    GET_DRIVES = "v1/objects/drives"
    GET_DRIVE = "v1/objects/drives/{}"
    ASSIGN_PARITY = "v1/objects/parity-groups/{}/actions/assign-clpr/invoke"

    # Tag device resources
    UAIG_ADD_STORAGE_RESOURCE = "v3/storage/{}/resource"

    # remote connection urls
    GET_ALL_REMOTE_CONNECTIONS = "v1/objects/remotepath-groups"
    REMOTE_CONNECTION_SINGLE = "v1/objects/remotepath-groups/{}"
    POST_REMOTE_CONNECTIONS = "v1/objects/remotepath-groups"
    ADD_REMOTE_PATH = "v1/objects/remotepath-groups/{}/actions/add-remotepath/invoke"
    DELETE_REMOTE_PATH = (
        "v1/objects/remotepath-groups/{}/actions/remove-remotepath/invoke"
    )
    DELETE_REMOTE_CONNECTION = "v1/objects/remotepath-groups/{}"

    # remote iscsi connection urls
    GET_ALL_REMOTE_ISCSI_CONNECTIONS = "v1/objects/remote-iscsi-ports"
    REMOTE_ISCSI_CONNECTION_SINGLE = "v1/objects/remote-iscsi-ports/{}"
    POST_REMOTE_ISCSI_CONNECTIONS = "v1/objects/remote-iscsi-ports"

    # Dynamic pool salmanda api
    GET_ALL_DDP_POOL_INFO = "simple/v1/objects/pools"
    POST_DDP_POOL = "simple/v1/objects/pools"
    SINGLE_DDP_POOL = "simple/v1/objects/pools/{}"
    EXPAND_DDP_POOL = "simple/v1/objects/pools/{}/actions/expand/invoke"
    GET_RECOMMENDED_POOL = "simple/v1/objects/recommended-pool-configurations"
    GET_RECOMMENDED_POOL_SINGLE = (
        "simple/v1/objects/recommended-pool-configurations?poolId={}"
    )

    # MP blades
    GET_MP_BLADES = "v1/objects/mps"

    # Initial config api
    UPLOAD_TRANSFER_DESTINATION_FILE = "v1/objects/actions/file-upload/invoke"
    GET_AUDIT_LOG_FILE_TRANSFER_DESTINATION = (
        "v1/objects/auditlog-syslog-servers/instance"
    )
    SPECIFY_TRANSFER_DESTINATION_FILE = "v1/objects/auditlog-syslog-servers/instance"
    SEND_TEST_MESSAGE = (
        "v1/objects/auditlog-syslog-servers/instance/actions/send-test/invoke"
    )
    GET_SNMP_SETTINGS = "v1/objects/snmp-settings/instance"
    SEND_SNMP_TRAP = "v1/objects/snmp-settings/instance/actions/send-trap-test/invoke"

    # VSP one server
    GET_SIMPLE_SERVER_INFO = "simple/v1/objects/servers"
    GET_SIMPLE_SERVER_INFO_QUERY = "simple/v1/objects/servers?{}"
    GET_SINGLE_SIMPLE_SERVER = "simple/v1/objects/servers/{}"
    ADD_HG_TO_SERVER = "simple/v1/objects/servers/{}/actions/add-host-groups/invoke"
    SYNC_HG_TO_SERVER_NICKNAME = (
        "simple/v1/objects/servers/{}/actions/sync-host-group-names/invoke"
    )
    GET_WWN_OF_HBA = "simple/v1/objects/servers/{}/hbas"
    SINGLE_WWN_OF_HBA_PER_SERVER = "simple/v1/objects/servers/{}/hbas/{}"
    ADD_WWN_OF_HBA = "simple/v1/objects/servers/{}/hbas"
    ALL_SERVER_PATHS = "simple/v1/objects/servers/{}/paths"
    SPECIFIC_SERVER_PATH = "simple/v1/objects/servers/{}/paths/{}"
    ADD_PATH_TO_SERVER = "simple/v1/objects/servers/{}/paths"
    SINGLE_SERVER_PATH = "simple/v1/objects/servers/{}/paths/{}"
    GET_ALL_SERVER_ISCSI = "simple/v1/objects/servers/{}/target-iscsi-ports"
    SINGLE_SERVER_ISCSI = "simple/v1/objects/servers/{}/target-iscsi-ports/{}"
    ISCSI_TARGET_SETTINGS = "simple/v1/objects/servers/{}/target-iscsi-ports/{}"

    # VSP one Port
    VSP_ONE_GET_PORTS = "simple/v1/objects/ports"
    VSP_ONE_SINGLE_PORT = "simple/v1/objects/ports/{}"


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
    HOST_MODE_OPT_NUMBER_MIN = 0
    HOST_MODE_OPT_NUMBER_MAX = 999
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
    LDEV_ID_MAX = 65279
    LDEV_ID_MAX_FULL = 65535
    LDEV_MAX_NUMBER = 16384
    LDEV_MAX_MU_NUMBER = 1023
    ISCSI_NAME_LEN_MIN = 1
    ISCSI_NAME_LEN_MAX = 32
    LDEV_NAME_LEN_MIN = 1
    LDEV_NAME_LEN_MAX = 24
    IQN_LEN_MIN = 5
    IQN_LEN_MAX = 223
    CHAP_USER_NAME_LEN_MIN = 1
    CHAP_USER_NAME_LEN_MAX = 223
    CHAP_SECRET_LEN_MIN = 12
    CHAP_SECRET_LEN_MAX = 32
    HG_NAME_LEN_MIN = 1
    HG_NAME_LEN_MAX = 64
    CONSISTENCY_GROUP_ID_MIN = 0
    CONSISTENCY_GROUP_ID_MAX = 255
    POOL_SIZE_MIN = 16777216
    NVM_SUBSYSTEM_MIN_ID = 0
    NVM_SUBSYSTEM_MAX_ID = 2047
    COPY_GROUP_NAME_LEN_MIN = 1
    COPY_GROUP_NAME_LEN_MAX = 29
    COPY_PAIR_NAME_LEN_MIN = 1
    COPY_PAIR_NAME_LEN_MAX = 31
    PATH_GROUP_ID_MIN = 0
    PATH_GROUP_ID_MAX = 255
    DEVICE_GROUP_NAME_LEN_MIN = 1
    DEVICE_GROUP_NAME_LEN_MAX = 31
    COPY_PACE_MIN = 1
    COPY_PACE_MAX = 15
    RG_NAME_LEN_MIN = 1
    RG_NAME_LEN_MAX = 32
    START_LDEV_ID_MIN = 0
    START_LDEV_ID_MAX = 65278
    END_LDEV_ID_MIN = 1
    END_LDEV_ID_MAX = 65279
    VIRTUAL_STORAGE_DEVICE_ID_LEN_MIN = 12
    RG_ID_MIN = 1
    RG_ID_MAX = 1023
    RG_LOCK_TIMEOUT_MIN = 0
    RG_LOCK_TIMEOUT_MAX = 7200
    VOLUME_SIZE_LEN_MIN = 3
    VOLUME_SIZE_LEN_MAX = 14
    USER_NAME_LEN_MIN = 1
    USER_NAME_LEN_MAX = 256
    PASS_LEN_MIN = 6
    PASS_LEN_MAX = 256
    MAX_USER_GROUPS = 8
    MAX_LDEVS_IN_DP = 64


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


class VolumePayloadConst:
    PARAMS = "parameters"
    POOL_ID = "poolId"
    BYTE_CAPACITY = "byteFormatCapacity"
    BLOCK_CAPACITY = "blockCapacity"
    LDEV = "ldevId"
    ADR_SETTING = "dataReductionMode"
    PARITY_GROUP = "parityGroupId"
    PARALLEL_EXECUTION = "isParallelExecutionEnabled"
    LABEL = "label"
    ADDITIONAL_BLOCK_CAPACITY = "additionalBlockCapacity"
    IS_DATA_REDUCTION_SHARED_VOLUME_ENABLED = "isDataReductionSharedVolumeEnabled"
    IS_DATA_REDUCTION_SHARE_ENABLED = "isDataReductionShareEnabled"
    FORCE_FORMAT = "isDataReductionForceFormat"
    OPERATION_TYPE = "operationType"
    STATUS = "status"
    ENHANCED_EXPANSION = "enhancedExpansion"
    VIRTUAL_LDEVID = "virtualLdevId"
    MP_BLADE_ID = "mpBladeId"
    DATA_REDUCTION_PROCESS_MODE = "dataReductionProcessMode"
    IS_COMPRESSION_ACCELERATION_ENABLED = "isCompressionAccelerationEnabled"
    IS_RELOCATION_ENABLED = "isRelocationEnabled"
    IS_FULL_ALLOCATION_ENABLED = "isFullAllocationEnabled"
    IS_ALUA_ENABLED = "isAluaEnabled"
    CLPR_ID = "clprId"

    # SALMENDER PARAMS
    CAPACITY = "capacity"
    NUMBER = "number"
    NICKNAME_PARAM = "nicknameParam"
    NICK_NAME = "nickname"
    SAVING_SETTING = "savingSetting"
    IS_DATA_REDUCTION_SHARE_ENABLED = "isDataReductionShareEnabled"
    POOL_ID = "poolId"
    COMPRESSION_ACCELERATION = "compressionAcceleration"
    threshold = "threshold"
    alertSetting = "alertSetting"
    isUpperIopsEnabled = "isUpperIopsEnabled"
    upperIops = "upperIops"
    isUpperTransferRateEnabled = "isUpperTransferRateEnabled"
    upperTransferRate = "upperTransferRate"
    isLowerIopsEnabled = "isLowerIopsEnabled"
    lowerIops = "lowerIops"
    isLowerTransferRateEnabled = "isLowerTransferRateEnabled"
    lowerTransferRate = "lowerTransferRate"
    isResponsePriorityEnabled = "isResponsePriorityEnabled"
    responsePriority = "responsePriority"
    isUpperAlertEnabled = "isUpperAlertEnabled"
    upperAlertAllowableTime = "upperAlertAllowableTime"
    isLowerAlertEnabled = "isLowerAlertEnabled"
    lowerAlertAllowableTime = "lowerAlertAllowableTime"
    isResponseAlertEnabled = "isResponseAlertEnabled"
    responseAlertAllowableTime = "responseAlertAllowableTime"

    # URL PARAMS
    HEAD_LDEV_ID = "?headLdevId={}"
    HEAD_LDEV_ID_NEXT = "&headLdevId={}"
    COUNT = "&count={}"
    LDEV_OPTION = "?&ldevOption={}"
    POOL_ID_PARAM = "?poolId={}"
    RESOURCE_GROUP_ID = "?resourceGroupId={}"
    JOURNAL_ID = "?journalId={}"
    PARITY_GROUP_ID = "?parityGroupId={}"

    # volume emulation type
    NOT_DEFINED = "NOT DEFINED"

    IS_DATA_REDUCTION_SHARE_ENABLED = "isDataReductionShareEnabled"
    IS_DATA_REDUCTION_DELETE_FORCE_EXECUTE = "isDataReductionDeleteForceExecute"
    IS_COMPRESSION_ACCELERATION_ENABLED = "isCompressionAccelerationEnabled"

    IS_PARALLEL_EXECUTION_ENABLED = "isParallelExecutionEnabled"
    START_LDEV_ID = "startLdevId"
    END_LDEV_ID = "endLdevId"
    EXTERNAL_PARITY_GROUP_ID = "externalParityGroupId"

    DISABLED = "disabled"
    BLOCK = "BLK"
    NORMAL = "NML"

    # Volume operation type
    FMT = "FMT"
    QFMT = "QFMT"
    START = "START"
    STOP = "STOP"

    # QOS constants
    UPPER_IOPS = "upperIops"
    LOWER_IOPS = "lowerIops"
    UPPER_TRANSFER_RATE = "upperTransferRate"
    LOWER_TRANSFER_RATE = "lowerTransferRate"
    UPPER_ALERT_ALLOWABLE_TIME = "upperAlertAllowableTime"
    LOWER_ALERT_ALLOWABLE_TIME = "lowerAlertAllowableTime"
    RESPONSE_PRIORITY = "responsePriority"
    RESPONSE_ALERT_ALLOWABLE_TIME = "responseAlertAllowableTime"

    # Vsp one server
    serverNickname = "serverNickname"
    protocol = "protocol"
    osType = "osType"
    osTypeOptions = "osTypeOptions"
    isReserved = "isReserved"


class ServerPayloadConst:
    serverNickname = "serverNickname"
    protocol = "protocol"
    osType = "osType"
    osTypeOptions = "osTypeOptions"
    isReserved = "isReserved"
    nickname = "nickname"
    portId = "portId"
    hostGroupId = "hostGroupId"
    hostGroupName = "hostGroupName"
    hbas = "hbas"
    hbaWwn = "hbaWwn"
    iscsiName = "iscsiName"
    hbaWwn = "hbaWwn"
    portIds = "portIds"
    targetIscsiName = "targetIscsiName"


class VSPOnePortConst:
    portSpeed = "portSpeed"
    portSecurity = "portSecurity"
    fcInformation = "fcInformation"


class VSPSnapShotReq:
    snapshotGroupName = "snapshotGroupName"
    snapshotPoolId = "snapshotPoolId"
    pvolLdevId = "pvolLdevId"
    svolLdevId = "svolLdevId"
    isConsistencyGroup = "isConsistencyGroup"
    autoSplit = "autoSplit"
    isDataReductionForceCopy = "isDataReductionForceCopy"
    canCascade = "canCascade"
    parameters = "parameters"
    isClone = "isClone"
    muNumber = "muNumber"
    retentionPeriod = "retentionPeriod"
    copySpeed = "copySpeed"
    clonesAutomation = "clonesAutomation"
    primaryLdevId = "ldevId"
    operationType = "operationType"


class PairStatus:
    SSWS = "SSWS"
    PSUS = "PSUS"
    SMPP = "SMPP"
    COPY = "COPY"
    PAIR = "PAIR"
    PFUL = "PFUL"
    PSUE = "PSUE"
    PFUS = "PFUS"
    RCPY = "RCPY"
    PSUP = "PSUP"
    CPYP = "CPYP"
    OTHER = "OTHER"


class VSPPortSetting:
    LUN_SECURITY_SETTING = "lunSecuritySetting"
    PORT_MODE = "portMode"
    PORT_ATTRIBUTE = "portAttribute"
    PORT_SPEED = "portSpeed"
    PORT_CONNECTION = "portConnection"
    FABRIC_MODE = "fabricMode"
    HOST_IP_ADDRESS = "ipAddress"


class DefaultValues:
    DEFAULT_HG_NAME = "ansible_host_group"


ARRAY_FAMILY_LOOKUP = {
    "AMS": "ARRAY_FAMILY_DF",
    "HUS": "ARRAY_FAMILY_DF",
    "VSP": "ARRAY_FAMILY_R700",
    "HUS-VM": "ARRAY_FAMILY_HM700",
    "VSP G1000": "ARRAY_FAMILY_R800",
    "VSP G1500/F1500": "ARRAY_FAMILY_R800",
    "VSP G200": "ARRAY_FAMILY_HM800",
    "VSP G 400": "ARRAY_FAMILY_HM800",
    "VSP F 400": "ARRAY_FAMILY_HM800",
    "VSP N 400": "ARRAY_FAMILY_HM800",
    "VSP G 600": "ARRAY_FAMILY_HM800",
    "VSP F 600": "ARRAY_FAMILY_HM800",
    "VSP N 600": "ARRAY_FAMILY_HM800",
    "VSP G 800": "ARRAY_FAMILY_HM800",
    "VSP F 800": "ARRAY_FAMILY_HM800",
    "VSP N 800": "ARRAY_FAMILY_HM800",
    "VSP G130": "ARRAY_FAMILY_HM800",
    "VSP G150": "ARRAY_FAMILY_HM800",
    "VSP G/F350": "ARRAY_FAMILY_HM800",
    "VSP G/F370": "ARRAY_FAMILY_HM800",
    "VSP G/F700": "ARRAY_FAMILY_HM800",
    "VSP G/F900": "ARRAY_FAMILY_HM800",
    "VSP 5000": "ARRAY_FAMILY_R900",
    "VSP 5000H": "ARRAY_FAMILY_R900",
    "VSP 5500": "ARRAY_FAMILY_R900",
    "VSP 5500H": "ARRAY_FAMILY_R900",
    "VSP 5200": "ARRAY_FAMILY_R900",
    "VSP 5200H": "ARRAY_FAMILY_R900",
    "VSP 5600": "ARRAY_FAMILY_R900",
    "VSP 5600H": "ARRAY_FAMILY_R900",
    "VSP E590": "ARRAY_FAMILY_HM900",
    "VSP E790": "ARRAY_FAMILY_HM900",
    "VSP E990": "ARRAY_FAMILY_HM900",
    "VSP E1090": "ARRAY_FAMILY_HM900",
    "VSP E1090H": "ARRAY_FAMILY_HM900",
    "VSP One B23": "ARRAY_FAMILY_HM2000",
    "VSP One B24": "ARRAY_FAMILY_HM2000",
    "VSP One B26": "ARRAY_FAMILY_HM2000",
    "VSP One B28": "ARRAY_FAMILY_HM2000",
}


class UnSubscribeResourceTypes:
    HOST_GROUP = "HostGroup"
    VOLUME = "volume"
    PORT = "port"
    ISCSI_TARGET = "IscsiTarget"
    STORAGE_POOL = "StoragePool"
    CHAP_USER = "chapuser"
    SHADOW_IMAGE = "shadowimage"


class CAPACITY_SAVINGS_CONST:
    COMPRESSION_DEDUPLICATION = "compression_deduplication"
    COMPRESSION = "compression"


class StoragePoolLimits:
    MAX_POOL_ID = 127
    JOURNAL_POOL_ID_LIMIT = 255


class VSPJournalVolumeReq:
    journalid = "journalId"
    startLdevId = "startLdevId"
    endLdevId = "endLdevId"
    dataOverflowWatchInSeconds = "dataOverflowWatchInSeconds"
    isCacheModeEnabled = "isCacheModeEnabled"
    mpBladeId = "mpBladeId"
    LDEV_IDS = "ldevIds"
    PARAMETERS = "parameters"
    mirrorUnit = "mirrorUnit"
    muNumber = "muNumber"
    copyPace = "copyPace"
    pathBlockadeWatchInMinutes = "pathBlockadeWatchInMinutes"


class RemoteConnectionReq:
    remoteSerialNumber = "remoteSerialNumber"
    remoteStorageTypeId = "remoteStorageTypeId"
    pathGroupId = "pathGroupId"
    remotePaths = "remotePaths"
    minNumOfPaths = "minNumOfPaths"
    localPortId = "localPortId"
    remotePortId = "remotePortId"
    timeoutValueForRemoteIOInSeconds = "timeoutValueForRemoteIOInSeconds"
    roundTripTimeInMilliSeconds = "roundTripTimeInMilliSeconds"
    parameters = "parameters"


class RemoteIscsiConnectionReq:
    localPortId = "localPortId"
    remoteSerialNumber = "remoteSerialNumber"
    remoteStorageTypeId = "remoteStorageTypeId"
    remotePortId = "remotePortId"
    remoteIpAddress = "remoteIpAddress"
    remoteTcpPort = "remoteTcpPort"


class VspDDPConst:
    name = "name"
    isEncryptionEnabled = "isEncryptionEnabled"
    drives = "drives"
    driveTypeCode = "driveTypeCode"
    dataDriveCount = "dataDriveCount"
    raidLevel = "raidLevel"
    parityGroupType = "parityGroupType"
    thresholdWarning = "thresholdWarning"
    thresholdDepletion = "thresholdDepletion"
    additionalDrives = "additionalDrives"


class InitialConfig:
    FileType = "fileType"
    file = "file"
    transferProtocol = "transferProtocol"
    locationName = "locationName"
    retries = "retries"
    retryInterval = "retryInterval"
    isDetailed = "isDetailed"
    primarySyslogServer = "primarySyslogServer"
    secondarySyslogServer = "secondarySyslogServer"
    isEnabled = "isEnabled"
    ipAddress = "ipAddress"
    port = "port"
    clientCertFileName = "clientCertFileName"
    clientCertFilePassword = "clientCertFilePassword"
    rootCertFileName = "rootCertFileName"
    isSNMPAgentEnabled = "isSNMPAgentEnabled"
    snmpVersion = "snmpVersion"
    sendingTrapSetting = "sendingTrapSetting"
    community = "community"
    sendTrapTo = "sendTrapTo"
    userName = "userName"
    sendTrapTo = "sendTrapTo"
    authentication = "authentication"
    requestAuthenticationSetting = "requestAuthenticationSetting"
    snmpv1v2cSettings = "snmpv1v2cSettings"
    community = "community"
    requestsPermitted = "requestsPermitted"
    snmpv3Settings = "snmpv3Settings"
    systemGroupInformation = "systemGroupInformation"
    storageSystemName = "storageSystemName"
    contact = "contact"
    location = "location"
    protocol = "protocol"
    password = "password"
    encryption = "encryption"
    key = "key"


class TimeZoneConst:
    isNtpEnabled = "isNtpEnabled"
    ntpServerNames = "ntpServerNames"
    timeZoneId = "timeZoneId"
    systemTime = "systemTime"
    synchronizingLocalTime = "synchronizingLocalTime"
    adjustsDaylightSavingTime = "adjustsDaylightSavingTime"
    synchronizesNow = "synchronizesNow"
