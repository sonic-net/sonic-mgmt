VLAN_SUB_INTERFACE_SEPARATOR = "."
# default port mapping mode for storage backend testbeds
PTF_PORT_MAPPING_MODE_DEFAULT = "use_sub_interface"
TOPO_KEY = "topo"
NAME_KEY = "name"
# field in mg_facts to flag whether it's a backend topology or not
IS_BACKEND_TOPOLOGY_KEY = "is_backend_topology"
# a topology whos name contains the indicator 'backend' will be considered as a backend topology
BACKEND_TOPOLOGY_IND = "backend"
# ssh connect default username and password
DEFAULT_SSH_CONNECT_PARAMS = {
    "public": {"username": "admin",
               "password": "YourPaSsWoRd"}
}
# resolv.conf expected nameservers
RESOLV_CONF_NAMESERVERS = {
    "public": []
}
KVM_PLATFORM = 'x86_64-kvm_x86_64-r0'


class CounterpollConstants:
    COUNTERPOLL_SHOW = 'counterpoll show'
    COUNTERPOLL_DISABLE = 'counterpoll {} disable'
    COUNTERPOLL_ENABLE = 'counterpoll {} enable'
    COUNTERPOLL_RESTORE = 'counterpoll {} {}'
    COUNTERPOLL_INTERVAL_STR = 'counterpoll {} interval {}'
    COUNTERPOLL_QUEST = 'counterpoll --help'
    EXCLUDE_COUNTER_SUB_COMMAND = ['show', 'config-db', "flowcnt-trap", "tunnel"]
    INTERVAL = 'interval (in ms)'
    TYPE = 'type'
    STATUS = 'status'
    STDOUT = 'stdout'
    PG_DROP = 'pg-drop'
    PG_DROP_STAT_TYPE = 'PG_DROP_STAT'
    QUEUE_STAT_TYPE = 'QUEUE_STAT'
    QUEUE = 'queue'
    PORT_STAT_TYPE = 'PORT_STAT'
    PORT = 'port'
    PORT_BUFFER_DROP_TYPE = 'PORT_BUFFER_DROP'
    PORT_BUFFER_DROP = 'port-buffer-drop'
    RIF_STAT_TYPE = 'RIF_STAT'
    RIF = 'rif'
    WATERMARK = 'watermark'
    QUEUE_WATERMARK_STAT_TYPE = 'QUEUE_WATERMARK_STAT'
    PG_WATERMARK_STAT_TYPE = 'PG_WATERMARK_STAT'
    BUFFER_POOL_WATERMARK_STAT_TYPE = 'BUFFER_POOL_WATERMARK_STAT'
    ACL = 'acl'
    ACL_TYPE = "ACL"
    COUNTERPOLL_MAPPING = {PG_DROP_STAT_TYPE: PG_DROP,
                           QUEUE_STAT_TYPE: QUEUE,
                           PORT_STAT_TYPE: PORT,
                           PORT_BUFFER_DROP_TYPE: PORT_BUFFER_DROP,
                           RIF_STAT_TYPE: RIF,
                           BUFFER_POOL_WATERMARK_STAT_TYPE: WATERMARK,
                           QUEUE_WATERMARK_STAT_TYPE: WATERMARK,
                           PG_WATERMARK_STAT_TYPE: WATERMARK,
                           ACL_TYPE: ACL}
    PORT_BUFFER_DROP_INTERVAL = '10000'
    COUNTERPOLL_INTERVAL = {PORT_BUFFER_DROP: 10000}
    SX_SDK = 'sx_sdk'
