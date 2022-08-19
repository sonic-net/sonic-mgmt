REQUIRED_PATTERNS = {
    "time_span": [
        "SAI_CREATE_SWITCH",
        "INIT_VIEW",
        "APPLY_VIEW"
    ],
    "offset_from_kexec": [
        "LAG_READY",
        "PORT_READY"
    ]
}

SERVICE_PATTERNS = {
    "LATEST": {
        "Stopping": re.compile(r'.*Stopping.*(service|container).*'),
        "Stopped": re.compile(r'.*Stopped.*(service|container).*'),
        "Starting": re.compile(r'.*Starting.*(service|container).*'),
        "Started": re.compile(r'.*Started.*(service|container).*')
    },
    "201911": {
        "Stopping": re.compile(r'.*Stopping.*'),
        "Stopped": re.compile(r'.*Stopped.*'),
        "Starting": re.compile(r'.*Starting.*'),
        "Started": re.compile(r'.*Started.*')
    }
}

OTHER_PATTERNS = {
    "COMMON": {
        "PORT_INIT|Start": re.compile(r'.*NOTICE swss#orchagent.*initPort: Initialized port.*'),
        "PORT_READY|Start": re.compile(r'.*swss#orchagent.*updatePortOperStatus.*Port Eth.*oper state set.* to up.*'),
        "FINALIZER|Start": re.compile(r'.*WARMBOOT_FINALIZER.*Wait for database to become ready.*'),
        "FINALIZER|End": re.compile(r"(.*WARMBOOT_FINALIZER.*Finalizing warmboot.*)|(.*WARMBOOT_FINALIZER.*warmboot is not enabled.*)"),
        "FPMSYNCD_RECONCILIATION|Start": re.compile(r'.*NOTICE bgp#fpmsyncd: :- main: Warm-Restart timer started.*'),
        "FPMSYNCD_RECONCILIATION|End": re.compile(r'.*NOTICE bgp#fpmsyncd: :- main: Warm-Restart reconciliation processed.*'),
        "ROUTE_DEFERRAL_TIMER|Start": re.compile(r'.*ADJCHANGE: neighbor .* in vrf default Up.*'),
        "ROUTE_DEFERRAL_TIMER|End": re.compile(r'.*rcvd End-of-RIB for .* Unicast from.*'),
        "FDB_AGING_DISABLE|Start": re.compile(r'.*NOTICE swss#orchagent.*setAgingFDB: Set switch.*fdb_aging_time 0 sec'),
        "FDB_AGING_DISABLE|End": re.compile(r'.*NOTICE swss#orchagent.*do.*Task: Set switch attribute fdb_aging_time to 600')
    },
    "LATEST": {
        "INIT_VIEW|Start": re.compile(r'.*swss#orchagent.*notifySyncd.*sending syncd.*INIT_VIEW.*'),
        "INIT_VIEW|End": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*switched ASIC to INIT VIEW.*'),
        "APPLY_VIEW|Start": re.compile(r'.*swss#orchagent.*notifySyncd.*sending syncd.*APPLY_VIEW.*'),
        "APPLY_VIEW|End": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*switched ASIC to APPLY VIEW.*'),
        "LAG_READY|Start": re.compile(r'.*teamd#tlm_teamd.*try_add_lag.*The LAG \'PortChannel.*\' has been added.*'),
    },
    "201911": {
        "INIT_VIEW|Start": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*sending syncd.*INIT view.*'),
        "INIT_VIEW|End": re.compile(r'.*swss#orchagent.*initSaiRedis.*Notify syncd INIT_VIEW.*'),
        "APPLY_VIEW|Start": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*sending syncd.*APPLY view.*'),
        "APPLY_VIEW|End": re.compile(r'.*syncd#SDK.*notifySyncd.*setting very first run to FALSE, op = APPLY_VIEW.*'),
        "LAG_READY|Start": re.compile(r'.*teamd#teammgrd.*setLagAdminStatus.*Set port channel PortChannel.*admin status to up')
    },
    "BRCM": {
        "SYNCD_CREATE_SWITCH|Start": re.compile(r'.*syncd#syncd.*performWarmRestart: switches defined in warm restart.*'),
        "SYNCD_CREATE_SWITCH|End": re.compile(r'.*syncd#syncd.*performWarmRestartSingleSwitch: Warm boot: create switch VID.*'),
        "FDB_EVENT_OTHER_MAC_EXPIRY|Start": re.compile(r".* INFO syncd#syncd.*SAI_API_FDB.*fdbEvent: 0 for mac (?!00-06-07-08-09-0A).*"),
        "FDB_EVENT_SCAPY_MAC_EXPIRY|Start": re.compile(r".* INFO syncd#syncd.*SAI_API_FDB.*fdbEvent: 0 for mac 00-06-07-08-09-0A.*")
    },
    "MLNX": {
        "SYNCD_CREATE_SWITCH|Start": re.compile(r'.*syncd.*mlnx_sai_switch.*mlnx_create_switch: Create switch.*INIT_SWITCH=true.*'),
        "SYNCD_CREATE_SWITCH|End": re.compile(r'.*syncd#SDK.*mlnx_sai_switch.*mlnx_create_switch.*Created switch Switch ID.*')
    }
}

SAIREDIS_PATTERNS = {
    "SAI_CREATE_SWITCH|Start": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_SWITCH.*'),
    "SAI_CREATE_SWITCH|End": re.compile(r'.*\|g\|SAI_OBJECT_TYPE_SWITCH.*SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID.*'),
    "NEIGHBOR_ENTRY|Start": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_NEIGHBOR_ENTRY.*'),
    "DEFAULT_ROUTE_SET|Start": re.compile(r'.*\|(S|s)\|SAI_OBJECT_TYPE_ROUTE_ENTRY.*0\.0\.0\.0/0.*SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION=SAI_PACKET_ACTION_FORWARD.*'),
    "FDB_RESTORE|Start": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_FDB_ENTRY.*'),
    "FDB_EVENT_OTHER_MAC_EXPIRY|Start": re.compile(r".*\|n\|fdb_event.*fdb_entry.*mac.*(?!00:06:07:08:09:0A).*fdb_event.*SAI_FDB_EVENT_LEARNED.*SAI_FDB_ENTRY_ATTR_TYPE.*SAI_FDB_ENTRY_TYPE_DYNAMIC.*SAI_FDB_ENTRY_ATTR_PACKET_ACTION.*SAI_PACKET_ACTION_FORWARD.*"),
    "FDB_EVENT_SCAPY_MAC_EXPIRY|Start": re.compile(r".*\|n\|fdb_event.*fdb_entry.*mac.*00:06:07:08:09:0A.*fdb_event.*SAI_FDB_EVENT_LEARNED.*SAI_FDB_ENTRY_ATTR_TYPE.*SAI_FDB_ENTRY_TYPE_DYNAMIC.*SAI_FDB_ENTRY_ATTR_PACKET_ACTION.*SAI_PACKET_ACTION_FORWARD.*"),
}

OFFSET_ITEMS = ['DATABASE', 'FINALIZER', 'INIT_VIEW', 'SYNCD_CREATE_SWITCH',
    'FPMSYNCD_RECONCILIATION', 'PORT_INIT', 'PORT_READY', 'SAI_CREATE_SWITCH',
    'NEIGHBOR_ENTRY', 'DEFAULT_ROUTE_SET', 'APPLY_VIEW', 'LAG_READY',
    'FDB_RESTORE', 'ROUTE_DEFERRAL_TIMER']

TIME_SPAN_ITEMS = ['RADV', 'BGP', 'SYNCD', 'SWSS', 'TEAMD', 'DATABASE',
    'SYNCD_CREATE_SWITCH', 'SAI_CREATE_SWITCH', 'APPLY_VIEW', 'INIT_VIEW',
    'NEIGHBOR_ENTRY', 'PORT_INIT', 'PORT_READY', 'FINALIZER', 'LAG_READY',
    'FPMSYNCD_RECONCILIATION', 'ROUTE_DEFERRAL_TIMER', 'FDB_RESTORE']
