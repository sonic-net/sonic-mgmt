SERVICE_PATTERNS = {
    "Stopping": re.compile(r'.*Stopping.*(service|container).*'),
    "Stopped": re.compile(r'.*Stopped.*(service|container).*'),
    "Starting": re.compile(r'.*Starting.*(service|container).*'),
    "Started": re.compile(r'.*Started.*(service|container).*')
}

OTHER_PATTERNS = {
    "INIT_VIEW|Start": re.compile(r'.*swss#orchagent.*notifySyncd.*sending syncd.*INIT_VIEW.*'),
    "INIT_VIEW|End": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*switched ASIC to INIT VIEW.*'),
    "APPLY_VIEW|Start": re.compile(r'.*swss#orchagent.*notifySyncd.*sending syncd.*APPLY_VIEW.*'),
    "APPLY_VIEW|End": re.compile(r'.*swss#orchagent.*sai_redis_notify_syncd.*switched ASIC to APPLY VIEW.*'),
    "PORT_INIT|Start": re.compile(r'.*NOTICE swss#orchagent.*initPort: Initialized port.*'),
    "PORT_READY|Start": re.compile(r'.*swss#orchagent.*updatePortOperStatus.*Port Eth.*oper state set.* to up.*'),
    "LAG_READY|Start": re.compile(r'.*teamd#tlm_teamd.*try_add_lag.*The LAG \'PortChannel.*\' has been added.*'),
    "FINALIZER|Start": re.compile(r'.*WARMBOOT_FINALIZER.*Wait for database to become ready.*'),
    "FINALIZER|End": re.compile(r"(.*WARMBOOT_FINALIZER.*Finalizing warmboot.*)|(.*WARMBOOT_FINALIZER.*warmboot is not enabled.*)"),
    "SYNCD_CREATE_SWITCH|Start": re.compile(r'.*syncd#syncd.*performWarmRestart: switches defined in warm restart.*'),
    "SYNCD_CREATE_SWITCH|End": re.compile(r'.*syncd#syncd.*performWarmRestartSingleSwitch: Warm boot: create switch VID.*'),
    "FPMSYNCD_RECONCILIATION|Start": re.compile(r'.*NOTICE bgp#fpmsyncd: :- main: Warm-Restart timer started.*'),
    "FPMSYNCD_RECONCILIATION|End": re.compile(r'.*NOTICE bgp#fpmsyncd: :- main: Warm-Restart reconciliation processed.*'),
    "ROUTE_DEFERRAL_TIMER|Start": re.compile(r'.*ADJCHANGE: neighbor .* in vrf default Up.*'),
    "ROUTE_DEFERRAL_TIMER|End": re.compile(r'.*rcvd End-of-RIB for IPv4 Unicast from.*')
}

SAIREDIS_PATTERNS = {
    "SAI_CREATE_SWITCH|Start": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_SWITCH.*'),
    "SAI_CREATE_SWITCH|End": re.compile(r'.*\|g\|SAI_OBJECT_TYPE_SWITCH.*SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID.*'),
    "NEIGHBOR_ENTRY|Start": re.compile(r'.*\|c\|SAI_OBJECT_TYPE_NEIGHBOR_ENTRY.*'),
    "DEFAULT_ROUTE_SET|Start": re.compile(r'.*\|(S|s)\|SAI_OBJECT_TYPE_ROUTE_ENTRY.*0\.0\.0\.0/0.*SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION=SAI_PACKET_ACTION_FORWARD.*')
}

OFFSET_ITEMS = ['DATABASE', 'FINALIZER', 'INIT_VIEW', 'SYNCD_CREATE_SWITCH',
    'FPMSYNCD_RECONCILIATION', 'PORT_INIT', 'PORT_READY', 'SAI_CREATE_SWITCH',
    'NEIGHBOR_ENTRY', 'DEFAULT_ROUTE_SET', 'APPLY_VIEW', 'LAG_READY',
    'ROUTE_DEFERRAL_TIMER']

TIME_SPAN_ITEMS = ['RADV', 'BGP', 'SYNCD', 'SWSS', 'TEAMD', 'DATABASE',
    'SYNCD_CREATE_SWITCH', 'SAI_CREATE_SWITCH', 'APPLY_VIEW', 'INIT_VIEW',
    'NEIGHBOR_ENTRY', 'PORT_INIT', 'PORT_READY', 'FINALIZER', 'LAG_READY',
    'FPMSYNCD_RECONCILIATION', 'ROUTE_DEFERRAL_TIMER']
