WHITELIST_202012_202305 = {
    "QUEUE|Ethernet*": [
        "scheduler"
    ],
    "PORT_QOS_MAP|Ethernet*": [
        "dscp_to_tc_map",
        "pfc_enable",
        "pfc_to_queue_map",
        "pfcwd_sw_enable",
        "tc_to_pg_map",
        "tc_to_queue_map"
    ],
    "BUFFER_PG|Ethernet*": [
        "profile"
    ],
    "VERSIONS|DATABASE": [
        "VERSION"
    ],
    "DEVICE_METADATA|localhost": [
        "timezone",
        "yang_config_validation"
    ],
    "FEATURE|p4rt": [],
    "FEATURE|macsec": [],
    "FEATURE|gnmi": [],
    "FEATURE|eventd": [],
    "FEATURE|restapi": [],
    "FEATURE|*": [
        "delayed",
        "support_syslog_rate_limit",
        "has_timer",
        "set_owner"
    ],
    "BUFFER_QUEUE|Ethernet*": [
        "profile"
    ],
    "CRM|Config": [
        "mpls_inseg_high_threshold",
        "mpls_inseg_low_threshold",
        "mpls_inseg_threshold_type",
        "mpls_nexthop_high_threshold",
        "mpls_nexthop_low_threshold",
        "mpls_nexthop_threshold_type"
    ],
    "VLAN|Vlan*": [
        "members"
    ],
    "PORT|Ethernet*": [
        "tpid"
    ],
    "PORTCHANNEL|PortChannel*": [
        "members",
        "tpid",
        "lacp_key"
    ],
    "DEVICE_NEIGHBOR_METADATA|ARISTA*": [
        "lo_addr",
        "mgmt_addr_v6",
        "hwsku"
    ],
    "BGP_NEIGHBOR|*": [
        "admin_status"
    ],
    "PASSW_HARDENING|*": [],
    "AUTO_TECHSUPPORT|*": [],
    "SYSLOG_CONFIG|*": [],
    "GNMI|*": [],
    "SYSLOG_CONFIG_FEATURE|*": [],
    "SYSTEM_DEFAULTS|*": [],
    "LOGGER|*": [],
    "AUTO_TECHSUPPORT_FEATURE|*": [],
    "BGP_DEVICE_GLOBAL|*": [],
    "SNMP|*": [],
    "SNMP_COMMUNITY|*": [],
    "FLEX_COUNTER_TABLE|*": []

}

WHITELIST_201811_202012 = {
    "DEVICE_METADATA|localhost": [
        "buffer_model",
        "cloudtype",
        "region",
        "synchronous_mode"
    ],
    "VLAN|Vlan*": [
        "members"
    ],
    "CRM|Config": [
        "dnat_entry_high_threshold",
        "dnat_entry_low_threshold",
        "dnat_entry_threshold_type",
        "ipmc_entry_high_threshold",
        "ipmc_entry_low_threshold",
        "ipmc_entry_threshold_type",
        "snat_entry_high_threshold",
        "snat_entry_low_threshold",
        "snat_entry_threshold_type"
    ],
    "VLAN_INTERFACE|*": [],
    "BGP_NEIGHBOR|*": [
        "admin_status"
    ],
    "PORTCHANNEL_INTERFACE|*": [],
    "LOOPBACK_INTERFACE|*": [],
    "PORT_QOS_MAP|Ethernet*": [
        "pfcwd_sw_enable",
    ],
    "PORT_QOS_MAP|global": [],
    "VERSIONS|DATABASE": [
        "VERSION"
    ],
    "CONSOLE_SWITCH|*": [],
    "SNMP|*": [],
    "SNMP_COMMUNITY|*": [],
    "FLEX_COUNTER_TABLE|*": [],
    "RESTAPI|*": [],
    "TELEMETRY|*": [],
    "FEATURE|*": [],
    "KDUMP|*": []
}
