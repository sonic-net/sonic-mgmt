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
    "FEATURE|*": [
        "delayed",
        "support_syslog_rate_limit"
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
        "mpls_nexthop_threshold_type:"
    ]
}

WHITELIST_201811_202012 = {

}