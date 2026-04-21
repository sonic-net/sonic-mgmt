FILTER_KEY_MAP = {
    "both-way": "filterRelationships",
    "consumer-to-provider": "filterRelationshipsConsumerToProvider",
    "provider-to-consumer": "filterRelationshipsProviderToConsumer",
}

PRIORITY_MAP = {
    "default": "default",
    "lowest_priority": "level1",
    "medium_priority": "level2",
    "highest_priority": "level3",
}

SERVICE_NODE_CONNECTOR_MAP = {
    "bd": {"id": "bd", "connector_type": "general"}
    # 'external_epg': {'id': 'externalEpg', 'connector_type': 'route-peering'}
}

YES_OR_NO_TO_BOOL_STRING_MAP = {"yes": "true", "no": "false", True: "yes", False: "no"}

ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP = {"enabled": True, "disabled": False}
BOOL_TO_ENABLED_OR_DISABLED_STRING_MAP = {True: "enabled", False: "disabled"}

NDO_4_UNIQUE_IDENTIFIERS = ["templateID", "autoRouteTargetImport", "autoRouteTargetExport"]

NDO_API_VERSION_FORMAT = "/mso/api/{api_version}"
NDO_API_VERSION_PATH_FORMAT = "/mso/api/{api_version}/{path}"

NDO_CIPHER_SUITE_MAP = {
    "128_gcm_aes": "128GcmAes",
    "128_gcm_aes_xpn": "128GcmAesXpn",
    "256_gcm_aes": "256GcmAes",
    "256_gcm_aes_xpn": "256GcmAesXpn",
}

NDO_SECURITY_POLICY_MAP = {
    "should_secure": "shouldSecure",
    "must_secure": "mustSecure",
}

EPG_U_SEG_ATTR_TYPE_MAP = {
    "ip": "ip",
    "mac": "mac",
    "dns": "dns",
    "vm_datacenter": "rootContName",
    "vm_hypervisor_identifier": "hv",
    "vm_operating_system": "guest-os",
    "vm_tag": "tag",
    "vm_identifier": "vm",
    "vmm_domain": "domain",
    "vm_name": "vm-name",
    "vnic_dn": "vnic",
}

EPG_U_SEG_ATTR_OPERATOR_LIST = ["equals", "contains", "starts_with", "ends_with"]

AZURE_L4L7_CONNECTOR_TYPE_MAP = {
    "none": "none",
    "redirect": "redir",
    "source_nat": "snat",
    "destination_nat": "dnat",
    "source_and_destination_nat": "snat_dnat",
}

LISTENER_PROTOCOLS = ["http", "https", "tcp", "udp", "tls", "inherit"]

LISTENER_SECURITY_POLICY_MAP = {
    "default": "default",
    "elb_sec_2016_18": "eLBSecurityPolicy-2016-08",
    "elb_sec_fs_2018_06": "eLBSecurityPolicy-FS-2018-06",
    "elb_sec_tls_1_2_2017_01": "eLBSecurityPolicy-TLS-1-2-2017-01",
    "elb_sec_tls_1_2_ext_2018_06": "eLBSecurityPolicy-TLS-1-2-Ext-2018-06",
    "elb_sec_tls_1_1_2017_01": "eLBSecurityPolicy-TLS-1-1-2017-01",
    "elb_sec_2015_05": "eLBSecurityPolicy-2015-05",
    "elb_sec_tls_1_0_2015_04": "eLBSecurityPolicy-TLS-1-0-2015-04",
    "app_gw_ssl_default": "AppGwSslPolicyDefault",
    "app_gw_ssl_2015_501": "AppGwSslPolicy20150501",
    "app_gw_ssl_2017_401": "AppGwSslPolicy20170401",
    "app_gw_ssl_2017_401s": "AppGwSslPolicy20170401S",
}

LISTENER_ACTION_TYPE_MAP = {"fixed_response": "fixedResponse", "forward": "forward", "redirect": "redirect", "ha_port": "haPort"}

LISTENER_CONTENT_TYPE_MAP = {"text_plain": "textPlain", "text_css": "textCSS", "text_html": "textHtml", "app_js": "appJS", "app_json": "appJson"}

LISTENER_REDIRECT_CODE_MAP = {
    "unknown": "unknown",
    "permanently_moved": "permMoved",
    "found": "found",
    "see_other": "seeOther",
    "temporary_redirect": "temporary",
}

PORT_CHANNEL_MODE_MAP = {
    "lacp_active": "active",
    "lacp_passive": "passive",
    "static_channel_mode_on": "off",
    "mac_pinning": "mac-pin",
    "mac_pinning_physical_nic_load": "mac-pin-nicload",
    "use_explicit_failover_order": "explicit-failover",
}

CONTROL_MAP = {
    "fast_sel_hot_stdby": "fast-sel-hot-stdby",
    "graceful_conv": "graceful-conv",
    "susp_individual": "susp-individual",
    "load_defer": "load-defer",
    "symmetric_hash": "symmetric-hash",
}

LINK_LEVEL_FEC_MAP = {
    "inherit": "inherit",
    "cl74_fc_fec": "cl74-fc-fec",
    "cl91_rs_fec": "cl91-rs-fec",
    "cons16_rs_fec": "cons16-rs-fec",
    "ieee_rs_fec": "ieee-rs-fec",
    "kp_fec": "kp-fec",
    "disable_fec": "disable-fec",
}

L2_INTERFACE_QINQ_MAP = {
    "double_q_tag_port": "doubleQtagPort",
    "core_port": "corePort",
    "edge_port": "edgePort",
    "disabled": "disabled",
}

LOAD_BALANCE_HASHING_MAP = {
    "destination_ip": "dst-ip",
    "layer_4_destination_ip": "l4-dst-port",
    "layer_4_source_ip": "l4-src-port",
    "source_ip": "src-ip",
}

TEMPLATE_TYPES = {
    "tenant": {
        "template_type": "tenantPolicy",  # templateType in payload
        "template_type_container": "tenantPolicyTemplate",  # templateType container in payload
        "tenant": True,  # tenant required
        "site_amount": 2,  # 1 = 1 site, 2 = multiple sites
        "template_container": True,  # configuration is set in template container in payload
    },
    "l3out": {
        "template_type": "l3out",
        "template_type_container": "l3outTemplate",
        "tenant": True,
        "site_amount": 1,
        "template_container": False,
    },
    "fabric_policy": {
        "template_type": "fabricPolicy",
        "template_type_container": "fabricPolicyTemplate",
        "tenant": False,
        "site_amount": 2,
        "template_container": True,
    },
    "fabric_resource": {
        "template_type": "fabricResource",
        "template_type_container": "fabricResourceTemplate",
        "tenant": False,
        "site_amount": 2,
        "template_container": True,
    },
    "monitoring_tenant": {
        "template_type": "monitoring",
        "template_type_container": "monitoringTemplate",
        "tenant": True,
        "site_amount": 1,
        "template_container": True,
    },
    "monitoring_access": {
        "template_type": "monitoring",
        "template_type_container": "monitoringTemplate",
        "tenant": False,
        "site_amount": 1,
        "template_container": True,
    },
    "service_device": {
        "template_type": "serviceDevice",
        "template_type_container": "deviceTemplate",
        "tenant": True,
        "site_amount": 2,
        "template_container": True,
    },
    "application": {
        "template_type": "application",
        "template_type_container": "appTemplate",
        "tenant": True,
        "site_amount": 2,
        "template_container": True,
    },
}

TARGET_DSCP_MAP = {
    "af11": "af11",
    "af12": "af12",
    "af13": "af13",
    "af21": "af21",
    "af22": "af22",
    "af23": "af23",
    "af31": "af31",
    "af32": "af32",
    "af33": "af33",
    "af41": "af41",
    "af42": "af42",
    "af43": "af43",
    "cs0": "cs0",
    "cs1": "cs1",
    "cs2": "cs2",
    "cs3": "cs3",
    "cs4": "cs4",
    "cs5": "cs5",
    "cs6": "cs6",
    "cs7": "cs7",
    "expedited_forwarding": "expeditedForwarding",
    "voice_admit": "voiceAdmit",
    "unspecified": "unspecified",
}

ORIGINATE_DEFAULT_ROUTE = {"only": "only", "in_addition": "inAddition", "": ""}
L3OUT_ROUTING_PROTOCOLS = {"bgp": ["bgp"], "ospf": ["ospf"], "bgpOspf": ["bgp", "ospf"], None: [None], "": None, "bgpospf": "bgpOspf", "ospfbgp": "bgpOspf"}

QOS_LEVEL = ["unspecified", "level1", "level2", "level3", "level4", "level5", "level6"]
SYNC_E_QUALITY_LEVEL_OPTION = {"option_1": "op1", "option_2_generation_1": "op2g1", "option_2_generation_2": "op2g2"}
PROFILE_TEMPLATE = {"aes67_2015": "aes67", "default": "default", "smpte_2059_2": "smpte", "telecom_8275_1": "telecomFullPath"}

TARGET_COS_MAP = {
    "background": "cos0",
    "best_effort": "cos1",
    "excellent_effort": "cos2",
    "critical_applications": "cos3",
    "video": "cos4",
    "voice": "cos5",
    "internetwork_control": "cos6",
    "network_control": "cos7",
    "unspecified": "cos8",
}

DSCP_COS_KEY_MAP = {
    "dscp_from": "dscpFrom",
    "dscp_to": "dscpTo",
    "dot1p_from": "dot1pFrom",
    "dot1p_to": "dot1pTo",
    "dscp_target": "dscpTarget",
    "target_cos": "targetCos",
    "qos_priority": "priority",
}

LOCAL_ASN_CONFIG = {"none": "none", "no_prepend": "no-prepend", "dual_as": "dual-as", "replace_as": "replace-as"}

QOS_CONGESTION_ALGORITHM_MAP = {"tail_drop": "tailDrop", "wred": "wred"}
QOS_SCHEDULING_ALGORITHM_MAP = {"strict_priority": "strictPriority", "weighted_round_robin": "wrr"}
QOS_PFC_SCOPE_MAP = {"fabric_wide": "fabricWide", "intra_tor": "intraTor"}
COS_VALUES = ["cos0", "cos1", "cos2", "cos3", "cos4", "cos5", "cos6", "cos7", "unspecified"]

PORT_MAPPING = {
    "dns": "53",
    "ftp_data": "20",
    "http": "80",
    "https": "443",
    "pop3": "110",
    "rtsp": "554",
    "smtp": "25",
    "ssh": "22",
    "unspecified": "0",
}

IP_PROTOCOL_MAPPING = {
    "unspecified": "0",
    "egp": "8",
    "eigrp": "88",
    "icmp": "1",
    "icmpv6": "58",
    "igmp": "2",
    "igp": "9",
    "l2tp": "115",
    "ospfigp": "89",
    "pim": "103",
    "tcp": "6",
    "udp": "17",
}

CONTRACT_SERVICE_CHAIN_NODE_FILTER_MAP = {"allow_all": "allow-all", "filters_from_contract": "filters-from-contract"}

PTP_MODES = {"multicast_dynamic": "multicast", "multicast_master": "multicastMaster", "unicast_master": "unicastMaster"}

DOMAIN_TYPE_MAP = {"vmm": "vmmDomain", "physical": "physicalDomain"}

VM_DOMAIN_PROVIDER_MAP = {
    "cloudfoundry": "CloudFoundry",
    "kubernetes": "Kubernetes",
    "microsoft": "Microsoft",
    "openshift": "OpenShift",
    "openstack": "OpenStack",
    "redhat": "Redhat",
    "vmware": "VMware",
    "nutanix": "Nutanix",
}

MATCH_COMMUNITY_SCOPE_MAP = {"transitive": "transitive", "non_transitive": "non-transitive"}

ROUTE_MAP_METRIC_TYPE_MAP = {
    "type1": "ospf-type1",
    "ospf_type1": "ospf-type1",
    "type2": "ospf-type2",
    "ospf_type2": "ospf-type2",
    "": "",
}

ROUTE_MAP_POLICY_MATCH_TYPE = {"prefix_and_routing_policy": "combinable", "routing_policy_only": "global"}
