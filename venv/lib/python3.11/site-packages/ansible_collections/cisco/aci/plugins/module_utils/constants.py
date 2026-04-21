VALID_IP_PROTOCOLS = ["eigrp", "egp", "icmp", "icmpv6", "igmp", "igp", "l2tp", "ospfigp", "pim", "tcp", "udp", "unspecified"]

FILTER_PORT_MAPPING = {"443": "https", "25": "smtp", "80": "http", "53": "dns", "110": "pop3", "554": "rtsp", "20": "ftpData", "ftp": "ftpData"}

VALID_ETHER_TYPES = ["arp", "fcoe", "ip", "ipv4", "ipv6", "mac_security", "mpls_ucast", "trill", "unspecified"]

VALID_QOS_CLASSES = ["unspecified", "level1", "level2", "level3", "level4", "level5", "level6"]

# mapping dicts are used to normalize the proposed data to what the APIC expects, which will keep diffs accurate
ARP_FLAG_MAPPING = dict(arp_reply="reply", arp_request="req", unspecified="unspecified")

# ICMPv4 Types Mapping
ICMP4_MAPPING = dict(
    dst_unreachable="dst-unreach", echo="echo", echo_reply="echo-rep", src_quench="src-quench", time_exceeded="time-exceeded", unspecified="unspecified"
)

# ICMPv6 Types Mapping
ICMP6_MAPPING = dict(
    dst_unreachable="dst-unreach",
    echo_request="echo-req",
    echo_reply="echo-rep",
    neighbor_advertisement="nbr-advert",
    neighbor_solicitation="nbr-solicit",
    redirect="redirect",
    time_exceeded="time-exceeded",
    unspecified="unspecified",
)

TCP_FLAGS = dict(acknowledgment="ack", established="est", finish="fin", reset="rst", synchronize="syn", unspecified="unspecified")

SUBNET_CONTROL_MAPPING = {"nd_ra_prefix": "nd", "no_default_gateway": "no-default-gateway", "querier_ip": "querier", "unspecified": ""}
SUBNET_CONTROL_MAPPING_BD_SUBNET = {"nd_ra": "nd", "no_gw": "no-default-gateway", "querier_ip": "querier", "unspecified": ""}

NODE_TYPE_MAPPING = {"tier_2": "tier-2-leaf", "remote": "remote-leaf-wan", "virtual": "virtual", "unspecified": "unspecified"}

SPAN_DIRECTION_MAP = {"incoming": "in", "outgoing": "out", "both": "both"}

MATCH_TYPE_MAPPING = {"all": "All", "at_least_one": "AtleastOne", "at_most_one": "AtmostOne", "none": "None"}

IPV4_REGEX = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"

VM_PROVIDER_MAPPING = dict(
    cloudfoundry="CloudFoundry",
    kubernetes="Kubernetes",
    microsoft="Microsoft",
    openshift="OpenShift",
    openstack="OpenStack",
    redhat="Redhat",
    vmware="VMware",
    nutanix="Nutanix",
)

SYSLOG_FORMATS = {"enhanced_log": "rfc5424-ts", "nxos": "nxos", "aci": "aci", "rfc5424_ts": "rfc5424-ts"}

VM_SCOPE_MAPPING = dict(
    cloudfoundry="cloudfoundry",
    kubernetes="kubernetes",
    microsoft="MicrosoftSCVMM",
    openshift="openshift",
    openstack="openstack",
    redhat="rhev",
    vmware="vm",
    nutanix="nutanix",
)

MATCH_TYPE_GROUP_MAPPING = {"all": "ALL", "all_in_pod": "ALL_IN_POD", "range": "range"}

MATCH_FC_FILL_PATTERN_MAPPING = {"arbff": "ARBFF", "idle": "IDLE"}

MATCH_FIRMWARE_NODES_TYPE_MAPPING = {
    "c_apic_patch": "cApicPatch",
    "catalog": "catalog",
    "config": "config",
    "controller": "controller",
    "controller_patch": "controllerPatch",
    "plugin": "plugin",
    "plugin_package": "pluginPackage",
    "switch": "switch",
    "switch_patch": "switchPatch",
    "vpod": "vpod",
}

MATCH_TRIGGER_MAPPING = {
    "trigger": "trigger",
    "trigger_immediate": "trigger-immediate",
    "triggered": "triggered",
    "untriggered": "untriggered",
}

INTERFACE_POLICY_FC_SPEED_LIST = ["auto", "unknown", "2G", "4G", "8G", "16G", "32G"]

MATCH_RUN_MODE_MAPPING = dict(
    pause_always_between_sets="pauseAlwaysBetweenSets",
    pause_only_on_failures="pauseOnlyOnFailures",
    pause_never="pauseNever",
)

MATCH_NOTIFY_CONDITION_MAPPING = dict(
    notify_always_between_sets="notifyAlwaysBetweenSets",
    notify_never="notifyNever",
    notify_only_on_failures="notifyOnlyOnFailures",
)

MATCH_SMU_OPERATION_MAPPING = dict(smu_install="smuInstall", smu_uninstall="smuUninstall")

MATCH_SMU_OPERATION_FLAGS_MAPPING = dict(smu_reload_immediate="smuReloadImmediate", smu_reload_skip="smuReloadSkip")

MATCH_BEST_PATH_CONTROL_MAPPING = dict(enable="asPathMultipathRelax", disable="")

MATCH_GRACEFUL_RESTART_CONTROLS_MAPPING = dict(helper="helper", complete="")

EP_LOOP_PROTECTION_ACTION_MAPPING = {"bd": "bd-learn-disable", "port": "port-disable"}

FABRIC_POD_SELECTOR_TYPE_MAPPING = dict(all="ALL", range="range")

OPFLEX_TLS_MAPPING = {"tls_v1.0": "TLSv1", "tls_v1.1": "TLSv1.1", "tls_v1.2": "TLSv1.2"}

HTTP_TLS_MAPPING = {"tls_v1.0": "TLSv1", "tls_v1.1": "TLSv1.1", "tls_v1.2": "TLSv1.2", "tls_v1.3": "TLSv1.3"}

ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING = dict(
    spine=dict(
        class_name="infraSpineAccNodePGrp",
        rn="infra/funcprof/spaccnodepgrp-{0}",
        copp_pre_filter_policy=dict(class_name="infraRsIaclSpineProfile", tn_name="tnIaclSpineProfileName"),
        bfd_ipv4_policy=dict(class_name="infraRsSpineBfdIpv4InstPol", tn_name="tnBfdIpv4InstPolName"),
        bfd_ipv6_policy=dict(class_name="infraRsSpineBfdIpv6InstPol", tn_name="tnBfdIpv6InstPolName"),
        copp_policy=dict(class_name="infraRsSpineCoppProfile", tn_name="tnCoppSpineProfileName"),
        cdp_policy=dict(class_name="infraRsSpinePGrpToCdpIfPol", tn_name="tnCdpIfPolName"),
        lldp_policy=dict(class_name="infraRsSpinePGrpToLldpIfPol", tn_name="tnLldpIfPolName"),
        usb_configuration_policy=dict(class_name="infraRsSpineTopoctrlUsbConfigProfilePol", tn_name="tnTopoctrlUsbConfigProfilePolName"),
    ),
    leaf=dict(
        class_name="infraAccNodePGrp",
        rn="infra/funcprof/accnodepgrp-{0}",
        copp_pre_filter_policy=dict(class_name="infraRsIaclLeafProfile", tn_name="tnIaclLeafProfileName"),
        bfd_ipv4_policy=dict(class_name="infraRsBfdIpv4InstPol", tn_name="tnBfdIpv4InstPolName"),
        bfd_ipv6_policy=dict(class_name="infraRsBfdIpv6InstPol", tn_name="tnBfdIpv6InstPolName"),
        copp_policy=dict(class_name="infraRsLeafCoppProfile", tn_name="tnCoppLeafProfileName"),
        cdp_policy=dict(class_name="infraRsLeafPGrpToCdpIfPol", tn_name="tnCdpIfPolName"),
        lldp_policy=dict(class_name="infraRsLeafPGrpToLldpIfPol", tn_name="tnLldpIfPolName"),
        usb_configuration_policy=dict(class_name="infraRsLeafTopoctrlUsbConfigProfilePol", tn_name="tnTopoctrlUsbConfigProfilePolName"),
    ),
)

PIM_SETTING_CONTROL_STATE_MAPPING = {"fast": "fast-conv", "strict": "strict-rfc-compliant"}

ACI_CLASS_MAPPING = dict(
    consumer={
        "class": "fvRsCons",
        "rn": "rscons-",
        "name": "tnVzBrCPName",
    },
    provider={
        "class": "fvRsProv",
        "rn": "rsprov-",
        "name": "tnVzBrCPName",
    },
    oob_provider={
        "class": "mgmtRsOoBProv",
        "rn": "rsooBProv-",
        "name": "tnVzOOBBrCPName",
    },
    taboo={
        "class": "fvRsProtBy",
        "rn": "rsprotBy-",
        "name": "tnVzTabooName",
    },
    interface={
        "class": "fvRsConsIf",
        "rn": "rsconsIf-",
        "name": "tnVzCPIfName",
    },
    intra_epg={
        "class": "fvRsIntraEpg",
        "rn": "rsintraEpg-",
        "name": "tnVzBrCPName",
    },
    intra_esg={
        "class": "fvRsIntraEpg",
        "rn": "rsintraEpg-",
        "name": "tnVzBrCPName",
    },
)

PROVIDER_MATCH_MAPPING = dict(
    all="All",
    at_least_one="AtleastOne",
    at_most_one="AtmostOne",
    none="None",
)

CONTRACT_LABEL_MAPPING = dict(
    consumer="vzConsLbl",
    provider="vzProvLbl",
)

SUBJ_LABEL_MAPPING = dict(
    consumer="vzConsSubjLbl",
    provider="vzProvSubjLbl",
)

SUBJ_LABEL_RN = dict(
    consumer="conssubjlbl-",
    provider="provsubjlbl-",
)

MATCH_ACTION_RULE_SET_METRIC_TYPE_MAPPING = {"ospf_type_1": "ospf-type1", "ospf_type_2": "ospf-type2", "": ""}

MATCH_EIGRP_INTERFACE_POLICY_DELAY_UNIT_MAPPING = dict(picoseconds="pico", tens_of_microseconds="tens-of-micro")

MATCH_EIGRP_INTERFACE_POLICY_CONTROL_STATE_MAPPING = dict(bfd="bfd", nexthop_self="nh-self", passive="passive", split_horizon="split-horizon")

MATCH_TARGET_COS_MAPPING = {
    "background": "0",
    "best_effort": "1",
    "excellent_effort": "2",
    "critical_applications": "3",
    "video": "4",
    "voice": "5",
    "internetwork_control": "6",
    "network_control": "7",
    "unspecified": "unspecified",
}

MATCH_PIM_INTERFACE_POLICY_CONTROL_STATE_MAPPING = dict(multicast_domain_boundary="border", strict_rfc_compliant="strict-rfc-compliant", passive="passive")

MATCH_PIM_INTERFACE_POLICY_AUTHENTICATION_TYPE_MAPPING = dict(none="none", md5_hmac="ah-md5")

MATCH_COLLECT_NETFLOW_RECORD_MAPPING = dict(
    bytes_counter="count-bytes",
    pkts_counter="count-pkts",
    pkt_disposition="pkt-disp",
    sampler_id="sampler-id",
    source_interface="src-intf",
    tcp_flags="tcp-flags",
    first_pkt_timestamp="ts-first",
    recent_pkt_timestamp="ts-recent",
)

MATCH_MATCH_NETFLOW_RECORD_MAPPING = dict(
    destination_ipv4_v6="dst-ip",
    destination_ipv4="dst-ipv4",
    destination_ipv6="dst-ipv6",
    destination_mac="dst-mac",
    destination_port="dst-port",
    ethertype="ethertype",
    ip_protocol="proto",
    source_ipv4_v6="src-ip",
    source_ipv4="src-ipv4",
    source_ipv6="src-ipv6",
    source_mac="src-mac",
    source_port="src-port",
    ip_tos="tos",
    unspecified="unspecified",
    vlan="vlan",
)

MATCH_SOURCE_IP_TYPE_NETFLOW_EXPORTER_MAPPING = dict(
    custom_source_ip="custom-src-ip",
    inband_management_ip="inband-mgmt-ip",
    out_of_band_management_ip="oob-mgmt-ip",
    ptep="ptep",
)

ECC_CURVE = {"P256": "prime256v1", "P384": "secp384r1", "P521": "secp521r1", "none": "none"}

THROTTLE_UNIT = dict(requests_per_second="r/s", requests_per_minute="r/m")

SSH_CIPHERS = dict(
    aes128_ctr="aes128-ctr",
    aes192_ctr="aes192-ctr",
    aes256_ctr="aes256-ctr",
    aes128_gcm="aes128-gcm@openssh.com",
    aes256_gcm="aes256-gcm@openssh.com",
    chacha20="chacha20-poly1305@openssh.com",
)

SSH_MACS = dict(
    sha1="hmac-sha1",
    sha2_256="hmac-sha2-256",
    sha2_512="hmac-sha2-512",
    sha2_256_etm="hmac-sha2-256-etm@openssh.com",
    sha2_512_etm="hmac-sha2-512-etm@openssh.com",
)

KEX_ALGORITHMS = dict(
    dh_sha1="diffie-hellman-group14-sha1",
    dh_sha256="diffie-hellman-group14-sha256",
    dh_sha512="diffie-hellman-group16-sha512",
    curve_sha256="curve25519-sha256",
    curve_sha256_libssh="curve25519-sha256@libssh.org",
    ecdh_256="ecdh-sha2-nistp256",
    ecdh_384="ecdh-sha2-nistp384",
    ecdh_521="ecdh-sha2-nistp521",
)

USEG_ATTRIBUTE_MAPPING = dict(
    ip=dict(attribute_type="ip", attribute_class="fvIpAttr", rn_format="ipattr-{0}"),
    mac=dict(attribute_type="mac", attribute_class="fvMacAttr", rn_format="macattr-{0}"),
    dns=dict(attribute_type="dns", attribute_class="fvDnsAttr", rn_format="dnsattr-{0}"),
    ad_group=dict(attribute_type="ad", attribute_class="fvIdGroupAttr", rn_format="idgattr-[{0}]"),
    vm_custom_attr=dict(attribute_type="custom-label", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_vmm_domain=dict(attribute_type="domain", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_operating_system=dict(attribute_type="guest-os", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_hypervisor_id=dict(attribute_type="hv", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_datacenter=dict(attribute_type="rootContName", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_id=dict(attribute_type="vm", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_name=dict(attribute_type="vm-name", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_folder=dict(attribute_type="vm-folder", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_folder_path=dict(attribute_type="vmfolder-path", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_vnic=dict(attribute_type="vnic", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
    vm_tag=dict(attribute_type="tag", attribute_class="fvVmAttr", rn_format="vmattr-{0}"),
)

OPERATOR_MAPPING = dict(equals="equals", contains="contains", starts_with="startsWith", ends_with="endsWith")

MATCH_STORM_CONTROL_POLICY_TYPE_MAPPING = dict(all_types="Invalid", unicast_broadcast_multicast="Valid")

POLICY_LABEL_COLORS = [
    "alice_blue",
    "antique_white",
    "aqua",
    "aquamarine",
    "azure",
    "beige",
    "bisque",
    "black",
    "blanched_almond",
    "blue",
    "blue_violet",
    "brown",
    "burlywood",
    "cadet_blue",
    "chartreuse",
    "chocolate",
    "coral",
    "cornflower_blue",
    "cornsilk",
    "crimson",
    "cyan",
    "dark_blue",
    "dark_cyan",
    "dark_goldenrod",
    "dark_gray",
    "dark_green",
    "dark_khaki",
    "dark_magenta",
    "dark_olive_green",
    "dark_orange",
    "dark_orchid",
    "dark_red",
    "dark_salmon",
    "dark_sea_green",
    "dark_slate_blue",
    "dark_slate_gray",
    "dark_turquoise",
    "dark_violet",
    "deep_pink",
    "deep_sky_blue",
    "dim_gray",
    "dodger_blue",
    "fire_brick",
    "floral_white",
    "forest_green",
    "fuchsia",
    "gainsboro",
    "ghost_white",
    "gold",
    "goldenrod",
    "gray",
    "green",
    "green_yellow",
    "honeydew",
    "hot_pink",
    "indian_red",
    "indigo",
    "ivory",
    "khaki",
    "lavender",
    "lavender_blush",
    "lawn_green",
    "lemon_chiffon",
    "light_blue",
    "light_coral",
    "light_cyan",
    "light_goldenrod_yellow",
    "light_gray",
    "light_green",
    "light_pink",
    "light_salmon",
    "light_sea_green",
    "light_sky_blue",
    "light_slate_gray",
    "light_steel_blue",
    "light_yellow",
    "lime",
    "lime_green",
    "linen",
    "magenta",
    "maroon",
    "medium_aquamarine",
    "medium_blue",
    "medium_orchid",
    "medium_purple",
    "medium_sea_green",
    "medium_slate_blue",
    "medium_spring_green",
    "medium_turquoise",
    "medium_violet_red",
    "midnight_blue",
    "mint_cream",
    "misty_rose",
    "moccasin",
    "navajo_white",
    "navy",
    "old_lace",
    "olive",
    "olive_drab",
    "orange",
    "orange_red",
    "orchid",
    "pale_goldenrod",
    "pale_green",
    "pale_turquoise",
    "pale_violet_red",
    "papaya_whip",
    "peachpuff",
    "peru",
    "pink",
    "plum",
    "powder_blue",
    "purple",
    "red",
    "rosy_brown",
    "royal_blue",
    "saddle_brown",
    "salmon",
    "sandy_brown",
    "sea_green",
    "seashell",
    "sienna",
    "silver",
    "sky_blue",
    "slate_blue",
    "slate_gray",
    "snow",
    "spring_green",
    "steel_blue",
    "tan",
    "teal",
    "thistle",
    "tomato",
    "turquoise",
    "violet",
    "wheat",
    "white",
    "white_smoke",
    "yellow",
    "yellow_green",
]

MATCH_ACCESS_POLICIES_SELECTOR_TYPE = dict(range="range", all="ALL")

MANAGEMENT_EPG_TYPE = dict(ooband="oob", inband="inb")

MANAGEMENT_EPG_CLASS_MAPPING = dict(in_band={"epg_class": "mgmtInB", "epg_rn": "inb-"}, out_of_band={"epg_class": "mgmtOoB", "epg_rn": "oob-"})

NODE_TYPE_MAPPING = {"tier_2": "tier-2-leaf", "remote": "remote-leaf-wan", "virtual": "virtual", "unspecified": "unspecified"}

SPAN_DIRECTION_MAP = {"incoming": "in", "outgoing": "out", "both": "both"}

HTTP_VERSIONS_MAPPING = {"1.0": "HTTP10", "1.1": "HTTP11"}

L4L7_FUNC_TYPES_MAPPING = {"go_to": "GoTo", "go_through": "GoThrough", "l1": "L1", "l2": "L2"}

L4L7_HASH_ALGORITHMS_MAPPING = {"source_ip": "sip", "destination_ip": "dip", "ip_and_protocol": "sip-dip-prototype"}

L4L7_FUNCTIONAL_TEMPLATE_TYPES_MAPPING = {
    "adc_one_arm": "ADC_ONE_ARM",
    "adc_two_arm": "ADC_TWO_ARM",
    "cloud_native_fw": "CLOUD_NATIVE_FW",
    "cloud_native_lb": "CLOUD_NATIVE_LB",
    "cloud_vendor_fw": "CLOUD_VENDOR_FW",
    "cloud_vendor_lb": "CLOUD_VENDOR_LB",
    "fw_routed": "FW_ROUTED",
    "fw_trans": "FW_TRANS",
    "other": "OTHER",
}

L4L7_UI_TEMPLATE_TYPE = {
    "ndo_implicit_template": "NDO_IMPLICIT_TEMPLATE",
    "one_node_adc_one_arm": "ONE_NODE_ADC_ONE_ARM",
    "one_node_adc_one_arm_l3ext": "ONE_NODE_ADC_ONE_ARM_L3EXT",
    "one_node_adc_two_arm": "ONE_NODE_ADC_TWO_ARM",
    "one_node_fw_routed": "ONE_NODE_FW_ROUTED",
    "one_node_fw_trans": "ONE_NODE_FW_TRANS",
    "two_node_fw_routed_adc_one_arm": "TWO_NODE_FW_ROUTED_ADC_ONE_ARM",
    "two_node_fw_routed_adc_one_arm_l3ext": "TWO_NODE_FW_ROUTED_ADC_ONE_ARM_L3EXT",
    "two_node_fw_routed_adc_two_arm": "TWO_NODE_FW_ROUTED_ADC_TWO_ARM",
    "two_node_fw_trans_adc_one_arm": "TWO_NODE_FW_TRANS_ADC_ONE_ARM",
    "two_node_fw_trans_adc_one_arm_l3ext": "TWO_NODE_FW_TRANS_ADC_ONE_ARM_L3EXT",
    "two_node_fw_trans_adc_two_arm": "TWO_NODE_FW_TRANS_ADC_TWO_ARM",
    "unspecified": "UNSPECIFIED",
}

COS_MAPPING = {"cos_0": "Cos0", "cos_1": "Cos1", "cos_2": "Cos2", "cos_3": "Cos3", "cos_4": "Cos4", "cos_5": "Cos5", "cos_6": "Cos6", "cos_7": "Cos7"}

RESERVED_ANSIBLE_INVENTORY_KEYS = {
    "serial": "_serial",
    "name": "_name",
}

MOCKED_CONSTRUCTED_INVENTORY_ARGUMENT_SPEC = dict(
    plugin=dict(type="str"),
    use_vars_plugins=dict(type="bool"),
    strict=dict(type="bool"),
    compose=dict(type="dict"),
    groups=dict(type="dict"),
    keyed_groups=dict(
        type="list",
        elements="dict",
        options=dict(
            parent_group=dict(type="str"),
            prefix=dict(type="str"),
            separator=dict(type="str"),
            key=dict(type="str"),
            default_value=dict(type="str"),
            trailing_separator=dict(type="bool"),
        ),
    ),
    use_extra_vars=dict(type="bool"),
    leading_separator=dict(type="bool"),
)

SWITCH_CONFIG_FORMAT_MAP = {
    "fabricNodeConfig": {
        "rn": "fabric/nodeconfnode-{0}",
        "type": "fabric",
        "spine": "uni/fabric/funcprof/spnodepgrp-{0}",
        "leaf": "uni/fabric/funcprof/lenodepgrp-{0}",
    },
    "infraNodeConfig": {
        "rn": "infra/nodeconfnode-{0}",
        "type": "access",
        "spine": "uni/infra/funcprof/spaccnodepgrp-{0}",
        "leaf": "uni/infra/funcprof/accnodepgrp-{0}",
    },
}

CONTRACT_CLASS_MAPPING = {"standard": {"class": "vzBrCP", "rn": "brc-{0}"}, "oob": {"class": "vzOOBBrCP", "rn": "oobbrc-{0}"}}
