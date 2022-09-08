#!/usr/bin/python3

# test status
TEST_STARTED = "Started"
TEST_INPROGRESS = "InProgress"
TEST_FINISHED = "Finished"
TEST_FAILED = "Failed"
TEST_NOT_RUN = "NotRun"

STEP_SUCCESS = "Success"
STEP_FAILURE = "Failure"

# test response
TEST_RESPONSE_NONE = "None"
TEST_RESPONSE_PASSED = "Passed"
TEST_RESPONSE_NOTPASSED = "Failed"
TEST_NOT_APPLICABLE = "NotApplicable"

TEST_DUT_VERSION_CHECK = 'interop_dut_version_check'
TEST_DUT_DC_CODE_CHECK = 'interop_dut_dc_code_check'

CHECK_DUT_DEVICE_TYPE = 'check_dut_device_type'
CHECK_DUT_STARLAB_DEVICE = 'check_dut_starlab_device'

CONVERGENCE_INTEROP_TEST_NAME = "ConvergenceInteropSuite"
HWPROXY_INTEROP_TEST_NAME = "HwproxyInteropSuite"
IPFIX_INTEROP_TEST_NAME = "IPFIXInteropSuite"
ISIS_INTEROP_TEST_NAME = "ISISInteropSuite"
Kusto_INTEROP_TEST_NAME = "KustoInteropSuite"
LACP_INTEROP_TEST_NAME = "LACPInteropTest"
LACP_INTEROP_ADD_REMOVE_LINKS_TEST_NAME = "LACPInteropAddRemoveLinksTest"
LDP_INTEROP_TEST_NAME = "LDPInteropSuite"
LLDP_INTEROP_TEST_NAME = "LLDPInteropSuite"
SNMPPROXY_INTEROP_TEST_NAME = "SnmpproxyInteropSuite"
SNMPTOOL_INTEROP_TEST_NAME = "SNMPTooInteropSuite"
SNMPX_INTEROP_TEST_NAME = "SNMPXInteropSuite"
TACACS_INTEROP_TEST_NAME = "TACACSInteropSuite"

# Eventually, we will want to refactor these topology requirements to specify vendor name instead of devicename

"""
Convergence
"""
CONVERGENCE_VERIFY_TRAFFIC = 'convergence_verify_traffic'
CONVERGENCE_VERIFY_TRAFFIC_MATRIX = 'convergence_verify_traffic_matrix'
# CONVERGENCE_TRAFFIC_FLOWS should be in the format routerA, routerZ and an IP block
# that is reachable via an LSP between the two routers.
CONVERGENCE_TRAFFIC_FLOWS = [["rwa01.str01", "rwa02.str01", "5.5.6.0/30"],
                             ["str-96c-2a", "str-96c-4a", "54.100.0.0/24"]]
CONVERGENCE_VERIFY_TRAFFIC_PATH = 'convergence_verify_traffic_path'
CONVERGENCE_VERIFY_TRAFFIC_PATH_CHANGE = 'convergence_verify_traffic_path_change'
CONVERGENCE_FAIL_LINK = 'convergence_fail_link'
CONVERGENCE_CHECK_FOR_LOSS = 'convergence_check_for_loss'
CONVERGENCE_CHECK_FOR_LOSS_BASELINE = 'convergence_check_for_loss_baseline'
CONVERGENCE_RESTORE_LINK = 'convergence_restore_link'
CONVERGENCE_MAX_LINK_METRIC = 'convergence_max_link_metric'
CONVERGENCE_RESTORE_LINK_METRIC = 'convergence_restore_link_metric'
CONVERGENCE_ISIS_OVERLOAD = 'convergence_isis_overload'
CONVERGENCE_REMOVE_ISIS_OVERLOAD = 'convergence_remove_isis_overload'

"""
IPFIX
"""
IPFIX_APPLY_CONFIGS = 'ipfix_apply_configs'
IPFIX_GET_CONFIGURED_SERVERS_PROD = 'ipfix_get_configured_servers_prod'
IPFIX_VERIFY_TRAFFIC = 'ipfix_verify_traffic'

"""
ISIS
"""
ISIS_INTEROP_TOPOLOGY_REQUIREMENTS = {"RegionalWANAggregator": {"juniper": ["ibr", "sw"], "arista": {"owr"},
                                                                "cisco": {"owr"}},
                                      "InternetCoreRouter": {"juniper": ["ier"]},
                                      "InternetBackboneRouter": {"cisco": ["rwa"]},
                                      "InternetEdgeRouter": {"juniper": ["rwa", "icr"], "cisco": ["rwa", "icr"]},
                                      "SwanRouter": {"arista": ["rwa", "sw"]},
                                      "OneWANRouter": {"arista": ["rwa03", "ibr"], "cisco": ["rwa04"]}
                                      }
ISIS_INTEROP_TEST_EXPECTED_ADJACENCY_PORTS = 1
ISIS_INTEROP_TEST_TOPOLOGY_REQUIREMENT_CHECK = 'isis_interop_test_topology_requirement_check'
ISIS_INTEROP_TEST_ISIS_ADJACENCY_CHECK = 'isis_interop_test_isis_adjacency_check'
ISIS_INTEROP_TEST_ISIS_DATABASE_CHECK = 'isis_interop_test_isis_database_check'

"""
LACP
"""
LACP_INTEROP_TOPOLOGY_REQUIREMENTS = {"RegionalWANAggregator": {"juniper": ["ibr", "sw"], "arista": {"owr"},
                                                                "cisco": {"owr"}},
                                      "InternetCoreRouter": {"juniper": ["ibr"]},
                                      "InternetBackboneRouter": {"cisco": ["rwa"]},
                                      "OneWANRouter": {"arista": ["rwa03", "ibr"], "cisco": ["rwa04"]}
                                      }

"""
LDP
"""
LDP_VERIFY_REMOTE_SESSIONS = 'ldp_verify_remote_sessions'

"""
LLDP
"""
LLDP_INTEROP_TEST_LLDP_RX_CHECK = 'lldp_interop_test_lldp_rx_check'
LLDP_INTEROP_TEST_TOPOLOGY_REQUIREMENT_CHECK = 'lldp_interop_test_topology_requirement_check'
# NOTE TO SELF: do we want to have Cisco and Arista tested to both RWA and ICRs?
LLDP_INTEROP_TOPOLOGY_REQUIREMENTS = {
    "RegionalWANAggregator":
        {"juniper": ["ibr", "sw"], "cisco": ["owr04"], "arista": ["owr03"]},
    "InternetCoreRouter":
        {"juniper": ["ier"]},
    "InternetBackboneRouter":
        {"cisco": ["rwa"]},
    "InternetEdgeRouter":
        {"juniper": ["rwa", "icr"]},
    "SwanRouter":
        {"arista": ["rwa", "sw"]},
    "OneWANRouter":
        {"arista": ["ibr", "rwa03"], "cisco": ["rwa04"]}
}

"""
MACSEC
"""

MACSEC_CIPHER_SUITE_TEST_TOPOLOGY_REQUIREMENT_CHECK = 'macsec_test_topology_requirement_check'
MACSEC_CIPHER_SUITE_TEST_NAME = "MACSec_Cipher_Suite"
MACSEC_ENCRYPTED_PACKETS_TEST_NAME = "MACSec encrypted packets"
MACSEC_FAIL_CLOSED_TEST_NAME = "MACSec Fail Closed"
MACSEC_TOPOLOGY_REQUIREMENTS = {
    "InternetBackboneRouter":
        {"juniper": ["ibr", "02sw"], "cisco": ["rwa"], "arista": ["rwa"]},
    "InternetEdgeRouter":
        {"juniper": ["rwa"], "cisco": ["icr"]},
    "InternetCoreRouter":
        {"juniper": ["ier", "01sw", "ibr"]},
    "RegionalWANAggregator":
        {"juniper": ["ibr", "01sw"]},
    "SwanRouter":
        {"arista": ["rwa"]}
}

MACSEC_CIPHER_SUITE_TEST_ADJACENCY_CHECK = 'macsec_cipher_suite_test_adjacency_check'
MACSEC_128_DEFAULT_PROFILE = {
    "name": "macsec-xpn-128-with-fallback",
    "cipher-suite": "gcm-aes-xpn-128",
    "security-mode": "static-cak",
    "mka": {
        "key-server-priority": 1
    },
    "pre-shared-key": {
        "ckn": "C32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32C",
        "cak": "KEYVALUE"
    },
    "fallback-key": {
        "ckn": "F32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32CC32C",
        "cak": "KEYVALUE"
    }
}

MACSEC_REKEY_PERIOD_TEST_TOPOLOGY_REQUIREMENT_CHECK = 'macsec_test_topology_requirement_check'
MACSEC_REKEY_PERIOD_TEST_NAME = "MACSec_Rekey_Period"
MACSEC_REKEY_PERIOD_TEST_CAPTURE_PRESTATE_CHECK = "MACSec_Capture_Prestate"
MACSEC_REKEY_PERIOD_TEST_LOAD_PRESTATE_CHECK = "MACSec_Load_Prestate"
MACSEC_REKEY_PERIOD_TEST_ADJACENCY_CHECK = 'macsec_rekey_period_test_adjacency_check'
MACSEC_REKEY_PERIOD_SET_REKEY = 'macsec_rekey_period_set_rekey'
MACSEC_REKEY_PERIOD_TEST_STATUS_LOG = 'macsec_rekey_period_status_log'

MACSEC_KEY_MISMATCH_TEST_TOPOLOGY_REQUIREMENT_CHECK = 'macsec_test_topology_requirement_check'
MACSEC_KEY_MISMATCH_TEST_NAME = "MACSec_Key_Mismatch"
MACSEC_KEY_MISMATCH_TEST_CAPTURE_PRESTATE_CHECK = "MACSec_Capture_Prestate"
MACSEC_KEY_MISMATCH_TEST_LOAD_PRESTATE_CHECK = "MACSec_Load_Prestate"
MACSEC_KEY_MISMATCH_TEST_ADJACENCY_CHECK = 'macsec_rekey_period_test_adjacency_check'
MACSEC_KEY_MISMATCH_SET_REKEY = 'macsec_rekey_period_set_rekey'
MACSEC_KEY_MISMATCH_TEST_STATUS_LOG = 'macsec_key_mismatch_check_status_log'
MACSEC_KEY_MISMATCH_PRIMARY_INCORRECT = "d64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64c"
MACSEC_KEY_MISMATCH_PRIMARY_CORRECT = "c64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64c"
MACSEC_KEY_MISMATCH_FALLBACK_INCORRECT = "e64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64c"
MACSEC_KEY_MISMATCH_FALLBACK_CORRECT = "f64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64c"
MACSEC_KEY_MISMATCH_SET_PRIMARY_KEY = 'macsec_key_mismatch_set_primary_key'
MACSEC_KEY_MISMATCH_SET_FALLBACK_KEY = 'macsec_key_mismatch_set_fallback_key'
MACSEC_KEY_MISMATCH_REBOOT_DEVICE = 'macsec_key_mismatch_reboot_device'
MACSEC_KEY_MISMATCH_LOG_MESSAGES_JUNIPER = ["DOT1XD_MACSEC_SC_FALLBACK_CAK_IN_USE",
                                            'DOT1XD_MKA_SA_KEY_ROLLOVER',
                                            'DOT1XD_MACSEC_SC_PRIMARY_CAK_IN_USE',
                                            'DOT1XD_MACSEC_SC_CAK_ACTIVATED']

MACSEC_DEACTIVATE_ON_INTERFACE = 'macsec_deactivate_on_interface'
MACSEC_ACTIVATE_ON_INTERFACE = 'macsec_activate_on_interface'

MACSEC_ISIS_ADJACENCY_CHECK = 'Step ISIS Adjacency Check, result: True'
MACSEC_RSVP_NEIGHBOR_CHECK = 'Step RSVP neighbor Check, result: True'
MACSEC_ENCRYPTED_PACKETS_CHECK = 'step MACSec encrypted packets check'

MACSEC_DEVICE_REBOOT_TEST_NAME = 'MACSec_Device_Reboot'
MACSEC_DEVICE_REBOOT_TEST_SET_PRIMARY_KEY = 'macsec_device_reboot_set_primary_key'
MACSEC_DEVICE_REBOOT_TEST_STATUS_LOG = 'macsec_device_reboot_check_status_log'
MACSEC_DEVICE_REBOOT_TEST_REBOOT_DEVICE = 'macsec_device_reboot_reboot_device'
MACSEC_DEVICE_REBOOT_TEST_ADJACENCY_CHECK = 'macsec_rekey_period_test_adjacency_check'
MACSEC_DEVICE_REBOOT_TEST_TOPOLOGY_REQUIREMENT_CHECK = 'macsec_test_topology_requirement_check'
MACSEC_DEVICE_REBOOT_TEST_CAPTURE_PRESTATE_CHECK = "MACSec_Capture_Prestate"
MACSEC_REBOOT_TEST_PRIMARY_INCORRECT = "d64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64c"
MACSEC_REBOOT_TEST_PRIMARY_CORRECT = "c64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64c"

"""
TACACS
"""
TACACS_GET_PROD_USERNAME = 'tacacs_get_prod_username'
TACACS_GET_CONFIGURED_SERVERS_LAB = 'tacacs_get_configured_servers_lab'
TACACS_GET_CONFIGURED_SERVERS_PROD = 'tacacs_get_configured_servers_prod'
TACACS_APPLY_PROD_CONFIGS = 'tacacs_apply_prod_configs'
TACACS_VERIFY_AUTH_IN_KUSTO = 'tacacs_verify_auth_in_kusto'

"""
SWAN
"""
SERVICE_ACL_OPEN_SOCKET_CHECK = "service_acl_open_socket_check"
CONNECTION_TO_URL_CHECK = "connection_to_url_check"

"""
SONIC
"""

SONiC_CNTRLPLANE_ACL_BASIC_CONFIG_TEST = "SONiC_ACL_BASICCONFIG"
SONiC_CNTRLPLANE_ACL_PRESENT_TEST = "SONiC_ACL_PRESENT_TEST"
SONiC_CNTRLPLANE_ACL_CONFIGURE_STEP = "SONiC_ACL_CONFIGURED"
STAGE_IMAGE_ROUTE = "wan/8201/{file_name} -o /tmp/{file_name}"
SONIC_ACL_CNTRLPLANE = 'sonic_acl_cntrlplane.json'
ACL_RULE = "show acl rule"
ACL_RULE_SPECIFIC = "show acl rule {TableName}"
ACL_TABLE = "show acl table"
ACL_TABLE_SPECIFIC = "show acl table {TableName}"
SONiC_TOPOLOGY_REQUIREMENT_CHECK = 'sonic_topology_requirement_check'
# add ibr when ibr links are ready - depishe
SONiC_INTEROP_TOPOLOGY_REQUIREMENTS = {"OneWANRouter": {"cisco": ["rwa", "owr"]}}


"""
Generic
"""

NON_STARLAB_DEVICE = 'NonStarlabDevice'
DEVICE_NOT_IN_NGS = 'DeviceNotInNGS'

INT_STATUS_STR_CRITERIA = {
    "juniper": "physical link is up",
    "cisco": "line protocol is up",
    "arista": "line protocol is up"
}

INT_STATUS_STR_ADMIN_UP_LINK_DOWN = {
    "juniper": "enabled, physical link is down",
    "cisco": "up, line protocol is down",
    "arista": "up, line protocol is down"
}

# STEP Names

INTEROP_STARLAB_DEVICE_CHECK = 'interop_starlab_device_check'
LACP_INTEROP_TOPOLOGY_REQUIREMENTS_CHECK = 'lacp_interop_topology_requirements_check'
PORT_CHANNEL_STATUS_CHECK = 'port-channel_status_check'
PORT_CHANNEL_MEMBER_CHECK = 'port-channel_member_check'
PORT_CHANNEL_PEER_CHECK = 'port-channel_peer_check'
GET_INTERFACE_TO_SHUTDOWN = 'get_interface_to_shutdown'
SHUTDOWN_INTERFACE = 'shutdown_interface'
COMPARE_LOG = 'compare log between kusto and device'
SNMPTRAP_TRIGGER = 'check if snmptrap is triggered or not'
SNMPTRAP_KUSTO_CHECK = 'snmptrap check in kusto'

START_TRAFFIC = "StartTraffic"
LACP_REMOVE_LINK_LOSS = 0.3
LACP_ADD_LINK_LOSS = 0.2
VERIFY_PCK_LOSS_INC = 'VerifyPacketLossIncrease'
SHUT_DOWN_PORT = "ShutDownPort"
LACP_REMOVE_LINK = "LACPRemoveLink"
LACP_ADD_LINK = "LACPAddLink"

IXIA_CONNECTIONS = {"rwa02.str01": dict(Router_Port="et-2/0/28", IXIA_Port="7-2",
                                        Router_IPV4="133.0.0.1", IXIA_IPV4="133.0.0.0",
                                        Router_IPV6="2010::133:0:0:1", IXIA_IPV6="2010::133:0:0:0")
                    }

LAB_RR_DETAILS = {
    "rwa02.str01": dict(RR1_hostname="str-24irr-1a", RR1_IPV4="100.3.151.51", RR1_IPV6="2a01:111:e210:b::51")}
BGP_SESSION_STATUS_CHECK = 'bgp_session_status_check'
BGP_AGG_GENERATION_CHECK = 'bgp_agg_generation_check'
BGP_AGG_ADVERTISEMENT_CHECK = 'bgp_agg_advertisement_check'
BGP_AGGREGATES = ["133.4.0.0/14", "2011::/48"]
BGP_ROUTE_AGGREGATION_TEST_NAME = "BGPRouteAggregationTest"

BGP_AGGREGATE_TOPOLOGY_REQUIREMENTS = {"RegionalWANAggregator": {"juniper": ["ibr", "sw"]}}

DEACTIVATE_PROTOCOL_RSVP = 'deactivate_protocol_rsvp'
DEACTIVATE_BGP_WITH_SER = 'deactivate_bgp_with_ser'
VERIFY_SR_FORWARDING_NH_IP = 'verify_sr_forwarding_nh_ip'
VERIFY_BGP_DESTINATION_SR_LABEL = 'verify_bgp_destination_sr_label'

SR_INTEROP_TOPOLOGY_REQUIREMENTS = {"RegionalWANAggregator": {"juniper": ["ibr"]},
                                    "InternetCoreRouter": {"juniper": ["ibr"]}
                                    }
SR_INTEROP_ROUTER_PARAMETERS = {"rwa02.str01": {"RemoteRouter": "rwa01.str01", "RemoteBGPIPv4Prefix": "131.1.0.0/16",
                                                "RemoteLoopbackIPv4": "100.3.151.40", "NodeSIDIPv4": "16040"},
                                "icr01.str01": {"RemoteRouter": "rwa01.str01", "RemoteBGPIPv4Prefix": "131.1.0.0/16",
                                                "RemoteLoopbackIPv4": "100.3.151.40", "NodeSIDIPv4": "16040"}
                                }
