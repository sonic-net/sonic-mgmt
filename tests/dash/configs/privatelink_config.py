from dash_api.eni_pb2 import State, EniMode
from dash_api.route_type_pb2 import ActionType, EncapType, RoutingType
from dash_api.types_pb2 import IpVersion

VNET = "vnet"
VNET_ENCAP = "vnet_encap"
VNET_DIRECT = "vnet_direct"
PRIVATELINK = "privatelink"
DECAP = "decap"

APPLIANCE_VIP = "10.1.0.5"
VM1_PA = "25.1.1.1"  # VM host physical address
VM1_CA = "10.0.0.11"  # VM customer address
VM_CA_SUBNET = "10.0.0.0/16"
PE_PA = "101.1.2.3"  # private endpoint physical address
PE_CA = "10.2.0.100"  # private endpoint customer address
PE_CA_SUBNET = "10.2.0.0/16"
PL_ENCODING_IP = "::d107:64:ff71:0:0"
PL_ENCODING_MASK = "::ffff:ffff:ffff:0:0"
PL_OVERLAY_SIP = "fd41:108:20:abc:abc::0"
PL_OVERLAY_SIP_MASK = "ffff:ffff:ffff:ffff:ffff:ffff::"
PL_OVERLAY_DIP = "2603:10e1:100:2::3401:203"
PL_OVERLAY_DIP_MASK = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

APPLIANCE_ID = "100"
LOCAL_REGION_ID = "100"
VM_VNI = "4321"
ENCAP_VNI = 100
VNET1 = "Vnet1"
VNET1_VNI = "2001"
VNET1_GUID = "559c6ce8-26ab-4193-b946-ccc6e8f930b2"
VM_MAC = "44:E3:9F:EF:C4:6E"
ENI_MAC = "F4:93:9F:EF:C4:7E"
ENI_MAC_STRING = ENI_MAC.replace(":", "")
# REMOTE MAC is corresponding to PE MAC
REMOTE_MAC = "43:BE:65:25:FA:67"
REMOTE_MAC_STRING = REMOTE_MAC.replace(":", "")
ENI_ID = "497f23d7-f0ac-4c99-a98f-59b470e8c7bd"
ROUTE_GROUP1 = "RouteGroup1"
ROUTE_GROUP2 = "RouteGroup2"
ROUTE_GROUP1_GUID = "48af6ce8-26cc-4293-bfa6-0126e8fcdeb2"
ROUTE_GROUP2_GUID = "58cf62e0-22cc-4693-baa6-012358fcdec9"
OUTBOUND_DIR_LOOKUP = "src_mac"
OUTBOUND_DIR_LOOKUP_FLOATING_NIC = "dst_mac"
METER_POLICY_V4 = "MeterPolicyV4"
METER_RULE_V4_PREFIX1 = "48.10.5.0/24"
METER_RULE_V4_PREFIX2 = "92.6.0.0/16"

APPLIANCE_CONFIG = {
    f"DASH_APPLIANCE_TABLE:{APPLIANCE_ID}": {
        "sip": APPLIANCE_VIP,
        "vm_vni": VM_VNI,
        "local_region_id": LOCAL_REGION_ID,
        "trusted_vnis": ENCAP_VNI
    }
}

APPLIANCE_CONFIG_FNIC = {
    f"DASH_APPLIANCE_TABLE:{APPLIANCE_ID}": {
        "sip": APPLIANCE_VIP,
        "vm_vni": VM_VNI,
        "local_region_id": LOCAL_REGION_ID,
        "outbound_direction_lookup": OUTBOUND_DIR_LOOKUP_FLOATING_NIC,
        "trusted_vnis": ENCAP_VNI
    }
}

VNET_CONFIG = {
    f"DASH_VNET_TABLE:{VNET1}": {
        "vni": VNET1_VNI,
        "guid": VNET1_GUID
    }
}

ENI_CONFIG = {
    f"DASH_ENI_TABLE:{ENI_ID}": {
        "vnet": VNET1,
        "underlay_ip": VM1_PA,
        "mac_address": ENI_MAC,
        "eni_id": ENI_ID,
        "admin_state": State.STATE_ENABLED,
        "pl_underlay_sip": APPLIANCE_VIP,
        "pl_sip_encoding": f"{PL_ENCODING_IP}/{PL_ENCODING_MASK}",
        "v4_meter_policy_id": METER_POLICY_V4,
    }
}

ENI_CONFIG_FNIC = {
    f"DASH_ENI_TABLE:{ENI_ID}": {
        "vnet": VNET1,
        "underlay_ip": VM1_PA,
        "mac_address": ENI_MAC,
        "eni_id": ENI_ID,
        "admin_state": State.STATE_ENABLED,
        "pl_underlay_sip": APPLIANCE_VIP,
        "pl_sip_encoding": f"{PL_ENCODING_IP}/{PL_ENCODING_MASK}",
        "v4_meter_policy_id": METER_POLICY_V4,
        "eni_mode": EniMode.MODE_FNIC,
        "trusted_vnis": ENCAP_VNI
    }
}

PE_VNET_MAPPING_CONFIG = {
    f"DASH_VNET_MAPPING_TABLE:{VNET1}:{PE_CA}": {
        "routing_type": RoutingType.ROUTING_TYPE_PRIVATELINK,
        "underlay_ip": PE_PA,
        "overlay_sip_prefix": f"{PL_OVERLAY_SIP}/{PL_OVERLAY_SIP_MASK}",
        "overlay_dip_prefix": f"{PL_OVERLAY_DIP}/{PL_OVERLAY_DIP_MASK}",
        "metering_class_or": "1586",
    }
}

PE_VNET_MAPPING_CONFIG_FNIC = {
    f"DASH_VNET_MAPPING_TABLE:{VNET1}:{PE_CA}": {
        "routing_type": RoutingType.ROUTING_TYPE_PRIVATELINK,
        "underlay_ip": PE_PA,
        "mac_address": REMOTE_MAC,
        "overlay_sip_prefix": f"{PL_OVERLAY_SIP}/{PL_OVERLAY_SIP_MASK}",
        "overlay_dip_prefix": f"{PL_OVERLAY_DIP}/{PL_OVERLAY_DIP_MASK}",
        "metering_class_or": "1586",
    }
}

VM1_VNET_MAPPING_CONFIG = {
    f"DASH_VNET_MAPPING_TABLE:{VNET1}:{VM1_CA}": {
        "routing_type": RoutingType.ROUTING_TYPE_VNET,
        "underlay_ip": VM1_PA,
        "metering_class_or": "2",
    }
}

VM1_VNET_MAPPING_CONFIG_FNIC = {
    f"DASH_VNET_MAPPING_TABLE:{VNET1}:{VM1_CA}": {
        "routing_type": RoutingType.ROUTING_TYPE_VNET,
        "underlay_ip": VM1_PA,
        "mac_address": VM_MAC,
        "metering_class_or": "2",
    }
}

PE_SUBNET_ROUTE_CONFIG = {
    f"DASH_ROUTE_TABLE:{ROUTE_GROUP1}:{PE_CA_SUBNET}": {
        "routing_type": RoutingType.ROUTING_TYPE_VNET,
        "vnet": VNET1,
        "metering_class_or": "2048",
        "metering_class_and": "4095",
    }
}

VM_SUBNET_ROUTE_CONFIG = {
    f"DASH_ROUTE_TABLE:{ROUTE_GROUP1}:{VM_CA_SUBNET}": {
        "routing_type": RoutingType.ROUTING_TYPE_VNET,
        "vnet": VNET1,
        "metering_class_or": "2048",
        "metering_class_and": "4095",
    }
}

ROUTING_TYPE_VNET_CONFIG = {
    f"DASH_ROUTING_TYPE_TABLE:{VNET}": {
        "items": [
            {
                "action_name": "action1",
                "action_type": ActionType.ACTION_TYPE_STATICENCAP,
                "encap_type": EncapType.ENCAP_TYPE_VXLAN,
            },
        ]
    }
}

ROUTING_TYPE_PL_CONFIG = {
    f"DASH_ROUTING_TYPE_TABLE:{PRIVATELINK}": {
        "items": [
            {
                "action_name": "action1",
                "action_type": ActionType.ACTION_TYPE_4_to_6
            },
            {
                "action_name": "action2",
                "action_type": ActionType.ACTION_TYPE_STATICENCAP,
                "encap_type": EncapType.ENCAP_TYPE_NVGRE,
                "vni": ENCAP_VNI
            }
        ]
    }
}

ROUTE_GROUP1_CONFIG = {
    f"DASH_ROUTE_GROUP_TABLE:{ROUTE_GROUP1}": {
        "guid": ROUTE_GROUP1_GUID,
        "version": "rg_version"
    }
}

ENI_ROUTE_GROUP1_CONFIG = {
    f"DASH_ENI_ROUTE_TABLE:{ENI_ID}": {
        "group_id": ROUTE_GROUP1
    }
}

METER_POLICY_V4_CONFIG = {
    f"DASH_METER_POLICY_TABLE:{METER_POLICY_V4}": {
        "ip_version": IpVersion.IP_VERSION_IPV4
    }
}

METER_RULE1_V4_CONFIG = {
    f"DASH_METER_RULE_TABLE:{METER_POLICY_V4}:1": {
        "priority": "10",
        "ip_prefix": f"{METER_RULE_V4_PREFIX1}",
        "metering_class": 1,
    }
}

METER_RULE2_V4_CONFIG = {
    f"DASH_METER_RULE_TABLE:{METER_POLICY_V4}:2": {
        "priority": "10",
        "ip_prefix": f"{METER_RULE_V4_PREFIX2}",
        "metering_class": 2,
    }
}
