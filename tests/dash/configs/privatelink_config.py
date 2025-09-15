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
VM_VNI = 4321
ENCAP_VNI = 100
NSG_OUTBOUND_VNI = 100
VNET1 = "Vnet1"
VNET2 = "Vnet2"
VNET1_VNI = "2001"
VNET1_GUID = "559c6ce8-26ab-4193-b946-ccc6e8f930b2"
VNET2_GUID = "559c6ce8-26ab-4193-b946-ccc6e8f930b3"
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
OUTBOUND_DIR_LOOKUP = "dst_mac"
TUNNEL1 = "Tunnel1"
ENI_ID2 = "497f23d7-f0ac-4c99-a98f-59b470e8c7bd"
TUNNEL1_ENDPOINT_IP = "40.40.40.40"
TUNNEL2 = "Tunnel2"
TUNNEL1_ENDPOINT_IPS = [TUNNEL1_ENDPOINT_IP]
TUNNEL2_ENDPOINT_IPS = ["60.60.60.60", "70.70.70.70"]
TUNNEL3 = "Tunnel3"
TUNNEL3_ENDPOINT_IPS = ["80.80.80.80"]
TUNNEL4 = "Tunnel4"
TUNNEL4_ENDPOINT_IPS = ["90.90.90.90", "10.10.10.10"]
ENI_TRUSTED_VNI = "800"
METER_POLICY_V4 = "MeterPolicyV4"
METER_RULE_V4_PREFIX1 = "48.10.5.0/24"
METER_RULE_V4_PREFIX2 = "92.6.0.0/16"

APPLIANCE_CONFIG = {
    f"DASH_APPLIANCE_TABLE:{APPLIANCE_ID}": {
        "sip": APPLIANCE_VIP,
        "vm_vni": VM_VNI,
        "local_region_id": LOCAL_REGION_ID,
        "trusted_vnis": [ENCAP_VNI, NSG_OUTBOUND_VNI],
    }
}

APPLIANCE_FNIC_CONFIG = {
    f"DASH_APPLIANCE_TABLE:{APPLIANCE_ID}": {
        "sip": APPLIANCE_VIP,
        "vm_vni": VM_VNI,
        "outbound_direction_lookup": OUTBOUND_DIR_LOOKUP,
        "local_region_id": LOCAL_REGION_ID,
        "trusted_vnis": ENCAP_VNI
    }
}

VNET_CONFIG = {
    f"DASH_VNET_TABLE:{VNET1}": {
        "vni": VNET1_VNI,
        "guid": VNET1_GUID
    }
}

VNET2_CONFIG = {
    f"DASH_VNET_TABLE:{VNET2}": {
        "vni": VM_VNI,
        "guid": VNET2_GUID
    }
}

ENI_FNIC_CONFIG = {
    f"DASH_ENI_TABLE:{ENI_ID}": {
        "vnet": VNET1,
        "underlay_ip": VM1_PA,
        "mac_address": ENI_MAC,
        "eni_id": ENI_ID2,
        "admin_state": State.STATE_ENABLED,
        "pl_underlay_sip": APPLIANCE_VIP,
        "pl_sip_encoding": f"{PL_ENCODING_IP}/{PL_ENCODING_MASK}",
        "eni_mode": EniMode.MODE_FNIC,
        "trusted_vnis": ENI_TRUSTED_VNI,
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
        "trusted_vnis": VM_VNI
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

PE_PLNSG_SINGLE_ENDPOINT_VNET_MAPPING_CONFIG = {
    f"DASH_VNET_MAPPING_TABLE:{VNET1}:{PE_CA}": {
        "routing_type": RoutingType.ROUTING_TYPE_PRIVATELINK,
        "underlay_ip": PE_PA,
        "overlay_sip_prefix": f"{PL_OVERLAY_SIP}/{PL_OVERLAY_SIP_MASK}",
        "overlay_dip_prefix": f"{PL_OVERLAY_DIP}/{PL_OVERLAY_DIP_MASK}",
        "metering_class_or": "1586",
        "tunnel": TUNNEL3,
    }
}

PE_PLNSG_MULTI_ENDPOINT_VNET_MAPPING_CONFIG = {
    f"DASH_VNET_MAPPING_TABLE:{VNET1}:{PE_CA}": {
        "routing_type": RoutingType.ROUTING_TYPE_PRIVATELINK,
        "underlay_ip": PE_PA,
        "overlay_sip_prefix": f"{PL_OVERLAY_SIP}/{PL_OVERLAY_SIP_MASK}",
        "overlay_dip_prefix": f"{PL_OVERLAY_DIP}/{PL_OVERLAY_DIP_MASK}",
        "metering_class_or": "1586",
        "tunnel": TUNNEL4,
    }
}

TUNNEL1_CONFIG = {
    f"DASH_TUNNEL_TABLE:{TUNNEL1}": {
        "endpoints": TUNNEL1_ENDPOINT_IPS,
        "vni": ENCAP_VNI,
        "encap_type": EncapType.ENCAP_TYPE_VXLAN
    }
}

TUNNEL2_CONFIG = {
    f"DASH_TUNNEL_TABLE:{TUNNEL2}": {
        "endpoints": TUNNEL2_ENDPOINT_IPS,
        "encap_type": EncapType.ENCAP_TYPE_VXLAN,
        "vni": ENCAP_VNI,
    }
}

TUNNEL3_CONFIG = {
    f"DASH_TUNNEL_TABLE:{TUNNEL3}": {
        "endpoints": TUNNEL3_ENDPOINT_IPS,
        "vni": NSG_OUTBOUND_VNI,
        "encap_type": EncapType.ENCAP_TYPE_VXLAN,
    }
}

TUNNEL4_CONFIG = {
    f"DASH_TUNNEL_TABLE:{TUNNEL4}": {
        "endpoints": TUNNEL4_ENDPOINT_IPS,
        "vni": NSG_OUTBOUND_VNI,
        "encap_type": EncapType.ENCAP_TYPE_VXLAN,
    }
}

INBOUND_VNI_ROUTE_RULE_CONFIG = {
    f"DASH_ROUTE_RULE_TABLE:{ENI_ID}:{ENCAP_VNI}:{PE_PA}/32": {
        "action_type": ActionType.ACTION_TYPE_DECAP,
        "priority": 1
    }
}

# For floating NIC, outbound packet will pass through inbound pipeline first before going to the outbound pipeline
# Need this route rule entry to prevent the packet from being dropped in the inbound pipeline
TRUSTED_VNI_ROUTE_RULE_CONFIG = {
    f"DASH_ROUTE_RULE_TABLE:{ENI_ID}:{ENI_TRUSTED_VNI}:{VM1_PA}/32": {
        "action_type": ActionType.ACTION_TYPE_DECAP,
        "priority": 1
    }
}

VM_SUBNET_ROUTE_WITH_TUNNEL_MULTI_ENDPOINT = {
    f"DASH_ROUTE_TABLE:{ROUTE_GROUP1}:{VM_CA_SUBNET}": {
        "routing_type": RoutingType.ROUTING_TYPE_DIRECT,
        "tunnel": TUNNEL2
    }
}

VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT = {
    f"DASH_ROUTE_TABLE:{ROUTE_GROUP1}:{VM_CA_SUBNET}": {
        "routing_type": RoutingType.ROUTING_TYPE_DIRECT,
        "tunnel": TUNNEL1
    }
}

VM_VNI_ROUTE_RULE_CONFIG = {
    f"DASH_ROUTE_RULE_TABLE:{ENI_ID}:{VM_VNI}:{VM1_PA}/32": {
        "action_type": ActionType.ACTION_TYPE_DECAP,
        "priority": 1
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
