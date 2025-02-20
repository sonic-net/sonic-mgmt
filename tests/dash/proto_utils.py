import base64
import ipaddress
import re
import socket
import ipaddress
import uuid
import base64

from ipaddress import ip_address as IP
import importlib

import pytest
from dash_api.acl_group_pb2 import AclGroup
from dash_api.acl_in_pb2 import AclIn
from dash_api.acl_out_pb2 import AclOut
from dash_api.acl_rule_pb2 import AclRule, Action
from dash_api.appliance_pb2 import Appliance
from dash_api.eni_pb2 import Eni, State
from dash_api.eni_route_pb2 import EniRoute
from dash_api.prefix_tag_pb2 import PrefixTag
from dash_api.qos_pb2 import Qos
from dash_api.route_group_pb2 import RouteGroup
from dash_api.route_pb2 import Route
from dash_api.route_rule_pb2 import RouteRule
from dash_api.route_type_pb2 import RoutingType, ActionType, RouteType, RouteTypeItem, EncapType
from dash_api.types_pb2 import IpVersion, Range, ValueOrRange, IpPrefix, IpAddress
from dash_api.vnet_mapping_pb2 import VnetMapping
from dash_api.vnet_pb2 import Vnet
from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.json_format import ParseDict

ENABLE_PROTO = True

PB_INT_TYPES = set([
    FieldDescriptor.TYPE_INT32,
    FieldDescriptor.TYPE_INT64,
    FieldDescriptor.TYPE_UINT32,
    FieldDescriptor.TYPE_UINT64,
    FieldDescriptor.TYPE_FIXED64,
    FieldDescriptor.TYPE_FIXED32,
    FieldDescriptor.TYPE_SFIXED32,
    FieldDescriptor.TYPE_SFIXED64,
    FieldDescriptor.TYPE_SINT32,
    FieldDescriptor.TYPE_SINT64
])

PB_CLASS_MAP = {
    "APPLIANCE": Appliance,
    "VNET": Vnet,
    "ENI": Eni,
    "VNET_MAPPING": VnetMapping,
    "ROUTE": Route,
    "ROUTING_TYPE": RouteType,
    "ROUTE_GROUP": RouteGroup,
    "ENI_ROUTE": EniRoute,
}

def get_enum_type_from_str(enum_type_str, enum_name_str):

    # 4_to_6 uses small cap so cannot use dynamic naming
    if enum_name_str == "4_to_6":
        return ActionType.ACTION_TYPE_4_to_6

    my_enum_type_parts = re.findall(r'[A-Z][^A-Z]*', enum_type_str)
    my_enum_type_concatenated = '_'.join(my_enum_type_parts)
    enum_name = f"{my_enum_type_concatenated.upper()}_{enum_name_str.upper()}"
    a = globals()[enum_type_str]
    if a is not None:
        """Returns the value for the given enum name and raisees ValueError if not found."""
        return a.Value(enum_name)
    else:
        raise Exception(f"Cannot find enum type {enum_type_str}")

'''
message RouteTypeItem {
    string action_name = 1;
    route_type.ActionType action_type = 2;
    // Optional
    // encap type depends on the action_type - {vxlan, nvgre}
    optional route_type.EncapType encap_type = 3;
    // Optional
    // vni value to be used as the key for encapsulation. Applicable if encap_type is specified.
    optional uint32 vni = 4;
}
message RouteType {
    repeated RouteTypeItem items = 1;
}'''
def routing_type_from_json(json_obj):
    pb = RouteType()
    if isinstance(json_obj, list):
        for item in json_obj:
            pbi = RouteTypeItem()
            pbi.action_name = item["action_name"]
            pbi.action_type = get_enum_type_from_str('ActionType', item.get("action_type"))
            if item.get("encap_type") is not None:
                pbi.encap_type = get_enum_type_from_str('EncapType', item.get("encap_type"))
            if item.get("vni") is not None:
                pbi.vni = int(item["vni"])
            pb.items.append(pbi)
    else:
        pbi = RouteTypeItem()
        pbi.action_name = json_obj["action_name"]
        pbi.action_type = get_enum_type_from_str('ActionType', json_obj.get("action_type"))
        if json_obj.get("encap_type") is not None:
            pbi.encap_type = get_enum_type_from_str('EncapType', json_obj.get("encap_type"))
        if json_obj.get("vni") is not None:
            pbi.vni = int(json_obj["vni"])
        pb.items.append(pbi)
    return pb

def get_message_from_table_name(table_name):
    table_name_lis = table_name.lower().split("_")
    table_name_lis2 = [item.capitalize() for item in table_name_lis]
    message_name = ''.join(table_name_lis2)
    module_name = f'dash_api.{table_name.lower()}_pb2'

    # Import the module dynamically
    module = importlib.import_module(module_name)

    # Get the class object
    message_class = getattr(module, message_name)

    return message_class()

def parse_ip_address(ip_str):
    ip_addr = IP(ip_str)
    if ip_addr.version == 4:
        encoded_val = socket.htonl(int(ip_addr))
    else:
        encoded_val = base64.b64encode(ip_addr.packed)

    return {f"ipv{ip_addr.version}": encoded_val}

def prefix_to_ipv4(prefix_length):
    mask = 2**32 - 2**(32-int(prefix_length))
    s = str(hex(mask))
    s = s[2:]
    hex_groups = [s[i:i+2] for i in range(0, len(s), 2)]
    ipv4_address_str = '.'.join(hex_groups)
    return ipv4_address_str

def prefix_to_ipv6(prefix_length):
    mask = 2**128 - 2**(128-int(prefix_length))
    s = str(hex(mask))
    s = s[2:]
    hex_groups = [s[i:i+4] for i in range(0, len(s), 4)]
    ipv6_address_str = ':'.join(hex_groups)
    return ipv6_address_str


def parse_ip_prefix(ip_prefix_str):
    ip_addr_str, mask = ip_prefix_str.split("/")
    if mask.isdigit():
        ip_addr = IP(ip_addr_str)
        if ip_addr.version == 4:
            mask_str = prefix_to_ipv4(mask)
        else:
            mask_str = prefix_to_ipv6(mask)
    else:
        mask_str = mask
    return {"ip": parse_ip_address(ip_addr_str), "mask": parse_ip_address(mask_str)}


def parse_byte_field(orig_val):
    return base64.b64encode(bytes.fromhex(orig_val.replace(":", "")))


def parse_guid(guid_str):
    return {"value": parse_byte_field(uuid.UUID(guid_str).hex)}


def json_to_proto(key: str, proto_dict: dict):
    """
    Custom parser for DASH configs to allow writing configs
    in a more human-readable format
    """
    table_name = re.search(r"DASH_(\w+)_TABLE", key).group(1)
    if table_name == "ROUTING_TYPE":
        pb = routing_type_from_json(proto_dict)
        return pb.SerializeToString()

    message = get_message_from_table_name(table_name)
    field_map = message.DESCRIPTOR.fields_by_name
    new_dict = {}
    for key, value in proto_dict.items():
        if field_map[key].type == field_map[key].TYPE_MESSAGE:

            if field_map[key].message_type.name == "IpAddress":
                new_dict[key] = parse_ip_address(value)
            elif field_map[key].message_type.name == "IpPrefix":
                new_dict[key] = parse_ip_prefix(value)
            elif field_map[key].message_type.name == "Guid":
                new_dict[key] = parse_guid(value)

        elif field_map[key].type == field_map[key].TYPE_ENUM:
            new_dict[key] = get_enum_type_from_str(field_map[key].enum_type.name, value)
        elif field_map[key].type == field_map[key].TYPE_BOOL:
            new_dict[key] = value == 'true'

        elif field_map[key].type == field_map[key].TYPE_BYTES:
            new_dict[key] = parse_byte_field(value)

        elif field_map[key].type in PB_INT_TYPES:
            new_dict[key] = int(value)

        if key not in new_dict:
            new_dict[key] = value

    pb =  ParseDict(new_dict, message)
    return pb.SerializeToString()


def parse_dash_proto(key: str, proto_dict: dict):
    """
    Custom parser for DASH configs to allow writing configs
    in a more human-readable format
    """
    table_name = re.search(r"DASH_(\w+)_TABLE", key).group(1)
    message = PB_CLASS_MAP[table_name]()
    field_map = message.DESCRIPTOR.fields_by_name
    new_dict = {}
    for key, value in proto_dict.items():
        if field_map[key].type == field_map[key].TYPE_MESSAGE:

            if field_map[key].message_type.name == "IpAddress":
                new_dict[key] = parse_ip_address(value)
            elif field_map[key].message_type.name == "IpPrefix":
                new_dict[key] = parse_ip_prefix(value)
            elif field_map[key].message_type.name == "Guid":
                new_dict[key] = parse_guid(value)

        elif field_map[key].type == field_map[key].TYPE_BYTES:
            new_dict[key] = parse_byte_field(value)

        elif field_map[key].type in PB_INT_TYPES:
            new_dict[key] = int(value)

        if key not in new_dict:
            new_dict[key] = value

    return ParseDict(new_dict, message)
