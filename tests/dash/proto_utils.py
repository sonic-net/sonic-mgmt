import base64
import re
import socket
import uuid
import importlib
from ipaddress import ip_address

from dash_api.appliance_pb2 import Appliance
from dash_api.eni_pb2 import Eni, State  # noqa: F401
from dash_api.eni_route_pb2 import EniRoute
from dash_api.route_group_pb2 import RouteGroup
from dash_api.route_pb2 import Route
from dash_api.route_type_pb2 import ActionType, RouteType, RouteTypeItem, EncapType, RoutingType  # noqa: F401
from dash_api.vnet_mapping_pb2 import VnetMapping
from dash_api.vnet_pb2 import Vnet
from dash_api.meter_policy_pb2 import MeterPolicy
from dash_api.meter_rule_pb2 import MeterRule
from dash_api.tunnel_pb2 import Tunnel
from dash_api.route_rule_pb2 import RouteRule
import dash_api.types_pb2 as types_pb2

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
    "METER_POLICY": MeterPolicy,
    "METER_RULE": MeterRule,
    "TUNNEL": Tunnel,
    "ROUTE_RULE": RouteRule
}

PB_TYPE_MAP = {
    "HA_SCOPE": types_pb2.HaScope,
    "HA_OWNER": types_pb2.HaOwner,
    "IP_VERSION": types_pb2.IpVersion,
    "IP_ADDRESS": types_pb2.IpAddress,
    "IP_PREFIX": types_pb2.IpPrefix,
    "VALUE_OR_RANGE": types_pb2.ValueOrRange,
    "RANGE": types_pb2.Range,
}


def parse_ip_address(ip_str):
    ip_addr = ip_address(ip_str)
    if ip_addr.version == 4:
        encoded_val = socket.htonl(int(ip_addr))
    else:
        encoded_val = base64.b64encode(ip_addr.packed)

    return {f"ipv{ip_addr.version}": encoded_val}


def parse_byte_field(orig_val):
    return base64.b64encode(bytes.fromhex(orig_val.replace(":", "")))


def parse_guid(guid_str):
    return {"value": parse_byte_field(uuid.UUID(guid_str).hex)}


def parse_value_or_range(orig):
    if isinstance(orig, list):
        if len(orig) == 1:
            val = int(orig[0])
            return {"value": val}
        elif len(orig) == 2:
            min = int(orig[0])
            max = int(orig[1])
            return {"range": {"min": min, "max": max}}
    else:
        val = int(orig)
        return {"value": val}


def parse_dash_proto(key: str, proto_dict: dict):
    """
    Custom parser for DASH configs to allow writing configs
    in a more human-readable format
    """
    table_name = re.search(r"DASH_(\w+)_TABLE", key).group(1)
    message = PB_CLASS_MAP[table_name]()
    field_map = message.DESCRIPTOR.fields_by_name

    if table_name == "ROUTING_TYPE":
        pb = routing_type_from_json(proto_dict)
        return pb

    new_dict = {}
    for key, value in proto_dict.items():
        if field_map[key].type == field_map[key].TYPE_MESSAGE:

            if field_map[key].message_type.name == "IpAddress":
                if field_map[key].label == FieldDescriptor.LABEL_REPEATED:
                    new_dict[key] = [parse_ip_address(val) for val in value]
                else:
                    new_dict[key] = parse_ip_address(value)
            elif field_map[key].message_type.name == "IpPrefix":
                new_dict[key] = parse_ip_prefix(value)
            elif field_map[key].message_type.name == "Guid":
                new_dict[key] = parse_guid(value)
            elif field_map[key].message_type.name == "ValueOrRange":
                new_dict[key] = parse_value_or_range(value)

        elif field_map[key].type == field_map[key].TYPE_BYTES:
            new_dict[key] = parse_byte_field(value)

        elif field_map[key].type == field_map[key].TYPE_ENUM:
            if isinstance(value, int):
                new_dict[key] = value
            else:
                new_dict[key] = get_enum_type_from_str(field_map[key].enum_type.name, value)

        elif field_map[key].type in PB_INT_TYPES:
            new_dict[key] = int(value)

        if key not in new_dict:
            new_dict[key] = value

    return ParseDict(new_dict, message)


def get_enum_type_from_str(enum_type_str, enum_name_str):
    # Special-case: enum value does not match standard naming
    if enum_name_str == "4_to_6":
        return ActionType.ACTION_TYPE_4_TO_6

    # Convert enum type name → ENUM_PREFIX
    # Example: HaScope → HA_SCOPE
    my_enum_type_parts = re.findall(r'[A-Z][^A-Z]*', enum_type_str)
    enum_prefix = '_'.join(my_enum_type_parts).upper()

    enum_class = PB_TYPE_MAP.get(enum_prefix)
    if not enum_class:
        raise Exception(f"Cannot find enum type {enum_prefix} in PB_TYPE_MAP")

    # Normalize enum value
    # Example: "dpu" → HA_SCOPE_DPU
    enum_value = enum_name_str.upper()
    if not enum_value.startswith(enum_prefix):
        enum_value = f"{enum_prefix}_{enum_value}"

    return enum_class.Value(enum_value)


def routing_type_from_json(json_obj):
    pb = RouteType()
    route_type_items = json_obj['items']
    for item in route_type_items:
        pbi = RouteTypeItem()
        pbi.action_name = item["action_name"]
        if isinstance(item.get("action_type"), int):
            pbi.action_type = item.get("action_type")
        else:
            pbi.action_type = get_enum_type_from_str('ActionType', item.get("action_type"))
        if item.get("encap_type") is not None:
            if isinstance(item.get("encap_type"), int):
                pbi.encap_type = item.get("encap_type")
            else:
                pbi.encap_type = get_enum_type_from_str('EncapType', item.get("encap_type"))
        if item.get("vni") is not None:
            pbi.vni = int(item["vni"])
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


def prefix_to_ipv4(prefix_length):
    if int(prefix_length) > 32:
        return ""
    mask = 2**32 - 2**(32-int(prefix_length))
    s = str(hex(mask))
    s = s[2:]
    hex_groups = [s[i:i+2] for i in range(0, len(s), 2)]
    decimal_groups = []
    for hex_string in hex_groups:
        decimal_groups.append(str(int(hex_string, 16)))
    ipv4_address_str = '.'.join(decimal_groups)
    return ipv4_address_str


def prefix_to_ipv6(prefix_length):
    if int(prefix_length) > 128:
        return ""
    mask = 2**128 - 2**(128-int(prefix_length))
    s = str(hex(mask))
    s = s[2:]
    hex_groups = [s[i:i+4] for i in range(0, len(s), 4)]
    ipv6_address_str = ':'.join(hex_groups)
    return ipv6_address_str


def parse_ip_prefix(ip_prefix_str):
    ip_addr_str, mask = ip_prefix_str.split("/")
    if mask.isdigit():
        ip_addr = ip_address(ip_addr_str)
        if ip_addr.version == 4:
            mask_str = prefix_to_ipv4(mask)
        else:
            mask_str = prefix_to_ipv6(mask)
    else:
        mask_str = mask
    return {"ip": parse_ip_address(ip_addr_str), "mask": parse_ip_address(mask_str)}


def json_to_proto(key: str, proto_dict: dict):
    """
    Custom parser for DASH configs to allow writing configs
    in a more human-readable format.
    Converts JSON → protobuf bytes.
    """

    table_name = re.search(r"DASH_(\w+)_TABLE", key).group(1)

    # Special handler for ROUTING_TYPE
    if table_name == "ROUTING_TYPE":
        pb = routing_type_from_json(proto_dict)
        return pb.SerializeToString()

    # Load the PB message type
    message = get_message_from_table_name(table_name)
    field_map = message.DESCRIPTOR.fields_by_name
    new_dict = {}

    for field_name, value in proto_dict.items():
        field = field_map[field_name]

        # ============================================================
        # MESSAGE FIELDS (IpAddress, IpPrefix, Guid, etc.)
        # ============================================================
        if field.type == field.TYPE_MESSAGE:

            # REPEATED message
            if field.label == field.LABEL_REPEATED:
                new_list = []
                for item in value:
                    if field.message_type.name == "IpAddress":
                        new_list.append(parse_ip_address(item))
                    elif field.message_type.name == "IpPrefix":
                        new_list.append(parse_ip_prefix(item))
                    elif field.message_type.name == "Guid":
                        new_list.append(parse_guid(item))
                    else:
                        new_list.append(item)
                new_dict[field_name] = new_list
                continue

            # SINGLE message field
            if field.message_type.name == "IpAddress":
                new_dict[field_name] = parse_ip_address(value)
            elif field.message_type.name == "IpPrefix":
                new_dict[field_name] = parse_ip_prefix(value)
            elif field.message_type.name == "Guid":
                new_dict[field_name] = parse_guid(value)
            else:
                new_dict[field_name] = value

            continue

        # ============================================================
        # ENUM FIELDS (HaScope, HaRole, HaOwner, etc.)
        # ============================================================
        elif field.type == field.TYPE_ENUM:
            enum_type = field.enum_type.name  # Example: "HaScope"

            # Convert CamelCase → HA_SCOPE
            parts = re.findall(r'[A-Z][a-z]*', enum_type)
            enum_prefix = '_'.join(parts).upper()  # HaScope → HA_SCOPE

            # Normalize user-supplied value (e.g. "dpu" or "HA_SCOPE_DPU")
            value_upper = value.upper()
            if value_upper.startswith(enum_prefix):
                enum_name = value_upper
            else:
                enum_name = f"{enum_prefix}_{value_upper}"

            # Lookup enum class from unified PB_TYPE_MAP
            enum_class = PB_TYPE_MAP.get(enum_prefix)
            if enum_class is None:
                raise KeyError(f"Enum type '{enum_type}' ({enum_prefix}) not found in PB_TYPE_MAP")

            # Convert string to enum integer
            new_dict[field_name] = enum_class.Value(enum_name)
            continue

        # ============================================================
        # BOOL
        # ============================================================
        if field.type == field.TYPE_BOOL:
            new_dict[field_name] = bool(value)
            continue

        # ============================================================
        # BYTES
        # ============================================================
        if field.type == field.TYPE_BYTES:
            new_dict[field_name] = parse_byte_field(value)
            continue

        # ============================================================
        # INT
        # ============================================================
        if field.type in PB_INT_TYPES:
            new_dict[field_name] = int(value)
            continue

        # ============================================================
        # STRING / DEFAULT
        # ============================================================
        new_dict[field_name] = value

    # Build protobuf
    pb = ParseDict(new_dict, message)
    return pb.SerializeToString()
