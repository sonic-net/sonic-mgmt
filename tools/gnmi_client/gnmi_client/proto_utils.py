import re
import socket
import uuid
import base64

from ipaddress import ip_address as IP
import importlib

from dash_api import eni_pb2 as _eni_pb2
from dash_api import route_type_pb2 as _route_type_pb2
from dash_api import types_pb2 as _types_pb2

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.json_format import ParseDict

ENABLE_PROTO = True

_ENUM_MODULES = [_route_type_pb2, _types_pb2, _eni_pb2]


def _get_enum_class(enum_type_str):
    for mod in _ENUM_MODULES:
        cls = getattr(mod, enum_type_str, None)
        if cls is not None:
            return cls
    return None


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


def get_enum_type_from_str(enum_type_str, enum_name_str):

    my_enum_type_parts = re.findall(r'[A-Z][^A-Z]*', enum_type_str)
    my_enum_type_concatenated = '_'.join(my_enum_type_parts)
    enum_name = f"{my_enum_type_concatenated.upper()}_{enum_name_str.upper()}"
    a = _get_enum_class(enum_type_str)
    if a is None:
        raise Exception(f"Cannot find enum type {enum_type_str}")
    # Try exact match first, then fall back to case-insensitive lookup
    # to handle cases like ACTION_TYPE_4_to_6 where the proto value
    # uses mixed case.
    try:
        return a.Value(enum_name)
    except ValueError:
        for name in a.DESCRIPTOR.values_by_name:
            if name.upper() == enum_name:
                return a.Value(name)
        raise Exception(f"Cannot find enum value {enum_name} in {enum_type_str}")


# Mapping of table inner names to (module_name, class_name) for tables
# that don't follow the standard naming convention.
_TABLE_NAME_OVERRIDES = {
    "ROUTING_TYPE": ("route_type", "RouteType"),
}


def _normalize_table_name(inner):
    """Return (module_base, class_name) for a table inner name.

    Most tables follow the convention:
      module = dash_api.{inner.lower()}_pb2
      class  = CamelCase(inner)

    Tables with non-standard naming are handled via _TABLE_NAME_OVERRIDES.
    """
    if inner in _TABLE_NAME_OVERRIDES:
        return _TABLE_NAME_OVERRIDES[inner]
    table_name_lis = inner.lower().split("_")
    table_name_lis2 = [item.capitalize() for item in table_name_lis]
    return (inner.lower(), ''.join(table_name_lis2))


def get_message_from_table_name(tbl_name):
    # Extract the inner name from a full SONiC table name like
    # "DASH_APPLIANCE_TABLE" -> "APPLIANCE". If the input doesn't match,
    # treat it as the inner name directly.
    m = re.search(r"DASH_(\w+)_TABLE", tbl_name)
    inner = m.group(1) if m else tbl_name

    module_base, message_name = _normalize_table_name(inner)
    module_name = f'dash_api.{module_base}_pb2'

    # Validate module_base contains only safe characters (alphanumeric and underscore)
    if not re.fullmatch(r'[a-z0-9_]+', module_base):
        raise ValueError(f"Invalid table name: {tbl_name}")

    # Import the module dynamically (constrained to dash_api.*_pb2 namespace)
    module = importlib.import_module(module_name)  # nosemgrep: non-literal-import

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
    s = str(int(mask))
    s = s[2:]
    hex_groups = [s[i:i+2] for i in range(0, len(s), 2)]
    ipv4_address_str = '.'.join(hex_groups)
    return ipv4_address_str


def prefix_to_ipv6(prefix_length):
    mask = 2**128 - 2**(128-int(prefix_length))
    s = str(int(mask))
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


def parse_range(range_str):
    parts = range_str.split(",")
    num_parts = len(parts)
    if num_parts != 2:
        raise ValueError("Input string must contain exactly two numbers separated by a comma.")
    try:
        int(parts[0])
        int(parts[1])
    except ValueError:
        raise ValueError("Both parts of the input string must be valid integers.")
    return {"min": parts[0], "max": parts[1]}


def parse_value_or_range(value_or_range):
    if isinstance(value_or_range, int):
        return {"value": value_or_range}
    else:
        parts = value_or_range.split(",")
        if len(parts) == 1:
            try:
                int(parts[0])
            except ValueError:
                raise ValueError("Input string must be a valid integer.")
            return {"value": parts[0]}
        elif len(parts) == 2:
            return parse_range(value_or_range)
        else:
            raise ValueError("Input string must contain either one or two numbers separated by a comma.")


def _convert_fields(proto_dict, field_map):
    """Convert a dict of human-readable field values to ParseDict-compatible format."""
    new_dict = {}
    for key, value in proto_dict.items():
        if field_map[key].type == field_map[key].TYPE_MESSAGE:
            if field_map[key].message_type.name == "IpAddress":
                new_dict[key] = parse_ip_address(value)
            elif field_map[key].message_type.name == "IpPrefix":
                new_dict[key] = parse_ip_prefix(value)
            elif field_map[key].message_type.name == "Guid":
                new_dict[key] = parse_guid(value)
            elif field_map[key].message_type.name == "Range":
                new_dict[key] = parse_range(value)
            elif field_map[key].message_type.name == "ValueOrRange":
                if field_map[key].label == FieldDescriptor.LABEL_REPEATED:
                    new_dict[key] = [parse_value_or_range(val) for val in value]
                else:
                    new_dict[key] = parse_value_or_range(value)
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
    return new_dict


def json_to_proto(key: str, proto_dict):
    """
    Custom parser for DASH configs to allow writing configs
    in a more human-readable format.
    Supports both dict and list inputs.
    """
    message = get_message_from_table_name(key)
    field_map = message.DESCRIPTOR.fields_by_name

    if isinstance(proto_dict, list):
        # Find the repeated message field to populate with list items
        repeated_field = None
        for fname, fdesc in field_map.items():
            if fdesc.label == FieldDescriptor.LABEL_REPEATED and fdesc.type == FieldDescriptor.TYPE_MESSAGE:
                repeated_field = fname
                break
        if repeated_field is None:
            raise ValueError(f"No repeated message field found in {key}")
        sub_field_map = field_map[repeated_field].message_type.fields_by_name
        converted_items = [_convert_fields(item, sub_field_map) for item in proto_dict]
        new_dict = {repeated_field: converted_items}
    else:
        new_dict = _convert_fields(proto_dict, field_map)

    pb = ParseDict(new_dict, message)
    return pb.SerializeToString()


def tbl_name_to_type(tbl_name):
    dash_name = re.search(r"DASH_(\w+)_TABLE", tbl_name).group(1)
    # Split the string by underscores
    words = dash_name.split('_')
    # Capitalize the first character of each word
    words = [word.capitalize() for word in words]
    return ''.join(words)


def from_pb(tbl_name, byte_array):
    obj = get_message_from_table_name(tbl_name)
    obj.ParseFromString(byte_array)
    return obj
