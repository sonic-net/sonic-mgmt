import re
import socket
import ipaddress
import uuid
import pytest

from dash_api.appliance_pb2 import Appliance
from dash_api.vnet_pb2 import Vnet
from dash_api.eni_pb2 import Eni, State
from dash_api.qos_pb2 import Qos
from dash_api.route_pb2 import Route
from dash_api.route_rule_pb2 import RouteRule
from dash_api.vnet_mapping_pb2 import VnetMapping
from dash_api.route_type_pb2 import RoutingType, ActionType, RouteType, RouteTypeItem


ENABLE_PROTO = True


def appliance_from_json(json_obj):
    pb = Appliance()
    pb.sip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["sip"])))
    pb.vm_vni = int(json_obj["vm_vni"])
    return pb


def vnet_from_json(json_obj):
    pb = Vnet()
    pb.vni = int(json_obj["vni"])
    pb.guid.value = bytes.fromhex(uuid.UUID(json_obj["guid"]).hex)
    return pb


def vnet_mapping_from_json(json_obj):
    pb = VnetMapping()
    pb.action_type = RoutingType.ROUTING_TYPE_VNET_ENCAP
    pb.underlay_ip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["underlay_ip"])))
    pb.mac_address = bytes.fromhex(json_obj["mac_address"].replace(":", ""))
    pb.use_dst_vni = json_obj["use_dst_vni"] == "true"
    return pb


def qos_from_json(json_obj):
    pb = Qos()
    pb.qos_id = json_obj["qos_id"]
    pb.bw = int(json_obj["bw"])
    pb.cps = int(json_obj["cps"])
    pb.flows = int(json_obj["flows"])
    return pb


def eni_from_json(json_obj):
    pb = Eni()
    pb.eni_id = json_obj["eni_id"]
    pb.mac_address = bytes.fromhex(json_obj["mac_address"].replace(":", ""))
    pb.underlay_ip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["underlay_ip"])))
    pb.admin_state = State.STATE_ENABLED if json_obj["admin_state"] == "enabled" else State.STATE_DISABLED
    pb.vnet = json_obj["vnet"]
    pb.qos = json_obj["qos"]
    return pb


def route_from_json(json_obj):
    pb = Route()
    if json_obj["action_type"] == "vnet":
        pb.action_type = RoutingType.ROUTING_TYPE_VNET
        pb.vnet = json_obj["vnet"]
    elif json_obj["action_type"] == "vnet_direct":
        pb.action_type = RoutingType.ROUTING_TYPE_VNET_DIRECT
        pb.vnet_direct.vnet = json_obj["vnet"]
        pb.vnet_direct.overlay_ip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["overlay_ip"])))
    elif json_obj["action_type"] == "direct":
        pb.action_type = RoutingType.ROUTING_TYPE_DIRECT
    else:
        pytest.fail("Unknown action type %s" % json_obj["action_type"])
    return pb


def route_rule_from_json(json_obj):
    pb = RouteRule()
    pb.action_type = RoutingType.ROUTING_TYPE_VNET_ENCAP
    pb.priority = int(json_obj["priority"])
    pb.pa_validation = json_obj["pa_validation"] == "true"
    pb.vnet = json_obj["vnet"]
    return pb


def routing_type_from_json(json_obj):
    pb = RouteType()
    pbi = RouteTypeItem()
    pbi.action_name = json_obj["name"]
    pbi.action_type = ActionType.ACTION_TYPE_MAPROUTING
    pb.items.append(pbi)
    return pb


handlers_map = {
    "APPLIANCE": appliance_from_json,
    "VNET": vnet_from_json,
    "VNET_MAPPING": vnet_mapping_from_json,
    "QOS": qos_from_json,
    "ENI": eni_from_json,
    "ROUTE": route_from_json,
    "ROUTE_RULE": route_rule_from_json,
    "ROUTING_TYPE": routing_type_from_json,
}


def json_to_proto(key, json_obj):
    table_name = re.search(r"DASH_(\w+)_TABLE", key).group(1)
    if table_name in handlers_map:
        pb = handlers_map[table_name](json_obj)
    else:
        pytest.fail("Unknown table %s" % table_name)
    return pb.SerializeToString()
