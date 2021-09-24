#! /usr/bin/env python

import json
import sys
import xml.etree.ElementTree as ET

from helpers import *
from common import *

from tempfile import mkstemp

ns_val = "Microsoft.Search.Autopilot.Evolution"
ns_i_val = "http://www.w3.org/2001/XMLSchema-instance"
ns_a_val = "http://schemas.datacontract.org/2004/07/Microsoft.Search.Autopilot.Evolution"

ns = "{" + ns_val + "}"
ns_i = "{" + ns_i_val + "}"
ns_a = "{" + ns_a_val + "}"


def usage(name):
    print("Usage: {} <i/p xml> [<T0 to strip>]".format(name))
    sys.exit(-1)


def get_tor_name(root):
    global tor_data

    tor_name = ""
    for bgp_router in root.iter(ns+"EndRouter"):
        name = bgp_router.text
        if name.endswith("T0"):
            tor_name = name
            break
    if not tor_name:
        for bgp_router in root.iter(ns+"StartRouter"):
            name = bgp_router.text
            if name.endswith("T0"):
                tor_name = name
                break
    if not tor_name:
        report_error("Failed to find a TOR name")
    tor_data["name"]["remote"] = name
    log_debug("found tor name: {}".format(name))
    return name


def find_sonic_ports():
    global tor_data, managed_files

    port_table = config_db_data_orig["PORT"]
    alias_map = {}
    for name, obj in port_table.items():
        alias = obj["alias"]
        alias_map[alias] = name

    lst_links = tor_data["links"]
    for link in lst_links:
        link["local"]["sonic_name"] = alias_map[link["local"]["alias"]]
        log_debug("link.local: alias={} sonic_name={}".format(
            link["local"]["alias"], link["local"]["sonic_name"]))

    return 0


def get_local_ports():
    global tor_data

    local_ports = set()
    local_sonic_ports = set()
    for link in tor_data["links"]:
        local_ports.add(link["local"]["alias"])
        local_sonic_ports.add(link["local"]["sonic_name"])

    return local_ports, local_sonic_ports


def get_tor_data(root):
    global tor_data
    tor_name = tor_data["name"]["remote"]
         
    for bgp in root.iter(ns+"BGPSession"):
        ip_start = ""
        ip_end = "" 
        holdtime = ""
        keepalive = ""
        found_start = False
        found_end = False
        for e in bgp: 
            if e.tag == ns+"StartPeer": 
                ip_start = e.text 
            elif e.tag == ns+"EndPeer": 
                ip_end = e.text 
            elif e.tag == ns+"StartRouter":
                if e.text == tor_name:
                    found_start = True
            elif e.tag == ns+"EndRouter":
                if e.text == tor_name:
                    found_end = True
            elif e.tag == ns+"HoldTime":
                holdtime = e.text
            elif e.tag == ns+"KeepAliveTime":
                keepalive = e.text
            
        if found_start:
            ip = tor_data["ip"] if ":" not in ip_start else tor_data["ipv6"]
            ip["remote"] = ip_start
            ip["local"] = ip_end

        if found_end:
            ip = tor_data["ip"] if ":" not in ip_end else tor_data["ipv6"]
            ip["remote"] = ip_end
            ip["local"] = ip_start

        if found_start or found_end:
            tor_data["bgp_info"]["holdtime"] = holdtime
            tor_data["bgp_info"]["keepalive"] = keepalive

        if (tor_data["ip"]["remote"]) and (tor_data["ipv6"]["remote"]):
            break

    log_debug("From BGPSession: ip: {}".format( str(tor_data["ip"])))
    log_debug("From BGPSession: ipv6: {}".format( str(tor_data["ipv6"])))

    for e_rtr in root.iter(ns_a+"BGPRouterDeclaration"):
        asn = ""
        hostname = ""
        for e in e_rtr:
            if e.tag.endswith("}ASN"):
                asn = e.text
            elif e.tag.endswith("}Hostname"):
                hostname = e.text
        if hostname == tor_name:
            tor_data["bgp_info"]["asn"] = asn
            break

    log_debug("asn = {}".format(str(tor_data["bgp_info"])))

    for dev_link in root.iter(ns+"DeviceLinkBase"):
        link = { "local": "", "remote": "" }
        port_start = ""
        port_end = "" 
        found_start = False
        found_end = False
        for e in dev_link: 
            if e.tag == ns+"ElementType": 
                if e.text != "DeviceInterfaceLink":
                    found_start = False
                    found_end = False
                    break
            elif e.tag == ns+"StartDevice":
                if e.text == tor_name:
                    found_start = True
            elif e.tag == ns+"EndDevice":
                if e.text == tor_name:
                    found_end = True
            if e.tag == ns+"StartPort": 
                port_start = e.text 
            elif e.tag == ns+"EndPort": 
                port_end = e.text 
        if found_start:
            link["remote"] = port_start
            link["local"] = { "alias": port_end }
        elif found_end:
            link["remote"] = port_end
            link["local"] = { "alias": port_start }

        if link["remote"]:
            if not tor_data["links"][0]["remote"]:
                tor_data["links"][0] = link
            else:
                tor_data["links"].append(link)

    log_debug("links: {}".format(str(tor_data["links"])))

    find_sonic_ports()

    local_ports, local_sonic_ports = get_local_ports()

    log_debug("local_ports:{}".format(str(local_ports)))
    log_debug("local_sonic_ports:{}".format(str(local_sonic_ports)))

    for pc in root.iter(ns+"PortChannel"):
        pc_name = ""
        ports = None

        for e in pc:
            if e.tag == ns+"Name":
                pc_name = e.text
            elif e.tag == ns+"AttachTo":
                ports = set(e.text.split(";"))

        if ((ports == local_ports) or (ports == local_sonic_ports)):
            tor_data["portChannel"] = pc_name
            break
    log_debug("portchannel={}".format(str(tor_data["portChannel"])))

    for e0 in root.iter(ns+"PngDec"):
        for e1 in e0:
            cnt = 0
            if e1.tag == ns+"Devices":
                for dev in e1:
                    hwsku = ""
                    hname = ""
                    mgmt_ip = ""
                    for e in dev:
                        if e.tag == ns+"Hostname":
                            hname = e.text
                        elif e.tag == ns+"ManagementAddress":
                            for e2 in e:
                                if e2.tag.endswith("}IPPrefix"):
                                    mgmt_ip = e2.text
                        elif e.tag == ns+"HwSku":
                            hwsku = e.text

                    if hname == tor_data["name"]["local"]:
                        tor_data["hwsku"]["local"] = hwsku
                        tor_data["mgmt_ip"]["local"] = mgmt_ip
                        cnt += 1
                    elif hname == tor_data["name"]["remote"]:
                        tor_data["hwsku"]["remote"] = hwsku
                        tor_data["mgmt_ip"]["remote"] = mgmt_ip
                        cnt += 1
                if cnt == 2:                     
                    break
    log_debug("hwsku={}".format(str(tor_data["hwsku"])))
    log_debug("mgmt_ip={}".format(str(tor_data["mgmt_ip"])))

    if (not tor_data["hwsku"]["local"]):
        report_error("Failed to find hwsku for local={}".
                format(tor_data["hwsku"]["local"]))


def remove_bgp_session(root):
    tor_name = tor_data["name"]["remote"]
    to_remove = []
    for bgp in root.iter(ns+"BGPSession"):
        for e in bgp:
            if e.tag == ns+"StartRouter":
                if e.text == tor_name:
                    to_remove.append(bgp)
                    break
            elif e.tag == ns+"EndRouter":
                if e.text == tor_name:
                    to_remove.append(bgp)
                    break
        if len(to_remove) == 2:
            break

    for peering_sessions in root.iter(ns+"PeeringSessions"):
        for bgp in to_remove:
            peering_sessions.remove(bgp)
            log_info("BGP session removed")


def remove_bgp_router(root):
    tor_name = tor_data["name"]["remote"]
    routers = None
    for e in root.iter(ns+"Routers"):
        routers = e
        break

    found = False
    for rtr in routers:
        for e in rtr:
            if e.tag == ns_a+"Hostname":
                if e.text == tor_name:
                    routers.remove(rtr)
                    found = True
                    log_info("removed BGP router {}".format(tor_name))
                    break
        if found:
            break



def remove_bgp_peer(root):
    host_name = tor_data["name"]["local"]
    to_remove = []
    router = None
    peers = None

    for e_rtr in root.iter(ns_a+"BGPRouterDeclaration"):
        for e in e_rtr:
            if e.tag == ns_a+"Hostname":
                if e.text == host_name:
                    router = e_rtr
            elif e.tag == ns_a+"Peers":
                peers = e
        if router is not None:
            break

    if router is None or peers is None:
        report_error("Failed to find BGPRouterDeclaration for {}".format(
            host_name))

    ip_lst = set()
    ip_lst.add(tor_data["ip"]["local"])
    ip_lst.add(tor_data["ip"]["remote"])
    ip_lst.add(tor_data["ipv6"]["local"])
    ip_lst.add(tor_data["ipv6"]["remote"])

    for peer in peers:
        for e in peer:
            if e.tag == ns+"Address":
                if e.text in ip_lst:
                    log_info("Peer remove: {}".format(e.text))
                    to_remove.append(peer)
    
    for peer in to_remove:
        peers.remove(peer)
        log_info("BGPPeer removed")

    
def remove_remote_device_dataplane_info(dpg):
    tor_name = tor_data["name"]["remote"]

    for info in dpg:
        found = False
        if info.tag == ns+"DeviceDataPlaneInfo":
            for e in info:
                if e.tag == ns+"Hostname":
                    if e.text == tor_name:
                        dpg.remove(info)
                        log_info("removed dataplane info for {}".format(tor_name))
                        found = True
                        break
            if found:
                break


def remove_port_channel(data_plane_info):
    pc_name_to_drop = tor_data["portChannel"]
    pc_list = None

    for e in data_plane_info:
        if e.tag == ns+"PortChannelInterfaces":
            pc_list = e
            break
    if pc_list is None:
        report_error("Unable to find porthannels")

    found = False
    for pc in pc_list:
        for e in pc:
            if e.tag == ns+"Name":
                if e.text == pc_name_to_drop:
                    pc_list.remove(pc)
                    log_info("removed PortChannel for {}".format(pc_name_to_drop))
                    found = True
                    break
        if found:
            break


def remove_IP_interfaces(data_plane_info):
    local_ports, _ = get_local_ports()
    pc_to_remove = tor_data["portChannel"]
    ip_list = None
    to_remove = set()

    for e in data_plane_info:
        if e.tag == ns+"IPInterfaces":
            ip_list = e
            break
    if ip_list is None:
        report_error("Unable to find IPInterfaces")

    for intf in ip_list:
        for e in intf:
            if e.tag == ns+"AttachTo":
                if e.text in local_ports:
                    to_remove.add(intf)
                elif e.text == pc_to_remove:
                    to_remove.add(intf)

    for intf in to_remove:
        ip_list.remove(intf)
        log_info("remove ip_intf")


def remove_ACL_interfaces(data_plane_info):
    local_ports, _ = get_local_ports()
    pc_to_remove = tor_data["portChannel"]
    acl_list = None

    for e in data_plane_info:
        if e.tag == ns+"AclInterfaces":
            acl_list = e
            break
    if acl_list is None:
        report_error("Unable to find AclInterfaces")

    data_acl = {}
    for acl in acl_list:
        for e in acl:
            if e.tag == ns+"Type":
                if e.text == "DataPlane":
                    data_acl = acl
                    break
        if data_acl is not None:
            break

    for e in data_acl:
        if e.tag == ns+"AttachTo":
            lst = set(e.text.split(';'))
            for p in local_ports:
                lst.discard(p)
            lst.discard(pc_to_remove)
            e.text = ";".join(lst)
            e.set('updated', 'yes')
            log_info("data acl updated")
            break


def remove_dataplane_entries(dpg):
    host_name = tor_data["name"]["local"]

    info_host = None
    for info in dpg:
        if info.tag == ns+"DeviceDataPlaneInfo":
            for e in info:
                if e.tag == ns+"Hostname":
                    if e.text == host_name:
                        info_host = info
                        break
        if info_host is not None:
            break

    if info is None:
        report_error("Unable to fnd DeviceDataPlaneInfo for local {}".
                format(host_name))

    remove_port_channel(info)
    remove_IP_interfaces(info)
    remove_ACL_interfaces(info)

    
def update_cpg(root):
    remove_bgp_session(root)
    remove_bgp_router(root)
    remove_bgp_peer(root)


def update_dpg(root):
    dpg = None
    for e in root:
        if e.tag == ns+"DpgDec":
            dpg = e
            break

    if dpg is None:
        report_error("Failed to get DpgDec")

    remove_remote_device_dataplane_info(dpg)
    remove_dataplane_entries(dpg)


def update_png(root):
    tor_name = tor_data["name"]["remote"]
    to_remove = []

    # Remove DeviceInterfaceLinks
    #
    lst_links = None
    for e in root.iter(ns+"DeviceInterfaceLinks"):
        lst_links = e
        break
    if lst_links is None:
        report_error("Failed to find DeviceInterfaceLinks")

    for link in lst_links:
        for e in link:
            if ((e.tag == ns+"StartDevice") or (e.tag == ns+"EndDevice")):
                if e.text == tor_name:
                    to_remove.append(link)
                    break
    
    for link in to_remove:
        lst_links.remove(link)
        log_info("DeviceInterfaceLink removed")

    # Remove device from Devices
    #
    lst_devices = None
    for e0 in root.iter(ns+"PngDec"):
        for e in e0:
            if e.tag == ns+"Devices":
                lst_devices = e
                break
        if lst_devices is not None:
            break

    found = False
    for device in lst_devices:
        for e in device:
            if e.tag == ns+"Hostname":
                if e.text == tor_name:
                    lst_devices.remove(device)
                    found = True
                    log_info("removed device from pngDec")
                    break
        if found:
            break


def write_out(tree, tmpdir):
    global managed_files

    _, fpath = mkstemp(prefix="minigraph_", suffix=".xml", dir=tmpdir)
    tree.write(fpath)
    managed_files["minigraph_wo_to"] = fpath


def main(tmpdir):
    global managed_files, tor_data

    ET.register_namespace('', ns_val)
    ET.register_namespace('i', ns_i_val)
    ET.register_namespace('a', ns_a_val)

    tree = ET.parse(managed_files["minigraph_file"])
    root = tree.getroot()

    if not tor_data["name"]["remote"]:
        get_tor_name(root)

    get_tor_data(root)
    log_info ("tor_data: {}".format(json.dumps(tor_data, indent=4, default=str)))

    update_cpg(root)

    update_dpg(root)

    update_png(root)

    write_out(tree, tmpdir)
    log_debug("managed_files={}".format(json.dumps(managed_files, indent=4)))

    return 0





