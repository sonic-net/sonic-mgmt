import json


def generate_intf_neigh(asichost, num_neigh, ip_version):
    interfaces = asichost.show_interface(command="status")["ansible_facts"][
        "int_status"
    ]
    up_interfaces = []
    for intf, values in list(interfaces.items()):
        if values["admin_state"] == "up" and values["oper_state"] == "up":
            up_interfaces.append(intf)
    if not up_interfaces:
        raise Exception("DUT does not have up interfaces")

    # Generate interfaces and neighbors
    intf_neighs = []
    str_intf_nexthop = {"ifname": "", "nexthop": ""}

    idx_neigh = 0
    for itfs_name in up_interfaces:
        if not itfs_name.startswith("PortChannel") and interfaces[itfs_name][
            "vlan"
        ].startswith("PortChannel"):
            continue
        if interfaces[itfs_name]["vlan"] == "trunk":
            continue
        if ip_version == 4:
            intf_neigh = {
                "interface": itfs_name,
                # change prefix ip starting with 3 to avoid overlap with any bgp ip
                "ip": "30.%d.0.1/24" % (idx_neigh + 1),
                "neighbor": "30.%d.0.2" % (idx_neigh + 1),
                "mac": "54:54:00:ad:48:%0.2x" % idx_neigh,
            }
        else:
            intf_neigh = {
                "interface": itfs_name,
                "ip": "%x::1/64" % (0x2000 + idx_neigh),
                "neighbor": "%x::2" % (0x2000 + idx_neigh),
                "mac": "54:54:00:ad:48:%0.2x" % idx_neigh,
            }

        intf_neighs.append(intf_neigh)
        if idx_neigh == 0:
            str_intf_nexthop["ifname"] += intf_neigh["interface"]
            str_intf_nexthop["nexthop"] += intf_neigh["neighbor"]
        else:
            str_intf_nexthop["ifname"] += "," + intf_neigh["interface"]
            str_intf_nexthop["nexthop"] += "," + intf_neigh["neighbor"]
        idx_neigh += 1
        if idx_neigh == num_neigh:
            break

    if not intf_neighs:
        raise Exception("DUT does not have interfaces available for test")

    return intf_neighs, str_intf_nexthop


def generate_route_file(duthost, prefixes, str_intf_nexthop, dir, op):
    route_data = []
    for prefix in prefixes:
        key = "ROUTE_TABLE:" + prefix
        route = {}
        route["ifname"] = str_intf_nexthop["ifname"]
        route["nexthop"] = str_intf_nexthop["nexthop"]
        route_command = {}
        route_command[key] = route
        route_command["OP"] = op
        route_data.append(route_command)

    # Copy json file to DUT
    duthost.copy(content=json.dumps(route_data, indent=4), dest=dir, verbose=False)


def prepare_dut(asichost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Set up interface
        asichost.config_ip_intf(intf_neigh["interface"], intf_neigh["ip"], "add")
        # Set up neighbor
        asichost.run_ip_neigh_cmd(
            "replace "
            + intf_neigh["neighbor"]
            + " lladdr "
            + intf_neigh["mac"]
            + " dev "
            + intf_neigh["interface"]
        )


def cleanup_dut(asichost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Delete neighbor
        asichost.run_ip_neigh_cmd(
            "del " + intf_neigh["neighbor"] + " dev " + intf_neigh["interface"]
        )
        # remove interface
        asichost.config_ip_intf(intf_neigh["interface"], intf_neigh["ip"], "remove")
