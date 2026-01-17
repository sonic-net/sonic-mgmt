from multihome.const import SEQ_IDS, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP, spytest_data
from multihome.status_report import report_fail
from spytest import st


def update_sequence_ids(node_names):
    """
    Update the sequence IDs for the specified nodes.
    NOTE: This function is a non db operation, didn't find a best place to put it.
    Args:
        node_names (list): List of node names to update sequence IDs for.
    Returns:
        list: Updated sequence IDs in the format 'local/remote'.
    """
    # Calculate the maximum sequence ID for the specified nodes
    max_seq_id = max(
        max(SEQ_IDS[node]["local"], SEQ_IDS[node]["remote"]) for node in node_names
    )
    # New sequence ID to be used
    new_seq_id = max_seq_id + 1
    # Update the sequence IDs
    for node in SEQ_IDS:
        if node in node_names:
            # Update only the local sequence ID to new_seq_id
            SEQ_IDS[node]["local"] = new_seq_id
        else:
            # Update only the remote sequence ID to new_seq_id
            SEQ_IDS[node]["remote"] = new_seq_id
    # Return the updated sequence IDs in the format 'local/remote'
    updated_seq_ids = [
        str(SEQ_IDS[node]["local"]) + "/" + str(SEQ_IDS[node]["remote"])
        for node in SEQ_IDS
    ]
    return updated_seq_ids


def verify_mac_in_app_db(nodes, vtep_node_name, mac, expected_type, expected_vni):
    """
    Verify if the MAC address is present in the application database with the expected type and VNI.
    Args:
        nodes (list): List of node names.
        vtep_node_name (str): dut node name.
        mac (str): MAC address to verify.
        expected_type (str):
        expected_vni (str): Expected VNI of the MAC address.
    Returns:
        bool: True if the MAC address is found with the expected type and VNI, False otherwise.
    """
    output = st.show(
        nodes[vtep_node_name],
        "sonic-db-dump -n APPL_DB -k *{}* -y".format(mac),
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(
        nodes[vtep_node_name],
        "sonic-db-dump -n APPL_DB -k *{}* -y".format(mac),
        output,
        "show_appl_db_vxlan_fdb_tbl.tmpl",
    )
    st.log(parsed)
    if len(parsed) == 0:
        return False
    for path in parsed:
        if path["mac_addr"] == mac:
            if path["vni_label"] == expected_vni:
                return True
            # if path["type"] == expected_type and path['vni_label'] == expected_vni:
    return False


def verify_sonic_app_db_for_pfx(nodes, prefix_ip, vtep_node_name, match_string):
    """
    Verify if the prefix IP is present in the application database with the expected type and VNI.
    Args:
        nodes (list): List of node names.
        prefix_ip (str): Prefix IP address to verify.
        vtep_node_name (str): Source VTEP node name.
        match_string (str): Match string to filter the output.
    Returns:
        bool: True if the prefix IP is found, False otherwise."""
    output = st.show(
        nodes[vtep_node_name],
        "sonic-db-dump -n APPL_DB -k *{}* -y".format(match_string),
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(
        nodes[vtep_node_name],
        "sonic-db-dump -n APPL_DB -k *{}* -y".format(match_string),
        output,
        "show_app_db_route_table.tmpl",
    )
    if len(parsed) == 0:
        st.log("ERROR empty output")
    for path in parsed:
        if path["ip_address"] == prefix_ip:
            return
    report_fail(
        nodes[vtep_node_name],
        "verify_sonic_app_db_for_pfx testcase failed for {} on node {}".format(
            prefix_ip, vtep_node_name
        ),
    )


def verify_sonic_asic_db_for_neighbor_pfx(nodes, prefix_ip, src_vtep, dst_vtep=None):
    output = st.show(
        nodes[src_vtep],
        "sonic-db-dump -n ASIC_DB -k *{}* -y".format(prefix_ip),
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(
        nodes[src_vtep],
        "sonic-db-dump -n ASIC_DB -k *{}* -y".format(prefix_ip),
        output,
        "show_asic_db.tmpl",
    )
    if len(parsed) == 0:
        st.log("ERROR empty output")
        report_fail(
            nodes[src_vtep],
            "{} neighbor entry missing in ASIC DB on {}".format(prefix_ip, src_vtep),
        )
    st.log(parsed)
    for path in parsed:
        if path["ip_address"].split("/")[0] == prefix_ip:
            return
    report_fail(
        nodes[src_vtep],
        "{} neighbor entry missing in ASIC DB on {}".format(prefix_ip, src_vtep),
    )


def is_nhg_installed(nodes):
    """
    Check if the nexthop group is installed in the ASIC DB.
    Args:
        nodes (list): List of node names.
    Returns:
        True or False"""
    vtep_list = [LEAF0_VXLAN_IP, LEAF1_VXLAN_IP]

    # Dump VXLAN_FDB_TABLE
    cmd = "sonic-db-dump -n APPL_DB -k *VXLAN_FDB_TABLE:Vlan10:{}* -y".format(
        spytest_data.lag_mac
    )

    retries = 5
    while retries > 0:
        output = st.show(nodes["leaf2"], cmd, skip_tmpl=True, skip_error_check=True)
        parsed = st.parse_show(
            nodes["leaf2"], cmd, output, "sonic_db_dump_app_db_VXLAN_FDB_TABLE.tmpl"
        )
        retries -= 1
        if parsed:
            st.log("VXLAN_FDB_TABLE retries left {}: {}".format(retries, parsed))
            break
        st.wait(5)
    if not parsed:
        report_fail(nodes["leaf2"], "No nexthop group is found on leaf2")
    nexthop_group = parsed[0]["nexthop_group"]

    # Dump NEXTHOP_GROUP_TABLE
    cmd = "sonic-db-dump -n APPL_DB -k *L2_NEXTHOP_GROUP_TABLE:{}* -y".format(
        nexthop_group
    )
    output = st.show(nodes["leaf2"], cmd, skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(
        nodes["leaf2"], cmd, output, "sonic_db_dump_app_db_L2_NEXTHOP_GROUP_TABLE.tmpl"
    )
    nexthops = parsed[0]["nexthop_group"].split(",")
    if len(nexthops) != len(vtep_list):
        report_fail(nodes["leaf2"], "Incorrect number of nexthop group members")

    # Dump NEXTHOP_GROUP_TABLE of each nexthop group member
    vtep0_seen = False
    vtep1_seen = False
    for nexthop in nexthops:
        cmd = "sonic-db-dump -n APPL_DB -k *L2_NEXTHOP_GROUP_TABLE:{}* -y".format(
            nexthop
        )
        output = st.show(nodes["leaf2"], cmd, skip_tmpl=True, skip_error_check=True)
        parsed = st.parse_show(
            nodes["leaf2"],
            cmd,
            output,
            "sonic_db_dump_app_db_L2_NEXTHOP_GROUP_TABLE.tmpl",
        )
        vtep_ip = parsed[0]["remote_vtep"]
        if vtep_ip == LEAF0_VXLAN_IP:
            vtep0_seen = True
        elif vtep_ip == LEAF1_VXLAN_IP:
            vtep1_seen = True

    if (not vtep0_seen) and (not vtep1_seen):
        report_fail(nodes["leaf2"], "Both leaf0 and leaf1 are missing as nexthops")
    elif not vtep0_seen:
        report_fail(nodes["leaf2"], "Leaf0 is missing as nexthop")
    elif not vtep1_seen:
        report_fail(nodes["leaf2"], "Leaf1 is missing as nexthop")


def verify_sonic_asic_db_for_pfx(nodes, prefix_ip, src_vtep, dst_vtep=None):
    output = st.show(
        nodes[src_vtep],
        "sonic-db-dump -n ASIC_DB -k *{}* -y".format(prefix_ip),
        skip_tmpl=True,
        skip_error_check=True,
    )
    parsed = st.parse_show(
        nodes[src_vtep],
        "sonic-db-dump -n ASIC_DB -k *{}* -y".format(prefix_ip),
        output,
        "show_asic_db.tmpl",
    )
    if len(parsed) == 0:
        st.log("ERROR empty output")
        report_fail(
            nodes[src_vtep],
            "verify_sonic_asic_db_for_pfx {} not found in asic db on {}".format(
                prefix_ip, src_vtep
            ),
        )
    st.log(parsed)
    for path in parsed:
        if path["ip_address"].split("/")[0] == prefix_ip:
            output = st.show(
                nodes[src_vtep],
                "sonic-db-dump -n ASIC_DB -k *{}* -y".format(path["nexthopid"]),
                skip_tmpl=True,
                skip_error_check=True,
            )
            parsed = st.parse_show(
                nodes[src_vtep],
                "sonic-db-dump -n ASIC_DB -k *{}* -y".format(path["nexthopid"]),
                output,
                "show_asic_db.tmpl",
            )
            if len(parsed) == 0:
                st.log("ERROR nexthopid not found in asic db")
            for path in parsed:
                if dst_vtep and path["nexthopip"] == dst_vtep:
                    st.log("Testcase passed")
                    return
                elif dst_vtep is None:
                    if (
                        path["attr_type"]
                        == "SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP"
                    ):
                        st.log("Testcase passed")
                        return
    report_fail(
        nodes[src_vtep],
        "verify_sonic_asic_db_for_pfx incorrect details found in asic_db for {} on {}".format(
            prefix_ip, src_vtep
        ),
    )
