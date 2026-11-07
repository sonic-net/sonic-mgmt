"""Topology-driven SONiC configuration for the EVPN-MH pytest topology."""

import shlex

from .operations import portchannel_members, wait_overlay, wait_until
from .topology import ethernet_segments


_IDEMPOTENT_ERROR_MARKERS = (
    # SONiC CLI currently emits both "already" and the legacy typo
    # "alreaday" for duplicate create operations.
    "alread",
    "has already been",
)

_ABSENT_ERROR_MARKERS = (
    "not found",
    "does not exist",
    "no such",
    "is not configured",
)


def _run(dut, commands, tolerate_existing=False):
    for command in commands:
        result = dut.shell(command, module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            output = "\n".join(str(result.get(field, ""))
                               for field in ("stderr", "stdout", "msg")).lower()
            if tolerate_existing and any(marker in output
                                         for marker in _IDEMPOTENT_ERROR_MARKERS):
                continue
            raise RuntimeError("{} failed on {}: {}".format(
                command, dut.hostname, result.get("stderr", result.get("stdout", ""))))


def _command_stdout(dut, command):
    """Run a read-only SONiC command and return its standard output."""
    result = dut.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError("{} failed on {}: {}".format(
            command, dut.hostname, result.get("stderr", result.get("stdout", ""))))
    return result.get("stdout", "")


def _config_db_key_exists(dut, key):
    """Return exact CONFIG_DB key presence and reject malformed replies."""
    output = _command_stdout(
        dut, "sonic-db-cli CONFIG_DB EXISTS {}".format(shlex.quote(key))
    ).strip()
    if output not in ("0", "1"):
        raise RuntimeError(
            "CONFIG_DB EXISTS returned {!r} for {} on {}".format(
                output, key, dut.hostname))
    return output == "1"


def _caclmgrd_active(dut):
    result = dut.shell(
        "sudo systemctl is-active --quiet caclmgrd",
        module_ignore_errors=True,
    )
    return result.get("rc", 1) == 0


def restart_caclmgrd(dut):
    """Re-render MUX-derived control-plane ACLs and require readiness."""
    result = dut.shell(
        "sudo systemctl restart caclmgrd", module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError(
            "caclmgrd restart failed on {}: {}".format(
                dut.hostname,
                result.get("stderr", result.get("stdout", ""))))
    if not wait_until(30, 1, 0, _caclmgrd_active, dut):
        raise RuntimeError(
            "caclmgrd did not return active on {}".format(dut.hostname))


def _unbind_port_from_acl_tables(dut, interface):
    """Remove an interface from ACL bindings before making it a LAG member.

    SONiC rejects ``config portchannel member add`` while the physical port is
    referenced by an ACL table.  Discover the tables from CONFIG_DB instead of
    assuming platform-specific names such as EVERFLOW, and preserve every
    unrelated port binding.
    """
    table_keys = _command_stdout(
        dut, "sonic-db-cli CONFIG_DB KEYS 'ACL_TABLE|*'").splitlines()
    for table_key in (key.strip() for key in table_keys if key.strip()):
        ports = _command_stdout(
            dut,
            "sonic-db-cli CONFIG_DB HGET '{}' 'ports@'".format(table_key))
        bound_ports = [port.strip() for port in ports.split(",") if port.strip()]
        if interface not in bound_ports:
            continue

        remaining_ports = [port for port in bound_ports if port != interface]
        if remaining_ports:
            command = (
                "sudo sonic-db-cli CONFIG_DB HSET '{}' 'ports@' '{}'".format(
                    table_key, ",".join(remaining_ports)))
        else:
            # An empty ACL_TABLE ports leaf-list is invalid.  Keep the table
            # and its rules, but remove its binding field.
            command = "sudo sonic-db-cli CONFIG_DB HDEL '{}' 'ports@'".format(
                table_key)
        _run(dut, [command])


def _prepare_single_homed_interface(dut, interface, attachment):
    """Guardedly release a stock dualtor access port for suite ownership.

    Pair 1 belongs to stock Vlan1000 and can have an active-active MUX_CABLE
    record.  The module-scoped SONiC checkpoint owns restoration; this helper
    only mutates state after proving the exact stock objects declared by the
    service model.  An unexpected or partially absent object fails closed.
    """
    stock_vlan = attachment.get("stock_vlan")
    if stock_vlan is None:
        return
    stock_vlan = int(stock_vlan)
    vlan_key = "VLAN_MEMBER|Vlan{}|{}".format(stock_vlan, interface)
    if not _config_db_key_exists(dut, vlan_key):
        raise RuntimeError(
            "{} lacks expected stock Vlan{} membership on {}".format(
                dut.hostname, stock_vlan, interface))

    mux_key = "MUX_CABLE|{}".format(interface)
    expected_cable_type = attachment.get("stock_mux_cable_type")
    mux_exists = _config_db_key_exists(dut, mux_key)
    if expected_cable_type:
        if not mux_exists:
            raise RuntimeError(
                "{} lacks expected stock MUX_CABLE for {}".format(
                    dut.hostname, interface))
        actual_cable_type = _command_stdout(
            dut,
            "sonic-db-cli CONFIG_DB HGET {} cable_type".format(
                shlex.quote(mux_key)),
        ).strip()
        if actual_cable_type.replace("_", "-").lower() != str(
                expected_cable_type).replace("_", "-").lower():
            raise RuntimeError(
                "{} {} cable_type {!r} differs from expected {!r}".format(
                    dut.hostname, mux_key, actual_cable_type,
                    expected_cable_type))
        _run(dut, [
            "sudo sonic-db-cli CONFIG_DB DEL {}".format(
                shlex.quote(mux_key))
        ])
        if _config_db_key_exists(dut, mux_key):
            raise RuntimeError("{} was not removed".format(mux_key))
        # caclmgrd consumes STATE_DB MUX_CABLE_TABLE but does not subscribe to
        # direct CONFIG_DB MUX_CABLE changes.  Restart it immediately after
        # the proven deletion so stale MUX iptables rules cannot survive.
        restart_caclmgrd(dut)
    elif mux_exists:
        raise RuntimeError(
            "{} has undeclared MUX_CABLE ownership for {}".format(
                dut.hostname, interface))

    _unbind_port_from_acl_tables(dut, interface)
    _run(dut, [
        "sudo config vlan member del {} {}".format(stock_vlan, interface)
    ])
    if _config_db_key_exists(dut, vlan_key):
        raise RuntimeError("{} was not removed".format(vlan_key))


def _bgp_asn(dut):
    result = dut.shell("sonic-db-cli CONFIG_DB hget 'DEVICE_METADATA|localhost' bgp_asn")
    return int(result["stdout"].strip())


def uses_frrcfgd(dut):
    """Return whether this SONiC image consumes the model-driven BGP tables."""
    result = dut.shell(
        "docker exec bgp sh -c \"ps -ef | grep '[f]rrcfgd'\"",
        module_ignore_errors=True)
    return result.get("rc", 1) == 0


def wait_evpn_mh_overlay(duts, topology, timeout=180):
    """Wait for symmetric ES state on model-driven SONiC images only."""
    unsupported = [role for role, dut in duts.items() if not uses_frrcfgd(dut)]
    if unsupported:
        raise RuntimeError(
            "EVPN-MH requires frrcfgd for reversible CONFIG_DB ownership: {}"
            .format(", ".join(sorted(unsupported)))
        )
    return wait_overlay(duts, topology, timeout=timeout)


def _configure_overlay_bgp(dut, role, duts, topology):
    if not uses_frrcfgd(dut):
        raise RuntimeError(
            "{} lacks frrcfgd; legacy FRR-file mutation is not reversible by "
            "the SONiC checkpoint".format(role)
        )
    asn = _bgp_asn(dut)
    local_address = topology["vtep_ip"][role]
    router_id = topology.get("router_id", {}).get(role, local_address)
    local_peer_role = "mh_leaf1" if role == "mh_leaf0" else "mh_leaf0"
    local_peer = topology["vtep_ip"][local_peer_role]
    remote_peer = topology["vtep_ip"]["remote_leaf"]
    remote_asn = int(topology["remote_overlay_asn"])
    commands = [
        "sudo sonic-db-cli CONFIG_DB HMSET 'BGP_GLOBALS|default' "
        "local_asn {} router_id {}".format(asn, router_id),
        "sudo sonic-db-cli CONFIG_DB HMSET 'BGP_GLOBALS|{}' "
        "local_asn {} router_id {}".format(topology["vrf"], asn, router_id),
        "sudo sonic-db-cli CONFIG_DB HMSET 'BGP_PEER_GROUP|default|EVPN' "
        "admin_status up local_asn {} asn {} local_addr {} "
        "capability_ext_nexthop true name EVPN".format(
            asn, asn, local_address),
        "sudo sonic-db-cli CONFIG_DB HMSET "
        "'BGP_PEER_GROUP|default|EVPN_REMOTE' "
        "admin_status up local_asn {} asn {} local_addr {} "
        "ebgp_multihop true ebgp_multihop_ttl 5 "
        "capability_ext_nexthop true name EVPN_REMOTE".format(
            asn, remote_asn, local_address),
        "sudo sonic-db-cli CONFIG_DB HMSET 'BGP_GLOBALS_AF|default|l2vpn_evpn' "
        "advertise-all-vni true advertise-ipv4-unicast true "
        "advertise-ipv6-unicast true",
        "sudo sonic-db-cli CONFIG_DB HSET 'BGP_GLOBALS_AF|{}|ipv4_unicast' "
        "redistribute_connected true".format(topology["vrf"]),
        "sudo sonic-db-cli CONFIG_DB HSET 'BGP_GLOBALS_AF|{}|ipv6_unicast' "
        "redistribute_connected true".format(topology["vrf"]),
        "sudo sonic-db-cli CONFIG_DB HMSET 'BGP_GLOBALS_AF|{}|l2vpn_evpn' "
        "advertise-ipv4-unicast true advertise-ipv6-unicast true".format(
            topology["vrf"]),
        "sudo sonic-db-cli CONFIG_DB HSET "
        "'BGP_PEER_GROUP_AF|default|EVPN|l2vpn_evpn' admin_status up",
        "sudo sonic-db-cli CONFIG_DB HSET "
        "'BGP_PEER_GROUP_AF|default|EVPN_REMOTE|l2vpn_evpn' "
        "admin_status up",
    ]
    for peer, peer_group, peer_asn in (
            (local_peer, "EVPN", asn),
            (remote_peer, "EVPN_REMOTE", remote_asn)):
        commands.extend([
            "sudo sonic-db-cli CONFIG_DB HMSET 'BGP_NEIGHBOR|default|{}' "
            "admin_status up local_addr {} local_asn {} asn {} "
            "peer_group_name {} "
            "capability_ext_nexthop true name EVPN-{}".format(
                peer, local_address, asn, peer_asn, peer_group,
                peer.replace(":", "-")),
            "sudo sonic-db-cli CONFIG_DB HSET "
            "'BGP_NEIGHBOR_AF|default|{}|l2vpn_evpn' admin_status up".format(
                peer),
        ])
    _run(dut, commands)


def _known_task_fdb_absent(duts, macs):
    """Reject every ASIC FDB row for a bounded suite-owned MAC.

    A stale remote/static row is just as capable of contaminating the next
    learning verdict as a dynamic row.  The clean-start phase has no safe
    pre-existing task-MAC row to preserve, so any matching key fails closed.
    """
    normalized_macs = {
        str(mac).lower().replace("-", ":") for mac in macs
    }
    for dut in duts.values():
        keys = _command_stdout(
            dut, "sonic-db-cli ASIC_DB KEYS '*FDB_ENTRY*'").splitlines()
        for key in (item.strip() for item in keys if item.strip()):
            normalized_key = key.lower().replace("-", ":")
            if any(mac in normalized_key for mac in normalized_macs):
                return False
    return True


def _host_interface_exists(dut, interface, container=None):
    prefix = "sudo docker exec {} ".format(container) if container else ""
    path = shlex.quote("/sys/class/net/{}".format(interface))
    probe = "if [ -d {} ]; then exit 0; else exit 10; fi".format(path)
    result = dut.shell(
        "{}sh -c {}".format(prefix, shlex.quote(probe)),
        module_ignore_errors=True,
    )
    rc = result.get("rc", 1)
    if rc == 0:
        return True
    if rc == 10:
        return False
    raise RuntimeError(
        "interface existence query failed on {} for {}: {}".format(
            dut.hostname, interface,
            result.get("stderr", result.get("stdout", "")),
        )
    )


def _known_task_neighbors_absent(duts, vlans):
    for dut in duts.values():
        for vlan in sorted(vlans):
            interface = "Vlan{}".format(vlan)
            if not _host_interface_exists(dut, interface):
                continue
            if _command_stdout(
                    dut, "ip neigh show dev {}".format(
                        shlex.quote(interface))).strip():
                return False
    return True


def _syncd_fdb_entry_present(dut, mac, portchannel, vlan):
    if not _host_interface_exists(dut, portchannel, container="syncd"):
        return False
    output = _command_stdout(
        dut,
        "sudo docker exec syncd bridge fdb show dev {}".format(
            shlex.quote(portchannel)),
    )
    normalized_mac = str(mac).lower().replace("-", ":")
    for line in output.splitlines():
        fields = line.lower().replace("-", ":").split()
        if not fields or fields[0] != normalized_mac:
            continue
        for index, field in enumerate(fields[:-1]):
            if field == "vlan" and fields[index + 1] == str(int(vlan)):
                return True
    return False


def _known_static_proxy_fdb_absent(duts, proxy_entries):
    return not any(
        _syncd_fdb_entry_present(
            duts[role], mac, portchannel, vlan)
        for role, mac, portchannel, vlan in proxy_entries
    )


def _known_runtime_learning_absent(duts, macs, vlans, proxy_entries):
    return (
        _known_task_fdb_absent(duts, macs)
        and _known_task_neighbors_absent(duts, vlans)
        and _known_static_proxy_fdb_absent(duts, proxy_entries)
    )


def clear_evpn_mh_runtime_state(duts, topology):
    """Remove host learning left by a previous suite run.

    Only task VLAN neighbor state and the task-owned ES MAC are cleared.  A
    global FDB flush would destroy unrelated stock Vlan1000 learning before
    the suite checkpoint exists.  Any other stale task MAC fails closed.  Do
    not delete VXLAN_FDB_TABLE directly:
    FRR can retain the matching Type-2 route and therefore emit no subsequent
    update to recreate the APPL_DB and ASIC FDB entries.  vSONiC can retain a
    Zebra-owned static proxy row after its neighbor has gone; remove that
    topology-owned H2 row from the syncd bridge as well so a repeated run can
    learn the host dynamically before rebuilding its MAC/IP RT2.
    """
    segments = ethernet_segments(topology)
    vlans = {int(topology["mh_vlan"]), int(topology["remote_vlan"])}
    vlans.update(int(segment["vlan"]) for segment in segments.values()
                 if segment.get("vlan") is not None)
    macs = {str(endpoint["mac"]).lower()
            for endpoint in topology["endpoints"].values()
            if endpoint.get("mac")}
    macs.update(str(segment["ptf_system_mac"]).lower()
                for segment in segments.values())

    for dut in duts.values():
        for vlan in vlans:
            interface = "Vlan{}".format(vlan)
            if _host_interface_exists(dut, interface):
                _run(dut, [
                    "sudo ip neigh flush dev {}".format(
                        shlex.quote(interface))
                ])

    proxy_entries = []
    for segment in segments.values():
        endpoint_mac = str(
            topology["endpoints"][segment["endpoint"]]["mac"]).lower()
        vlan = int(segment.get("vlan", topology["mh_vlan"]))
        for role in segment["leaf_roles"]:
            if role not in duts:
                continue
            entry = (role, endpoint_mac, segment["portchannel"], vlan)
            proxy_entries.append(entry)
            if _syncd_fdb_entry_present(
                    duts[role], endpoint_mac, segment["portchannel"], vlan):
                _run(duts[role], [
                    "sudo docker exec syncd bridge fdb del {mac} "
                    "dev {portchannel} vlan {vlan} master".format(
                        mac=shlex.quote(endpoint_mac),
                        portchannel=shlex.quote(segment["portchannel"]),
                        vlan=vlan,
                    )
                ])

    if not wait_until(
            60, 2, 2, _known_runtime_learning_absent,
            duts, macs, vlans, tuple(proxy_entries)):
        raise RuntimeError(
            "previous EVPN-MH neighbor, ASIC FDB, or static syncd "
            "proxy state did not drain")


def _base_commands(topology, vtep):
    l3vni_vlan = int(topology["l3vni_vlan"])
    return [
        "sudo config vxlan add VXLAN {}".format(vtep),
        "sudo config vxlan evpn_nvo add NVO VXLAN",
        "sudo config vlan add {}".format(l3vni_vlan),
        "sudo config vrf add {}".format(topology["vrf"]),
        "sudo config interface vrf bind Vlan{} {}".format(
            l3vni_vlan, topology["vrf"]),
        "sudo config vxlan map add VXLAN {} {}".format(
            l3vni_vlan, topology["l3vni"]),
        "sudo config vrf add_vrf_vni_map {} {}".format(topology["vrf"], topology["l3vni"]),
        "sudo config static-anycast-gateway mac_address add {}".format(
            topology["anycast_gateway_mac"]),
    ]


def _vlan_commands(topology, vlan, vni, interface, ipv4, ipv6):
    return [
        "sudo config vlan add {}".format(vlan),
        "sudo config vlan member add -u {} {}".format(vlan, interface),
        "sudo config interface vrf bind Vlan{} {}".format(vlan, topology["vrf"]),
        "sudo config vxlan map add VXLAN {} {}".format(vlan, vni),
        "sudo config interface ip add Vlan{} {}".format(vlan, ipv4),
        "sudo config interface ip add Vlan{} {}".format(vlan, ipv6),
        "sudo config vlan static-anycast-gateway enable {}".format(vlan),
    ]


def configure_temporary_l3_orphan(duts, source_role, source_interface,
                                  topology, endpoint):
    """Create the topology-owned tagged VLAN20 source used by testcase 12."""
    vlan = int(topology["remote_vlan"])
    prefix = "{}/{}".format(endpoint["ipv4"], endpoint["ipv4_prefixlen"])
    gateway_prefix = "{}/{}".format(
        endpoint["gateway_ipv4"], endpoint["ipv4_prefixlen"])
    for role in ("mh_leaf0", "mh_leaf1"):
        _run(duts[role], [
            "sudo config vlan add {}".format(vlan),
            "sudo config vxlan map add VXLAN {} {}".format(
                vlan, topology["remote_l2vni"]),
            "sudo config interface vrf bind Vlan{} {}".format(
                vlan, topology["vrf"]),
            "sudo config interface ip add Vlan{} {}".format(
                vlan, gateway_prefix),
            "sudo config vlan static-anycast-gateway enable {}".format(vlan),
        ], tolerate_existing=True)
    _run(duts[source_role], [
        # No -u: the source emits real 802.1Q frames for VLAN20 while the
        # physical orphan port retains its baseline untagged VLAN10 member.
        "sudo config vlan member add {} {}".format(vlan, source_interface),
    ], tolerate_existing=True)
    return {
        "vlan": vlan,
        "gateway_prefix": gateway_prefix,
        "host_prefix": prefix,
        "source_role": source_role,
        "source_interface": source_interface,
    }


def remove_temporary_l3_orphan(duts, topology, state):
    """Remove every object created by ``configure_temporary_l3_orphan``."""
    vlan = state["vlan"]
    commands = [(
        duts[state["source_role"]],
        "sudo config vlan member del {} {}".format(
            vlan, state["source_interface"]),
    )]
    for role in ("mh_leaf0", "mh_leaf1"):
        dut = duts[role]
        commands.extend((
            (dut, "sudo config vlan static-anycast-gateway disable {}".format(vlan)),
            (dut, "sudo config interface ip remove Vlan{} {}".format(
                vlan, state["gateway_prefix"])),
            (dut, "sudo config interface vrf unbind Vlan{}".format(vlan)),
            (dut, "sudo config vxlan map del VXLAN {} {}".format(
                vlan, topology["remote_l2vni"])),
            (dut, "sudo config vlan del {}".format(vlan)),
        ))

    failures = []
    for dut, command in commands:
        try:
            result = dut.shell(command, module_ignore_errors=True)
        except Exception as error:
            failures.append("{} on {}: {}".format(
                command, dut.hostname, error))
            continue
        if result.get("rc", 1) == 0:
            continue
        output = "\n".join(str(result.get(field, ""))
                           for field in ("stderr", "stdout", "msg")).lower()
        if any(marker in output for marker in _ABSENT_ERROR_MARKERS):
            continue
        failures.append("{} on {}: {}".format(command, dut.hostname, output.strip()))
    if failures:
        raise RuntimeError("temporary L3 orphan cleanup failed: {}".format(
            "; ".join(failures)))


def _interface_address_present(dut, vlan, prefix):
    result = dut.shell(
        "ip -o address show dev Vlan{}".format(vlan),
        module_ignore_errors=True,
    )
    return result.get("rc", 1) == 0 and prefix in result.get("stdout", "").split()


def _restore_interface_address(dut, vlan, prefix, timeout=15):
    """Reconcile a CONFIG_DB address that intfmgrd lost during VRF recreation."""
    if _interface_address_present(dut, vlan, prefix):
        return True
    interface = "Vlan{}".format(vlan)
    # Removing the persistent key first is required: ``config ... ip add`` is
    # otherwise a no-op when CONFIG_DB still has the address but Linux does
    # not. This race is observable after deleting and immediately recreating
    # a VRF on older SONiC-VS images.
    dut.shell(
        "sudo config interface ip remove {} {}".format(interface, prefix),
        module_ignore_errors=True,
    )
    result = dut.shell(
        "sudo config interface ip add {} {}".format(interface, prefix),
        module_ignore_errors=True,
    )
    return result.get("rc", 1) == 0 and wait_until(
        timeout, 2, 0, _interface_address_present, dut, vlan, prefix)


def _swss_interface_manager_ready(dut):
    result = dut.shell(
        "docker exec swss supervisorctl status intfmgrd",
        module_ignore_errors=True,
    )
    return result.get("rc", 1) == 0 and "RUNNING" in result.get("stdout", "")


def _replay_segment(dut, segment):
    """Republish local ES state lost by legacy SONiC-VS daemon restarts.

    Some older images preserve the CONFIG_DB keys across a SWSS restart but
    do not recreate the local FRR Ethernet Segment when the PortChannel comes
    back.  A bgp/zebra restart can also leave the already-up PortChannel with
    a stale routed-ingress attachment even after the ES control plane is
    republished.  Cycle the public PortChannel around the ESI/system-MAC
    rebuild so both the control plane and its dataplane attachment are
    recreated.  Callers limit this compatibility replay to legacy images.
    """
    portchannel = segment["portchannel"]
    system_mac = segment["system_mac"]
    dut.shell(
        "sudo config interface shutdown {}".format(portchannel),
        module_ignore_errors=True,
    )
    dut.shell(
        "sudo config interface evpn-esi del {}".format(portchannel),
        module_ignore_errors=True,
    )
    dut.shell(
        "sudo config interface sys-mac remove {} {}".format(
            portchannel, system_mac),
        module_ignore_errors=True,
    )
    _run(dut, [
        "sudo config interface sys-mac add {} {}".format(
            portchannel, system_mac),
        "sudo config interface evpn-esi add {} auto-system-mac".format(
            portchannel),
        "sudo config interface startup {}".format(portchannel),
    ])


def _local_segments(role, topology):
    segments = ethernet_segments(topology).values()
    return [segment for segment in segments
            if role in segment["leaf_roles"]]


def _reconcile_vlan_addresses(duts, topology):
    desired = []
    for endpoint_name, attachment in topology.get(
            "single_homed_endpoints", {}).items():
        desired.append((
            attachment["dut_role"], int(attachment["vlan"]),
            topology["endpoints"][endpoint_name]))
    for segment in ethernet_segments(topology).values():
        endpoint = topology["endpoints"][segment["endpoint"]]
        desired.extend((role, int(segment["vlan"]), endpoint)
                       for role in segment["leaf_roles"])
    addresses = sorted({
        (role, vlan, prefix)
        for role, vlan, endpoint in desired
        for prefix in (
            "{}/{}".format(endpoint["gateway_ipv4"], endpoint["ipv4_prefixlen"]),
            "{}/{}".format(endpoint["gateway_ipv6"], endpoint["ipv6_prefixlen"]),
        )
    })
    failed = [
        item for item in addresses
        if not _restore_interface_address(duts[item[0]], item[1], item[2])
    ]
    if not failed:
        return

    # Older SONiC-VS images can leave intfmgrd unable to publish INTF_TABLE
    # after a VRF is repeatedly deleted and recreated. Restart only the
    # affected SWSS containers, then replay their persistent CLI state once.
    affected_roles = sorted({role for role, _, _ in failed})
    for role in affected_roles:
        dut = duts[role]
        result = dut.shell(
            "sudo systemctl restart swss", module_ignore_errors=True)
        if result.get("rc", 1) != 0 or not wait_until(
                90, 2, 0, _swss_interface_manager_ready, dut):
            raise RuntimeError("{} SWSS did not recover".format(role))
        for segment in _local_segments(role, topology):
            _replay_segment(dut, segment)

    for role, vlan, prefix in addresses:
        if role not in affected_roles:
            continue
        if not _restore_interface_address(
                duts[role], vlan, prefix, timeout=60):
            raise RuntimeError(
                "{} did not restore {} on Vlan{}".format(
                    role, prefix, vlan))


def configure_evpn_mh(duts, interfaces, topology):
    """Apply EVPN-MH configuration to exactly the two local SONiC DUTs."""
    expected_roles = {"mh_leaf0", "mh_leaf1"}
    if set(duts) != expected_roles:
        raise RuntimeError(
            "SONiC DUT role map must contain exactly {}".format(
                ", ".join(sorted(expected_roles))
            )
        )
    unsupported = [role for role, dut in duts.items() if not uses_frrcfgd(dut)]
    if unsupported:
        raise RuntimeError(
            "EVPN-MH requires frrcfgd before any SONiC mutation: {}".format(
                ", ".join(sorted(unsupported))
            )
        )
    for role in duts:
        _run(duts[role], _base_commands(topology, topology["vtep_ip"][role]),
             tolerate_existing=True)

    for endpoint_name, attachment in topology.get(
            "single_homed_endpoints", {}).items():
        role = attachment["dut_role"]
        dut = duts[role]
        interface = interfaces[endpoint_name]["interface"]
        endpoint = topology["endpoints"][endpoint_name]
        _prepare_single_homed_interface(dut, interface, attachment)
        _run(
            dut,
            _vlan_commands(
                topology, int(attachment["vlan"]), int(attachment["l2vni"]),
                interface,
                "{}/{}".format(endpoint["gateway_ipv4"],
                               int(endpoint.get("ipv4_prefixlen", 24))),
                "{}/{}".format(endpoint["gateway_ipv6"],
                               int(endpoint.get("ipv6_prefixlen", 64))),
            ),
            tolerate_existing=True,
        )
        _run(dut, [
            "sudo config interface startup {}".format(interface),
        ])

    segments = ethernet_segments(topology)
    for name, segment in segments.items():
        missing = [
            field for field in ("vlan", "l2vni", "system_mac")
            if not segment.get(field)
        ]
        if missing:
            raise RuntimeError(
                "Ethernet Segment {} is missing provisioning fields {}".format(
                    name, ", ".join(missing)))
        endpoint = topology["endpoints"][segment["endpoint"]]
        for role, member_role in zip(
                segment["leaf_roles"], segment["ptf_member_roles"]):
            dut = duts[role]
            member = interfaces[member_role]["interface"]
            segment_portchannel = segment["portchannel"]
            _run(dut, [
                "sudo config portchannel add {}".format(segment_portchannel),
            ], tolerate_existing=True)
            if member not in portchannel_members(dut, segment_portchannel):
                _unbind_port_from_acl_tables(dut, member)
                _run(dut, [
                    "sudo config interface ipv6 disable use-link-local-only {}".format(
                        member),
                    "sudo config portchannel member add {} {}".format(
                        segment_portchannel, member),
                ])
            _run(
                dut,
                _vlan_commands(
                    topology, int(segment["vlan"]), int(segment["l2vni"]),
                    segment_portchannel,
                    "{}/{}".format(endpoint["gateway_ipv4"],
                                   int(endpoint.get("ipv4_prefixlen", 24))),
                    "{}/{}".format(endpoint["gateway_ipv6"],
                                   int(endpoint.get("ipv6_prefixlen", 64))),
                ),
                tolerate_existing=True,
            )
            _run(dut, [
                "sudo config interface sys-mac add {} {}".format(
                    segment_portchannel, segment["system_mac"]),
                "sudo config interface evpn-esi add {} auto-system-mac".format(
                    segment_portchannel),
                "sudo config interface startup {}".format(member),
                "sudo config interface startup {}".format(segment_portchannel),
            ], tolerate_existing=True)

    _reconcile_vlan_addresses(duts, topology)

    for role, dut in duts.items():
        _configure_overlay_bgp(dut, role, duts, topology)
        _run(dut, ["sudo config save -y"])
