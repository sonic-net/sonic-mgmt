"""Deterministic PTF LACP lifecycle for the EVPN-MH emulated host."""

import json

from tests.common.utilities import wait_until


BOND_NAME = "bond-evpn-mh"


def _bond_member_operational(state, member):
    """Return whether one exact slave is selected and forwarding in LACP."""
    sections = []
    for raw_section in state.split("Slave Interface:")[1:]:
        lines = raw_section.splitlines()
        if lines and lines[0].strip() == member:
            sections.append(raw_section)
    if len(sections) != 1:
        return False
    section = sections[0].lower()
    if "details actor lacp pdu:" not in section:
        return False
    actor = section.split("details actor lacp pdu:", 1)[1]
    actor = actor.split("details partner lacp pdu:", 1)[0]
    return (
        "mii status: up" in section
        and "port state: 63" in actor
    )


def ptf_bond_member_operational(ptfhost, member, bond_name=BOND_NAME):
    """Prove an exact PTF slave is LACP selected/collecting/distributing."""
    result = ptfhost.shell(
        "cat /proc/net/bonding/{}".format(bond_name),
        module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        return False
    state = result.get("stdout", "")
    return (
        "Partner Mac Address: 00:00:00:00:00:00" not in state
        and _bond_member_operational(state, member)
    )


def ptf_bond_operational(ptfhost, members, bond_name=BOND_NAME):
    result = ptfhost.shell(
        "cat /proc/net/bonding/{}".format(bond_name),
        module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        return False
    state = result.get("stdout", "")
    return (
        "Number of ports: {}".format(len(members)) in state
        and "Partner Mac Address: 00:00:00:00:00:00" not in state
        and all(_bond_member_operational(state, member) for member in members)
    )


def configure_ptf_segment(ptfhost, ports, segment, endpoints, duts):
    """Recreate one semantic PTF bond and its two-sided LACP exchange."""
    members = ["eth{}".format(ports[role])
               for role in segment["ptf_member_roles"]]
    endpoint = endpoints[segment["endpoint"]]
    lag_system_mac = segment["ptf_system_mac"]
    portchannel = segment["portchannel"]
    bond_name = segment["ptf_bond_interface"]
    host_interface = segment["ptf_host_interface"]

    ptfhost.shell("ip link del {} 2>/dev/null || true".format(host_interface))
    ptfhost.shell("ip link del {} 2>/dev/null || true".format(bond_name))
    for role in segment["leaf_roles"]:
        duts[role].shell(
            "sudo config interface shutdown {}".format(portchannel))

    ptfhost.shell("ip link add {} type bond".format(bond_name))
    ptfhost.shell(
        "ip link set {} type bond miimon 100 mode 802.3ad lacp_rate fast".format(
            bond_name))
    ptfhost.shell("ip link set dev {} address {}".format(
        bond_name, lag_system_mac))
    for member in members:
        ptfhost.shell("ip link set {} down".format(member))
        ptfhost.shell("ip link set {} master {}".format(member, bond_name))
    ptfhost.shell("ip link set dev {} up".format(bond_name))

    for role in segment["leaf_roles"]:
        duts[role].shell(
            "sudo config interface startup {}".format(portchannel))
    for member in members:
        ptfhost.shell("ip link set {} up".format(member))
    for port in sorted(set(ports.values())):
        interface = "eth{}".format(port)
        if interface not in members:
            ptfhost.shell("ip link set {} up".format(interface))

    ptfhost.shell("ip link add link {} name {} type macvlan mode bridge".format(
        bond_name, host_interface))
    # Multiple semantic hosts intentionally share one tenant subnet inside
    # the PTF namespace.  Linux's default weak-host ARP behavior can answer
    # a request for one macvlan's address on another macvlan and advertise the
    # receiving interface's MAC (ARP flux).  Keep every emulated host's
    # IP-to-MAC identity bound to its own attachment.  These settings are
    # interface-local and disappear when the macvlan is removed.
    ptfhost.shell(
        "sysctl -w net.ipv4.conf.{}.arp_ignore=1".format(host_interface))
    ptfhost.shell(
        "sysctl -w net.ipv4.conf.{}.arp_announce=2".format(host_interface))
    ptfhost.shell("ip link set dev {} address {}".format(
        host_interface, endpoint["mac"]))
    ptfhost.shell("ip addr add {}/{} dev {}".format(
        endpoint["ipv4"], int(endpoint.get("ipv4_prefixlen", 24)),
        host_interface))
    ptfhost.shell("ip -6 addr add {}/{} dev {}".format(
        endpoint["ipv6"], int(endpoint.get("ipv6_prefixlen", 64)),
        host_interface))
    ptfhost.shell("ip link set dev {} up".format(host_interface))
    ptfhost.shell("supervisorctl restart ptf_nn_agent")

    assert wait_until(90, 2, 0, ptf_bond_operational,
                      ptfhost, members, bond_name), (
        "PTF EVPN-MH bond did not converge with members {}".format(members))
    return bond_name


def remove_ptf_segment(ptfhost, ports, segment):
    """Remove a PTF segment and prove no bond/macvlan/master state leaked."""
    failures = []

    def link_state(interface):
        result = ptfhost.shell(
            "ip -j link show dev {}".format(interface),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            detail = "\n".join(
                str(result.get(field, ""))
                for field in ("stderr", "stdout", "msg")
            ).lower()
            if result.get("rc") == 1 and any(
                    marker in detail for marker in (
                        "does not exist", "cannot find device", "not found")):
                return None
            failures.append(
                "{} link-state query failed: {}".format(
                    interface, detail.strip() or "unknown command error"))
            return False
        try:
            payload = json.loads(result.get("stdout", ""))
        except (TypeError, ValueError):
            failures.append("{} link state is not JSON".format(interface))
            return False
        if len(payload) != 1 or payload[0].get("ifname") != interface:
            failures.append("{} link state is incomplete".format(interface))
            return False
        return payload[0]

    def checked(command, label):
        result = ptfhost.shell(command, module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            failures.append("{}: {}".format(
                label, result.get("stderr", result.get("stdout", ""))
            ))

    host_interface = segment["ptf_host_interface"]
    bond_name = segment["ptf_bond_interface"]
    if link_state(host_interface) is not None:
        checked(
            "ip link del {}".format(host_interface),
            "delete {}".format(host_interface),
        )
    for role in segment["ptf_member_roles"]:
        member = "eth{}".format(ports[role])
        checked("ip link set {} nomaster".format(member),
                "detach {}".format(member))
        checked("ip link set {} up".format(member),
                "bring up {}".format(member))
    if link_state(bond_name) is not None:
        checked("ip link del {}".format(bond_name),
                "delete {}".format(bond_name))

    if link_state(host_interface) is not None:
        failures.append("{} still exists".format(host_interface))
    if link_state(bond_name) is not None:
        failures.append("{} still exists".format(bond_name))
    for role in segment["ptf_member_roles"]:
        member = "eth{}".format(ports[role])
        state = link_state(member)
        if not isinstance(state, dict):
            failures.append("{} is unavailable after cleanup".format(member))
            continue
        if state.get("master"):
            failures.append("{} remains enslaved to {}".format(
                member, state["master"]
            ))
        if "UP" not in state.get("flags", []):
            failures.append("{} is not administratively up".format(member))
    if failures:
        raise RuntimeError("PTF segment cleanup failed: {}".format(
            "; ".join(failures)
        ))
