"""Reversible SONiC operations shared by EVPN-MH disruption tests."""

from copy import deepcopy
from contextlib import contextmanager
import json
import sys
import time

from .state import (command_json, established_peers, ethernet_segment,
                    segment_is_df, segment_is_local, segment_is_remote,
                    segment_vteps)
from .topology import ethernet_segments


def wait_until(timeout, interval, delay, function, *args, **kwargs):
    """Small local poller that keeps parser-only collection dependency-free."""
    if delay:
        time.sleep(delay)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if function(*args, **kwargs):
            return True
        time.sleep(interval)
    return bool(function(*args, **kwargs))


def set_interface_admin(duthost, interface, up):
    action = "startup" if up else "shutdown"
    result = duthost.shell("sudo config interface {} {}".format(action, interface),
                           module_ignore_errors=True)
    assert result.get("rc", 1) == 0, result.get("stderr", result)


def interface_oper_up(duthost, interface):
    result = duthost.shell("show interface status {}".format(interface),
                           module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        return False
    for line in reversed(result.get("stdout_lines", [])):
        fields = line.split()
        if fields and fields[0].lower() == interface.lower():
            states = [field.lower() for field in fields
                      if field.lower() in ("up", "down")]
            return bool(states and states[0] == "up")
    return False


def wait_interface(duthost, interface, up, timeout=90):
    return wait_until(timeout, 5, 0, lambda: interface_oper_up(duthost, interface) is up)


def bounce_ptf_member(ptfhost, member):
    """Restart LACP negotiation after a peer-side link disruption."""
    failures = []
    for action in ("down", "up"):
        try:
            result = ptfhost.shell(
                "ip link set {} {}".format(member, action),
                module_ignore_errors=True)
            if result.get("rc", 1) != 0:
                raise RuntimeError(
                    result.get("stderr", result.get("stdout", "failed")))
        except Exception as error:
            failures.append("{}: {}".format(action, error))
    if failures:
        raise RuntimeError(
            "failed to bounce PTF member {}: {}".format(
                member, "; ".join(failures)))


@contextmanager
def interface_down(duthost, interface, wait_recovery=True):
    mutation_attempted = False
    try:
        # A command can change admin state even when its wrapper later reports
        # failure.  Enter the restoration guard before the first mutation so a
        # failed down-state assertion cannot poison every following testcase.
        mutation_attempted = True
        set_interface_admin(duthost, interface, False)
        assert wait_interface(duthost, interface, False, 45)
        yield
    finally:
        if mutation_attempted:
            if wait_recovery:
                restore_interfaces(duthost, (interface,))
            else:
                # The owning case renegotiates PTF LACP before waiting up.
                set_interface_admin(duthost, interface, True)


def restore_interfaces(duthost, interfaces, timeout=90):
    """Best-effort restoration that attempts every named interface."""
    primary = sys.exc_info()[1]
    failures = []
    for interface in interfaces:
        try:
            set_interface_admin(duthost, interface, True)
        except Exception as error:
            failures.append((interface, error))
        try:
            if not wait_interface(duthost, interface, True, timeout):
                raise AssertionError("{} did not return up".format(interface))
        except Exception as error:  # Continue restoring the remaining links.
            failures.append((interface, error))
    if failures:
        detail = "; ".join(
            "{}: {}".format(interface, error) for interface, error in failures)
        message = "failed to restore interfaces: {}".format(detail)
        if primary is not None:
            raise AssertionError(
                "{}; additionally, {}".format(primary, message)) from primary
        raise AssertionError(message) from failures[0][1]


def portchannel_members(duthost, portchannel):
    result = duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_MEMBER|{}|*'".format(portchannel),
        module_ignore_errors=True)
    members = []
    for line in result.get("stdout_lines", []):
        parts = line.split("|")
        if len(parts) == 3:
            members.append(parts[-1])
    return sorted(members)


def portchannel_config_snapshot(duthost, portchannel, member, vlan):
    """Capture the exact CONFIG_DB objects owned by one PortChannel."""
    result = duthost.shell(
        "sonic-cfggen -d --print-data", module_ignore_errors=True
    )
    if result.get("rc", 1) != 0:
        raise AssertionError(
            "cannot read CONFIG_DB for {} recovery".format(portchannel)
        )
    try:
        config = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError) as error:
        raise AssertionError(
            "invalid CONFIG_DB JSON during {} recovery".format(portchannel)
        ) from error

    return deepcopy({
        "portchannel": config.get("PORTCHANNEL", {}).get(portchannel),
        "member": config.get("PORTCHANNEL_MEMBER", {}).get(
            "{}|{}".format(portchannel, member)
        ),
        "vlan_member": config.get("VLAN_MEMBER", {}).get(
            "Vlan{}|{}".format(vlan, portchannel)
        ),
        "ethernet_segment": config.get(
            "EVPN_ETHERNET_SEGMENT", {}
        ).get(portchannel),
    })


def restore_portchannel_config(duthost, portchannel, member, vlan, baseline):
    """Reconcile a partially removed PortChannel to its exact snapshot."""
    required = ("portchannel", "member", "vlan_member", "ethernet_segment")
    if any(baseline.get(component) is None for component in required):
        raise AssertionError(
            "{} recovery snapshot is incomplete".format(portchannel)
        )
    baseline = deepcopy(baseline)
    baseline_without_mac = deepcopy(baseline["portchannel"])
    baseline_without_mac.pop("system_mac", None)

    def current():
        return portchannel_config_snapshot(
            duthost, portchannel, member, vlan
        )

    def mutate(command, component, expected):
        failure = None
        try:
            result = duthost.shell(command, module_ignore_errors=True)
            if result.get("rc", 1) != 0:
                failure = result.get(
                    "stderr", result.get("stdout", result)
                )
        except Exception as error:
            failure = error
        observed = current()[component]
        if observed == expected:
            return
        raise AssertionError(
            "{} did not restore {}: {}; observed {!r}".format(
                command, component, failure or "readback mismatch", observed
            )
        )

    observed = current()
    if observed["portchannel"] is None:
        command = "sudo config portchannel add {}".format(portchannel)
        failure = None
        try:
            result = duthost.shell(command, module_ignore_errors=True)
            if result.get("rc", 1) != 0:
                failure = result.get(
                    "stderr", result.get("stdout", result)
                )
        except Exception as error:
            failure = error
        restored = current()["portchannel"]
        if restored not in (baseline_without_mac, baseline["portchannel"]):
            raise AssertionError(
                "{} did not restore portchannel: {}; observed {!r}".format(
                    command, failure or "readback mismatch", restored
                )
            )
    elif observed["portchannel"] not in (
            baseline_without_mac, baseline["portchannel"]):
        raise AssertionError(
            "{} has divergent PortChannel state".format(portchannel)
        )

    observed = current()
    if observed["member"] is None:
        ipv6_command = (
            "sudo config interface ipv6 disable use-link-local-only {}"
            .format(member)
        )
        result = duthost.shell(ipv6_command, module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            raise AssertionError("{} failed".format(ipv6_command))
        mutate(
            "sudo config portchannel member add {} {}".format(
                portchannel, member
            ),
            "member",
            baseline["member"],
        )
    elif observed["member"] != baseline["member"]:
        raise AssertionError("{} has divergent member state".format(portchannel))

    observed = current()
    if observed["vlan_member"] is None:
        mutate(
            "sudo config vlan member add -u {} {}".format(vlan, portchannel),
            "vlan_member",
            baseline["vlan_member"],
        )
    elif observed["vlan_member"] != baseline["vlan_member"]:
        raise AssertionError(
            "{} has divergent VLAN membership".format(portchannel)
        )

    observed = current()
    if observed["portchannel"] == baseline_without_mac:
        mutate(
            "sudo config interface sys-mac add {} {}".format(
                portchannel, baseline["portchannel"]["system_mac"]
            ),
            "portchannel",
            baseline["portchannel"],
        )
    elif observed["portchannel"] != baseline["portchannel"]:
        raise AssertionError(
            "{} has divergent system-MAC state".format(portchannel)
        )

    observed = current()
    if observed["ethernet_segment"] is None:
        mutate(
            "sudo config interface evpn-esi add {} auto-system-mac".format(
                portchannel
            ),
            "ethernet_segment",
            baseline["ethernet_segment"],
        )
    elif observed["ethernet_segment"] != baseline["ethernet_segment"]:
        raise AssertionError(
            "{} has divergent Ethernet-Segment state".format(portchannel)
        )

    restored = current()
    if restored != baseline:
        raise AssertionError(
            "{} CONFIG_DB did not match its recovery snapshot".format(
                portchannel
            )
        )


def overlay_ready(duts, topology):
    vteps = topology["vtep_ip"]
    segments = ethernet_segments(topology)
    df_roles = {name: [] for name in segments}
    leaf_roles = ("mh_leaf0", "mh_leaf1")
    try:
        for role, dut in duts.items():
            if role not in leaf_roles:
                return False
            peer_role = next(item for item in leaf_roles if item != role)
            expected_peers = {
                vteps[peer_role],
                vteps["remote_leaf"],
            }
            summary = command_json(dut, "show bgp l2vpn evpn summary json")
            if not expected_peers.issubset(established_peers(summary)):
                return False
            state = command_json(dut, "show evpn es json")
            for name, definition in segments.items():
                segment = ethernet_segment(state, definition["esi"])
                segment_leaf_roles = tuple(definition["leaf_roles"])
                if role in segment_leaf_roles:
                    if segment is None or not segment_is_local(segment):
                        return False
                    peer_role = next(
                        item for item in segment_leaf_roles if item != role
                    )
                    if vteps[peer_role] not in segment_vteps(segment):
                        return False
                    if segment_is_df(segment):
                        df_roles[name].append(role)
                else:
                    expected = {vteps[item] for item in segment_leaf_roles}
                    if (segment is None or not segment_is_remote(segment)
                            or not expected.issubset(segment_vteps(segment))):
                        return False
    except RuntimeError:
        return False
    return all(len(roles) == 1 for roles in df_roles.values())


def wait_overlay(duts, topology, timeout=180):
    return wait_until(timeout, 10, 0, overlay_ready, duts, topology)
