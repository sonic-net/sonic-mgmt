import ipaddress
import json
import logging
import math
import re
import shlex
import time
import uuid
from contextlib import ExitStack, contextmanager

import pytest
from passlib.hash import cisco_type7

from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    disable_macsec_port,
    enable_macsec_port,
    generate_macsec_profile,
    set_macsec_profile,
    update_macsec_profile_key,
)
from tests.common.macsec.macsec_helper import get_ipnetns_prefix, get_mka_status, getns_prefix
from tests.common.macsec.macsec_platform_helper import find_portchannel_from_member, get_portchannel
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("t0", "t2", "lrh", "urh", "t0-sonic"),
]

FALLBACK_PROFILE = "MACSEC_PROFILE_FALLBACK"
REKEY_PERIOD = 30
MKA_TIMEOUT = 60
MKA_CONVERGE_TIMEOUT = 180
SA_RETIRE_TIMEOUT = 20
STRESS_ROTATIONS = 10
PING_REPLY = re.compile(r"bytes from .*icmp_seq[= ](\d+)")


# ---------------------------------------------------------------------------
# Public MACsec state
# ---------------------------------------------------------------------------

def generate_cak_ckn_pair(cipher_suite):
    """Return a fresh (cak, ckn) pair for *cipher_suite*."""
    profile = generate_macsec_profile("FALLBACK_TEST", cipher_suite)
    return profile["primary_cak"], profile["primary_ckn"]


def profile_fields(host, port, name):
    """Return SONiC profile fields in the port's namespace, or None when absent."""
    output = host.command("show macsec {} --profile".format(getns_prefix(host, port)), verbose=False)["stdout"]
    profiles, current = {}, None
    for line in output.splitlines():
        if line.startswith("MACsec profile : "):
            current = profiles.setdefault(line.partition(":")[2].strip(), {})
        elif current is not None:
            field, _, value = line.strip().partition(" ")
            current[field] = value.strip()
    return profiles.get(name)


def eos_profile(host, name):
    """Return the config lines of EOS MACsec profile *name*, or None."""
    result = host.eos_command(
        commands=["show running-config section mac security"], module_ignore_errors=True, verbose=False)
    succeeded = not result.get("failed")
    assert succeeded, "Unable to inspect EOS MACsec profile"
    config = result["stdout"][0]
    lines, inside = None, False
    for line in config.splitlines():
        line = line.strip()
        if line.startswith("profile "):
            inside = line == "profile {}".format(name)
            if inside:
                lines = []
        elif inside:
            lines.append(line)
    return lines


def profile_exists(host, name):
    """Check every ASIC namespace: the SONiC profile helpers write all of them."""
    if isinstance(host, EosHost):
        return eos_profile(host, name) is not None
    namespaces = host.get_asic_namespace_list() if host.is_multi_asic else [None]
    return any(
        line.strip() == "MACsec profile : {}".format(name)
        for ns in namespaces
        for line in host.command(
            "show macsec {} --profile".format("-n {}".format(ns) if ns else ""), verbose=False)["stdout"].splitlines())


def bound_profile(host, port):
    """Return the configured MACsec binding, independently of operational session readiness."""
    if isinstance(host, EosHost):
        config = host.eos_command(commands=["show running-config interfaces {}".format(port)])["stdout"][0]
        names = re.findall(r"(?m)^\s*mac security profile\s+(\S+)\s*$", config)
        assert len(names) <= 1, "Ambiguous MACsec binding on {} {}".format(host.hostname, port)
        return names[0] if names else None
    result = host.command(
        "sonic-db-cli {} CONFIG_DB HGET {} macsec".format(getns_prefix(host, port), shlex.quote("PORT|" + port)),
        module_ignore_errors=True, verbose=False)
    succeeded = not result.get("failed") and result.get("rc") == 0
    assert succeeded, "Unable to inspect configured MACsec binding"
    return result["stdout"].strip() or None


def _eos_interface_stanzas(host):
    """Return all EOS interface stanzas keyed by logical interface name."""
    result = host.eos_command(
        commands=["show running-config section ^interface"],
        module_ignore_errors=True, verbose=False)
    assert not result.get("failed"), \
        "Unable to enumerate EOS interface MACsec bindings"
    output = result["stdout"][0]
    inverse = {
        actual: logical
        for logical, actual in (host.intf_map or {}).items()
    }
    stanzas = {}
    current = None
    for raw_line in output.splitlines():
        if raw_line.startswith("interface "):
            current = inverse.get(
                raw_line.split(None, 1)[1].strip(),
                raw_line.split(None, 1)[1].strip())
            stanzas[current] = []
        elif current is not None and raw_line.strip() == "!":
            current = None
        elif current is not None:
            stanzas[current].append(raw_line.strip())
    return stanzas


def _profile_attachments(host, port, profile_name):
    """Enumerate every interface bound to one profile in its actual scope."""
    if isinstance(host, EosHost):
        attachments = set()
        for interface, lines in _eos_interface_stanzas(host).items():
            profiles = [
                line.split(None, 3)[3]
                for line in lines
                if line.startswith("mac security profile ")
            ]
            assert len(profiles) <= 1, \
                "Multiple MACsec profiles are bound to {} {}".format(
                    host.hostname, interface)
            if profiles and profiles[0] == profile_name:
                attachments.add(interface)
        return attachments

    namespace = getns_prefix(host, port)
    result = host.command(
        "sonic-db-cli {} CONFIG_DB KEYS 'PORT|*'".format(namespace),
        module_ignore_errors=True, verbose=False)
    assert not result.get("failed") and result.get("rc") == 0, \
        "Unable to enumerate SONiC MACsec port bindings"
    keys = [
        key.strip()
        for key in result["stdout"].splitlines()
        if key.strip()
    ]
    attachments = set()
    for key in keys:
        assert key.startswith("PORT|"), \
            "Unexpected CONFIG_DB port key {}".format(key)
        binding = host.command(
            "sonic-db-cli {} CONFIG_DB HGET {} macsec".format(
                namespace, shlex.quote(key)),
            module_ignore_errors=True, verbose=False)
        assert not binding.get("failed") and binding.get("rc") == 0, \
            "Unable to read SONiC MACsec binding {}".format(key)
        if binding["stdout"].strip() == profile_name:
            attachments.add(key.split("|", 1)[1])
    return attachments


def configured_ckns(host, port, name):
    if isinstance(host, EosHost):
        return {line.split()[1].lower() for line in eos_profile(host, name) or [] if line.startswith("key ")}
    fields = profile_fields(host, port, name) or {}
    return {fields[key].lower() for key in ("primary_ckn", "fallback_ckn") if key in fields}


def _expected_ckns(profile):
    return {profile[field].lower() for field in ("primary_ckn", "fallback_ckn") if profile.get(field)}


def _key_pair(profile, role):
    return profile[role + "_cak"], profile[role + "_ckn"]


def _key_identity(profile, role):
    """Compare key material in process; type-7 salts may differ between endpoints."""
    cak, ckn = _key_pair(profile, role)
    return profile["cipher_suite"], ckn.lower(), cisco_type7.decode(cak)


def _profile_scope(host, port, profile):
    namespace = "" if isinstance(host, EosHost) else getns_prefix(host, port).strip()
    return host.hostname, namespace, profile["name"] or ("unbound", port)


def sa_state(host, port):
    """Parse `show macsec <port>`. The output contains SAKs, so it is never logged."""
    output = host.command("show macsec {} {}".format(getns_prefix(host, port), port), verbose=False)["stdout"]
    blocks = [(None, None, {})]
    for line in output.splitlines():
        header = re.search(r"MACsec (Egress|Ingress) (SC|SA) \((\S+)\)", line)
        if header:
            blocks.append((header.group(1, 2), header.group(3), {}))
        else:
            field, _, value = line.strip().partition(" ")
            blocks[-1][2][field] = value.strip()
    port_fields = blocks[0][2]
    encoding_ans = {fields.get("encoding_an") for section, _, fields in blocks if section == ("Egress", "SC")}
    return {
        "bound_profile": port_fields.get("profile"),
        "enabled": port_fields.get("enable") == "true",
        "tx_saks": [fields["sak"] for section, an, fields in blocks
                    if section == ("Egress", "SA") and an in encoding_ans and "sak" in fields],
        "rx_saks": {fields["sak"] for section, _, fields in blocks
                    if section == ("Ingress", "SA") and fields.get("active") == "true" and "sak" in fields},
    }


def get_macsec_link_state(host, port):
    """Return MKA status plus SA state for a SONiC port, or None without an MKA session."""
    state = get_mka_status(host, port)
    if state is not None:
        state.update(sa_state(host, port))
    return state


def _get_principal_ckns(state):
    return sorted(ckn for ckn, participant in state["participants"].items() if participant["principal"])


def get_link_protection_errors(state, profile, principal, require_all_live=True):
    """Return protection errors, or an empty list when the link is secured."""
    errors = get_applied_ckn_errors(state, profile["primary_ckn"], profile["fallback_ckn"])
    if state is None:
        return errors
    principal = principal.lower()
    if state["profile"] != profile["name"]:
        errors.append("bound to profile {}".format(state["profile"]))
    if not state["enabled"] or state["mode"] != "secured" or state["kay"] != "active":
        errors.append("port is not secured")
    if _get_principal_ckns(state) != [principal]:
        errors.append("principals are {}, expected {}".format(_get_principal_ckns(state), principal))
    for ckn in _expected_ckns(profile):
        participant = state["participants"].get(ckn, {})
        # A peerless non-principal participant may be inactive while the other CA protects the link.
        if (require_all_live or ckn == principal) and (not participant.get("active") or participant.get("live", 0) < 1):
            errors.append("{} is not an active participant with a live peer".format(ckn))
    if len(state["tx_saks"]) != 1 or state["tx_saks"][0] not in state["rx_saks"]:
        errors.append("transmit SAK is not active for receive")
    return errors


def get_applied_ckn_errors(state, primary_ckn, fallback_ckn):
    """Return CKN apply errors, or an empty list; peer liveness is not required."""
    if state is None:
        return ["MKA status is missing"]
    errors = []
    if state["config"] != "in-sync":
        errors.append("config is {}".format(state["config"]))
    roles = {ckn: participant.get("role") for ckn, participant in state["participants"].items()}
    if roles != {primary_ckn.lower(): "primary", fallback_ckn.lower(): "fallback"}:
        errors.append("participants are {}".format(roles))
    return errors


def get_link_blocking_errors(state, primary_ckn, fallback_ckn):
    """Return blocking errors, or an empty list when mismatched keys block the link.

    SA objects may be retained and peerless participants may be inactive, so neither is checked.
    """
    errors = get_applied_ckn_errors(state, primary_ckn, fallback_ckn)
    if errors:
        return errors
    if state["mode"] == "secured":
        errors.append("port remains secured")
    if any(participant["live"] for participant in state["participants"].values()):
        errors.append("a participant has a live peer")
    return errors


def _eos_field(mapping, *names):
    """Read the first present field, ignoring case and punctuation in cEOS JSON keys."""
    normalized = {re.sub(r"[^a-z0-9]", "", str(key).lower()): value for key, value in mapping.items()}
    return next((normalized[name] for name in names if normalized.get(name) is not None), None)


def _eos_true(value):
    return str(value).lower() in ("true", "yes", "1")


def eos_participants(host, port):
    """Return {ckn: {active, failed, live, principal}} from `show mac security participants`.

    See the sample in tests/common/devices/arista.py get_macsec_connection_status_details.
    """
    output = host.eos_command(
        commands=["show mac security participants {} detail | json".format(port)])["stdout"][0]
    interfaces = _eos_field(output, "interfaces") or {}
    interface = next((value for name, value in interfaces.items() if name.lower() == port.lower()), {})
    participants = {}
    for ckn, participant in (_eos_field(interface, "participants") or {}).items():
        live = _eos_field(participant, "livepeers", "livepeerlist")
        if live is None:
            live = _eos_field(_eos_field(participant, "details") or {}, "livepeers", "livepeerlist")
        # Either of success/active may be published alone; at least one is required.
        flags = [value for value in (_eos_field(participant, "success"), _eos_field(participant, "active"))
                 if value is not None]
        participants[ckn.lower()] = {
            "active": bool(flags) and all(_eos_true(flag) for flag in flags),
            "failed": _eos_true(_eos_field(participant, "failed", "failure")),
            "principal": _eos_true(_eos_field(participant, "principalactor")),
            "live": len(live) if isinstance(live, (list, dict)) else int(live or 0),
        }
    return participants


def get_peer_protection_errors(env, port, principal, require_all_live=True, profile=None):
    """Return peer protection errors, or an empty list when the peer is secured."""
    profile = profile or env["peer_profiles"][port]
    host, peer_port = env["control_links"][port]["host"], env["control_links"][port]["port"]
    if not isinstance(host, EosHost):
        return get_link_protection_errors(
            get_macsec_link_state(host, peer_port), profile, principal, require_all_live)
    expected = _expected_ckns(profile)
    participants = eos_participants(host, peer_port)
    errors = []
    if not host.iface_macsec_ok(peer_port):
        errors.append("controlled port is closed")
    if configured_ckns(host, peer_port, profile["name"]) != expected:
        errors.append("configured CKNs differ")
    if set(participants) != expected:
        errors.append("participants are {}".format(sorted(participants)))
    principals = sorted(ckn for ckn, participant in participants.items() if participant["principal"])
    if principals != [principal.lower()]:
        errors.append("principals are {}, expected {}".format(principals, principal.lower()))
    for ckn in expected:
        participant = participants.get(ckn, {})
        if (require_all_live or ckn == principal.lower()) and (
                not participant.get("active") or participant.get("failed") or participant.get("live", 0) < 1):
            errors.append("{} is not an active live participant".format(ckn))
    return errors


def get_dut_protection_errors(env, port, principal, require_all_live=True, profile=None):
    """Return DUT protection errors, or an empty list when the port is secured."""
    return get_link_protection_errors(
        get_macsec_link_state(env["duthost"], port),
        profile or env["profiles"][port], principal, require_all_live)


def get_macsec_link_errors(env):
    """Return a mapping of DUT/peer errors; an empty mapping means all links are secured."""
    errors = {}
    for port in env["active_ports"]:
        dut_profile = env["profiles"][port]
        peer_profile = env["peer_profiles"][port]
        errors.update({
            ("dut", port): get_dut_protection_errors(env, port, dut_profile["primary_ckn"]),
            ("peer", port): get_peer_protection_errors(env, port, peer_profile["primary_ckn"]),
        })
    return {key: value for key, value in errors.items() if value}


def wait_until_no_errors(timeout, get_errors, message):
    """Poll a MACsec error list/mapping until empty; report the last errors on timeout."""
    last_errors = None

    def _has_no_errors():
        nonlocal last_errors
        last_errors = get_errors()
        return not last_errors

    assert wait_until(timeout, 2, 0, _has_no_errors), "{}: {}".format(message, last_errors)


def wait_for_primary_macsec_links(env):
    """Wait for all selected DUT and peer links to use the primary CA."""
    wait_until_no_errors(
        MKA_CONVERGE_TIMEOUT,
        lambda: get_macsec_link_errors(env),
        "MACsec links are not secured by the primary CA")


def get_dut_macsec_states(env, ports=None):
    return {port: get_macsec_link_state(env["duthost"], port) for port in ports or env["links"]}


def wait_for_dut_macsec_convergence(env, before, principal, require_rekey=False, require_all_live=True):
    """Wait until each port in *before* is secured by *principal* and stays unchanged for one hello."""
    hello = max(math.ceil(int(state["hello"].split()[0]) / 1000.0) for state in before.values())
    errors = {}

    def _get_macsec_selection_snapshot():
        selection = {}
        for port, previous_state in before.items():
            state = get_macsec_link_state(env["duthost"], port)
            expected_principal = principal[port] if isinstance(principal, dict) else principal
            problems = get_link_protection_errors(state, env["profiles"][port], expected_principal, require_all_live)
            if require_rekey and not problems and state["tx_saks"] == previous_state["tx_saks"]:
                problems.append("transmit SAK did not change")
            if problems:
                errors[port] = problems
                return None
            selection[port] = (state["tx_saks"], _get_principal_ckns(state))
        return selection

    def _is_macsec_selection_stable():
        errors.clear()
        first = _get_macsec_selection_snapshot()
        if first is None:
            return False
        time.sleep(hello)
        if _get_macsec_selection_snapshot() != first:
            errors.setdefault("selection", "changed within one hello interval")
            return False
        return True

    # Allow three hellos for selection to settle before checking.
    assert wait_until(SA_RETIRE_TIMEOUT + MKA_TIMEOUT, 1, 3 * hello, _is_macsec_selection_stable), \
        "DUT did not settle on {}: {}".format(principal, errors)


def verify_periodic_rekey(env, port):
    """Require a periodic SAK refresh while the configured CKNs and primary selection stay unchanged."""
    duthost = env["duthost"]
    profile = env["profiles"][port]
    assert configured_ckns(duthost, port, profile["name"]) == _expected_ckns(profile)
    initial_tx_saks = None
    key_server_period = None

    def _capture_initial_tx_saks():
        nonlocal initial_tx_saks, key_server_period
        state = get_macsec_link_state(duthost, port)
        if get_link_protection_errors(state, profile, profile["primary_ckn"]):
            return False
        initial_tx_saks = state["tx_saks"]
        key_server_period = get_key_server_rekey_period(env, port, state)
        assert key_server_period > 0, "The current MACsec key server has periodic rekey disabled"
        return True

    def _has_new_protected_tx_sak():
        state = get_macsec_link_state(duthost, port)
        if get_link_protection_errors(state, profile, profile["primary_ckn"]):
            return False
        return state["tx_saks"] != initial_tx_saks

    assert wait_until(MKA_TIMEOUT, 1, 0, _capture_initial_tx_saks), \
        "{} is not secured by the primary".format(port)
    assert wait_until(max(MKA_CONVERGE_TIMEOUT, key_server_period + MKA_TIMEOUT),
                      1, 0, _has_new_protected_tx_sak), \
        "No periodic SAK refresh on {} with unchanged CKNs".format(port)
    assert configured_ckns(duthost, port, profile["name"]) == _expected_ckns(profile)


def get_key_server_rekey_period(env, port, status):
    assert status is not None, "MACsec key-server selection is unavailable"
    role = status["local_key_server"].lower()
    assert role in ("true", "false"), "MACsec key-server selection is unavailable"
    return (env["profiles"][port] if role == "true" else env["peer_profiles"][port])["rekey_period"]


def configure_eos_key(host, name, key, fallback=False, remove=False):
    cak, ckn = key
    result = host.eos_config(
        lines=["{}key {} 7 {}{}".format("no " if remove else "", ckn, cak, " fallback" if fallback else "")],
        parents=["mac security", "profile {}".format(name)], module_ignore_errors=True, verbose=False)
    succeeded = not result.get("failed")
    assert succeeded, "Unable to configure EOS MACsec key"


def get_profile_operations(env, ports=None, side=None):
    """Return each affected host/profile/namespace once, with its effective keys."""
    operations = {}
    for port in env["active_ports"] if ports is None else ports:
        if side != "peer":
            profile = env["profiles"][port]
            host = env["duthost"]
            operations.setdefault(_profile_scope(host, port, profile), (host, port, profile))
        if side != "dut":
            neighbor = env["control_links"][port]
            profile = env["peer_profiles"][port]
            host, peer_port = neighbor["host"], neighbor["port"]
            operations.setdefault(_profile_scope(host, peer_port, profile), (host, peer_port, profile))
    return list(operations.values())


def replace_profile_key(operation, role, replacement):
    host, port, profile = operation
    update_macsec_profile_key(
        host, profile["name"], *_key_pair(profile, role), *replacement,
        is_fallback=role == "fallback", namespace_option=getns_prefix(host, port))
    profile[role + "_cak"], profile[role + "_ckn"] = replacement


def restore_profile_key(operation, role, original, replacement):
    host, port, profile = operation
    configured = configured_ckns(host, port, profile["name"])
    if replacement[1].lower() in configured:
        update_macsec_profile_key(
            host, profile["name"], *replacement, *original, is_fallback=role == "fallback",
            namespace_option=getns_prefix(host, port))
    elif isinstance(host, EosHost) and original[1].lower() not in configured:
        configure_eos_key(host, profile["name"], original, fallback=role == "fallback")
    else:
        assert original[1].lower() in configured, "Original MACsec CKN is missing"
    profile[role + "_cak"], profile[role + "_ckn"] = original


# ---------------------------------------------------------------------------
# Neighbor-to-neighbor transit traffic through the DUT
# ---------------------------------------------------------------------------

def _netns_prefix(host, port):
    if isinstance(host, EosHost):
        return "sudo ip netns exec ns-{}".format(host.bgp_vrf) if host.bgp_vrf else ""
    return get_ipnetns_prefix(host, port)


def run_in_port_namespace(host, port, command, check=True):
    """Run *command* in the data-plane namespace of *port*; return stdout."""
    result = host.command(
        "{} {}".format(_netns_prefix(host, port), command).strip(),
        module_ignore_errors=not check, verbose=False)
    return result.get("stdout", "").strip()


def _route_field(route, field):
    words = route.split()
    return words[words.index(field) + 1] if field in words[:-1] else None


def route_ok(host, port, source, destination, gateway, device):
    """Check that *host* sends source->destination via *gateway* on *device* without ECMP."""
    route = run_in_port_namespace(host, port, "ip -4 route get {} from {}".format(destination, source), check=False)
    return (_route_field(route, "via") == gateway and _route_field(route, "dev") == device
            and "nexthop" not in route.split())


def dut_route_ok(duthost, in_port, out_port, source, destination, via=None):
    """Check that the DUT forwards source->destination from *in_port* out of *out_port* only."""
    portchannels = get_portchannel(duthost)
    in_dev, out_dev = ((find_portchannel_from_member(p, portchannels) or {"name": p})["name"]
                       for p in (in_port, out_port))
    route = run_in_port_namespace(
        duthost, out_port, "ip -4 route get {} from {} iif {}".format(destination, source, in_dev),
        check=False)
    return (_route_field(route, "dev") == out_dev and _route_field(route, "via") == via
            and "nexthop" not in route.split())


def _route_entries(output, prefix):
    """Return one prefix's FRR JSON entries, or an empty list."""
    try:
        routes = json.loads(output or "{}")
    except ValueError as error:
        raise AssertionError(
            "Unable to parse route state for {}".format(prefix)) from error
    return routes.get(prefix, [])


def _static_nexthops(entries):
    """Return {(gateway, interface)} for every configured static route path."""
    paths = set()
    for entry in entries:
        if entry.get("protocol") != "static":
            continue
        for nexthop in entry.get("nexthops", []):
            paths.add((
                nexthop.get("ip"),
                nexthop.get("interfaceName")))
    return paths


def _sonic_route_entries(host, port, prefix):
    output = run_in_port_namespace(
        host, port,
        "vtysh -c {}".format(
            shlex.quote("show ip route {} json".format(prefix))))
    return _route_entries(output, prefix)


def _asic_route_entries(asic, prefix):
    result = asic.run_vtysh(
        "-c {}".format(
            shlex.quote("show ip route {} json".format(prefix))))
    return _route_entries(result["stdout"], prefix)


def _eos_route_state(host, prefix):
    result = host.eos_command(
        commands=["show ip route {} | json".format(prefix)],
        module_ignore_errors=True, verbose=False)
    assert not result.get("failed"), \
        "Unable to inspect EOS route {}".format(prefix)
    output = result["stdout"][0]
    vrfs = output.get("vrfs", {}) if isinstance(output, dict) else {}
    if vrfs:
        vrf = host.bgp_vrf or "default"
        return (
            vrfs.get(vrf, {})
            .get("routes", {})
            .get(prefix, {})
        )
    return output.get("routes", {}).get(prefix, {}) \
        if isinstance(output, dict) else {}


def _eos_static_nexthops(host, prefix):
    result = host.eos_command(
        commands=["show running-config | include ^ip route"],
        module_ignore_errors=True, verbose=False)
    assert not result.get("failed"), \
        "Unable to inspect EOS static routes"
    expected_vrf = host.bgp_vrf
    nexthops = set()
    for line in result["stdout"][0].splitlines():
        fields = line.split()
        if fields[:2] != ["ip", "route"]:
            continue
        index = 2
        vrf = None
        if fields[index:index + 1] == ["vrf"]:
            assert len(fields) >= 6, "Malformed EOS static route"
            vrf = fields[index + 1]
            index += 2
        if vrf != expected_vrf or len(fields) <= index + 1:
            continue
        if fields[index] == prefix:
            nexthops.add((fields[index + 1], None))
    return nexthops


def _peer_static_nexthops(host, port, prefix):
    if isinstance(host, EosHost):
        return _eos_static_nexthops(host, prefix)
    return _static_nexthops(
        _sonic_route_entries(host, port, prefix))


def _peer_route_nexthops(host, port, prefix):
    if isinstance(host, EosHost):
        route = _eos_route_state(host, prefix)
        return {
            (via.get("nexthopAddr"), via.get("interface"))
            for via in route.get("vias", [])
            if via.get("nexthopAddr")
        }
    return {
        (nexthop.get("ip"), nexthop.get("interfaceName"))
        for entry in _sonic_route_entries(host, port, prefix)
        for nexthop in entry.get("nexthops", [])
        if nexthop.get("active", True)
    }


def _add_peer_static_route(
        host, port, prefix, source, gateway, device):
    if isinstance(host, EosHost):
        vrf = "vrf {} ".format(host.bgp_vrf) if host.bgp_vrf else ""
        host.eos_config(
            lines=[
                "ip route {}{} {}".format(
                    vrf, prefix, gateway)])
        return
    run_in_port_namespace(
        host, port,
        "vtysh -c {} -c {}".format(
            shlex.quote("configure terminal"),
            shlex.quote(
                "ip route {} {} {}".format(
                    prefix, gateway, device))))


def _remove_peer_static_route(
        host, port, prefix, source, gateway, device):
    if isinstance(host, EosHost):
        vrf = "vrf {} ".format(host.bgp_vrf) if host.bgp_vrf else ""
        host.eos_config(
            lines=[
                "no ip route {}{} {}".format(
                    vrf, prefix, gateway)])
        return
    run_in_port_namespace(
        host, port,
        "vtysh -c {} -c {}".format(
            shlex.quote("configure terminal"),
            shlex.quote(
                "no ip route {} {} {}".format(
                    prefix, gateway, device))))


def _directions(env, port):
    other = next(p for p in env["links"] if p != port)
    return ((port, other), (other, port))


@contextmanager
def transit_path(env, port):
    """Pin each neighbor's /32 to the other neighbor's link address through the DUT."""
    duthost, upstream = env["duthost"], env["upstream_links"]
    endpoints = []
    for src_port, dst_port in _directions(env, port):
        nbr = env["links"][src_port]
        source = upstream[src_port]["local_ipv4_addr"]
        destination = upstream[dst_port]["local_ipv4_addr"]
        gateway = upstream[src_port]["peer_ipv4_addr"]
        device = _route_field(
            run_in_port_namespace(nbr["host"], nbr["port"], "ip -4 route get {} from {}".format(gateway, source)),
            "dev")
        if not device or not dut_route_ok(duthost, src_port, dst_port, source, destination):
            pytest.skip("No direct protected DUT path from {} to {}".format(src_port, dst_port))
        endpoints.append((nbr["host"], nbr["port"], source, destination, gateway, device))

    with ExitStack() as cleanup:
        for host, nbr_port, source, destination, gateway, device in endpoints:
            if route_ok(host, nbr_port, source, destination, gateway, device):
                continue
            if run_in_port_namespace(host, nbr_port, "ip -4 route show exact {}/32".format(destination)):
                pytest.skip("Existing /32 route to {} on {}".format(destination, host.hostname))
            route = "{}/32 via {} dev {}".format(destination, gateway, device)
            run_in_port_namespace(host, nbr_port, "sudo ip -4 route add {} src {}".format(route, source))
            cleanup.callback(run_in_port_namespace, host, nbr_port, "sudo ip -4 route del {}".format(route))
        assert all(route_ok(*endpoint) for endpoint in endpoints), "Transit routes do not go through the DUT"
        yield endpoints


def data_loopback(nbr):
    output = run_in_port_namespace(nbr["host"], nbr["port"], "ip -o -4 addr show")
    addresses = {address for device, address in re.findall(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/32\b", output, re.M)
                 if (device in ("lo", "lo0") or device.startswith("Loopback"))
                 and not ipaddress.ip_address(address).is_loopback}
    if len(addresses) != 1:
        pytest.skip("{} has no unique data-plane /32 loopback".format(nbr["host"].hostname))
    return addresses.pop()


@contextmanager
def stable_transit_path(env, port):
    """Route between the two neighbors' data loopbacks through the DUT.

    Link addresses can be withdrawn when MACsec goes down, which would turn the blocked-traffic
    check into a local route error. Loopbacks keep it a real no-forwarding check.
    """
    duthost, upstream = env["duthost"], env["upstream_links"]
    asic = duthost.get_port_asic_instance(port)
    loopbacks = {p: data_loopback(env["links"][p]) for p in env["links"]}
    if len(set(loopbacks.values())) != 2:
        pytest.skip("Neighbor data loopbacks are not distinct")
    endpoints, dut_routes = [], []
    for src_port, dst_port in _directions(env, port):
        nbr = env["links"][src_port]
        gateway = upstream[src_port]["peer_ipv4_addr"]
        destination = loopbacks[dst_port]
        route = run_in_port_namespace(
            nbr["host"], nbr["port"], "ip -4 route get {} from {}".format(gateway, loopbacks[src_port]))
        if _route_field(route, "via") or not _route_field(route, "dev"):
            pytest.skip("{} loopback cannot reach its DUT gateway directly".format(nbr["host"].hostname))
        endpoints.append((nbr["host"], nbr["port"], loopbacks[src_port], destination, gateway,
                          _route_field(route, "dev")))
        dut_routes.append((
            src_port, dst_port, "{}/32".format(destination),
            upstream[dst_port]["local_ipv4_addr"]))

    expected_peer_routes = []
    for endpoint in endpoints:
        host, nbr_port, source, destination, gateway, device = endpoint
        prefix = "{}/32".format(destination)
        if not route_ok(*endpoint):
            pytest.skip(
                "Existing route to {} is not a single protected path".format(
                    destination))
        static_paths = _peer_static_nexthops(
            host, nbr_port, prefix)
        route_paths = _peer_route_nexthops(
            host, nbr_port, prefix)
        if len(route_paths) != 1 or not any(
                route_gateway == gateway
                and route_interface in (None, device)
                for route_gateway, route_interface in route_paths):
            pytest.skip(
                "Existing route to {} is ECMP or unprotected".format(
                    destination))
        if static_paths and not any(
                static_gateway == gateway
                and static_interface in (None, device)
                for static_gateway, static_interface in static_paths):
            pytest.skip(
                "Existing static route to {} is incompatible".format(
                    destination))
        if len(static_paths) > 1:
            pytest.skip(
                "Existing static route to {} is ECMP".format(
                    destination))
        expected_peer_routes.append(
            (endpoint, prefix, bool(static_paths)))

    expected_dut_routes = []
    for in_port, out_port, prefix, nexthop in dut_routes:
        if not dut_route_ok(
                duthost, in_port, out_port,
                loopbacks[in_port], loopbacks[out_port],
                via=nexthop):
            pytest.skip(
                "Existing DUT route to {} is not a single protected path".format(
                    prefix))
        static_paths = _static_nexthops(
            _asic_route_entries(asic, prefix))
        route_paths = {
            (path.get("ip"), path.get("interfaceName"))
            for entry in _asic_route_entries(asic, prefix)
            for path in entry.get("nexthops", [])
            if path.get("active", True)
        }
        if len(route_paths) != 1 or not any(
                gateway == nexthop
                for gateway, _ in route_paths):
            pytest.skip(
                "Existing DUT route to {} is ECMP or unprotected".format(
                    prefix))
        if static_paths and not any(
                gateway == nexthop
                for gateway, _ in static_paths):
            pytest.skip(
                "Existing DUT static route to {} is incompatible".format(
                    prefix))
        if len(static_paths) > 1:
            pytest.skip(
                "Existing DUT static route to {} is ECMP".format(
                    prefix))
        expected_dut_routes.append(
            (in_port, out_port, prefix, nexthop, bool(static_paths)))

    def _routes_ok():
        return (
            all(
                dut_route_ok(
                    duthost, in_port, out_port,
                    loopbacks[in_port], loopbacks[out_port],
                    via=nexthop)
                for in_port, out_port, _, nexthop, _ in
                expected_dut_routes)
            and all(
                route_ok(*endpoint)
                for endpoint, _, _ in expected_peer_routes))

    def _pins_ok():
        return (
            all(
                any(
                    gateway == nexthop
                    for gateway, _ in _static_nexthops(
                        _asic_route_entries(asic, prefix)))
                for _, _, prefix, nexthop, _ in
                expected_dut_routes)
            and all(
                any(
                    static_gateway == endpoint[4]
                    and static_interface in (
                        None, endpoint[5])
                    for static_gateway, static_interface in
                    _peer_static_nexthops(
                        endpoint[0], endpoint[1], prefix))
                for endpoint, prefix, _ in expected_peer_routes))

    with ExitStack() as cleanup:
        for _, _, prefix, nexthop, existed in expected_dut_routes:
            if existed:
                continue
            asic.run_vtysh("-c 'configure terminal' -c 'ip route {} {}'".format(prefix, nexthop))
            cleanup.callback(asic.run_vtysh, "-c 'configure terminal' -c 'no ip route {} {}'".format(prefix, nexthop))
        for endpoint, prefix, existed in expected_peer_routes:
            if existed:
                continue
            _add_peer_static_route(
                endpoint[0], endpoint[1], prefix,
                endpoint[2], endpoint[4], endpoint[5])
            cleanup.callback(
                _remove_peer_static_route,
                endpoint[0], endpoint[1], prefix,
                endpoint[2], endpoint[4], endpoint[5])
        assert wait_until(
            90, 2, 0,
            lambda: _routes_ok() and _pins_ok()), \
            "Protected static route pins are not programmed"
        yield {
            "endpoints": endpoints,
            "routes_ok": _routes_ok,
        }


def ping_transit_endpoint(endpoint):
    """Return whether three pings from one neighbor reach the other through the DUT."""
    host, port, source, destination = endpoint[:4]
    result = host.command("{} ping -c 3 -I {} {}".format(_netns_prefix(host, port), source, destination).strip(),
                          module_ignore_errors=True, verbose=False)
    if result["rc"] == 2 and "Network is unreachable" in result.get("stderr", ""):
        return False
    assert result["rc"] in (0, 1), "Transit ping did not run on {}: {}".format(host.hostname, result.get("stderr"))
    return result["rc"] == 0


def _namespace_shell(host, port, command):
    prefix = _netns_prefix(host, port)
    if prefix:
        return "{} sh -c {}".format(
            prefix, shlex.quote(command))
    return "sudo sh -c {}".format(shlex.quote(command))


def observe_transit_requests(
        endpoints, routes_ok, window, expect_requests,
        capability_probe=False):
    """Count exact ICMP echo requests received at both destinations."""
    if any(isinstance(endpoint[0], EosHost) for endpoint in endpoints):
        pytest.skip(
            "Both-invalid request capture requires SONiC neighbors")

    def _capture_alive(capture):
        result = capture["capture_host"].command(
            _namespace_shell(
                capture["capture_host"], capture["capture_port"],
                "kill -0 {}".format(capture["pid"])),
            module_ignore_errors=True, verbose=False)
        return not result.get("failed") and result.get("rc") == 0

    def _capture_stopped(capture):
        result = capture["capture_host"].command(
            _namespace_shell(
                capture["capture_host"], capture["capture_port"],
                "test ! -d /proc/{}".format(capture["pid"])),
            module_ignore_errors=True, verbose=False)
        return not result.get("failed") and result.get("rc") == 0

    token = uuid.uuid4().hex[:12]
    captures = []
    errors = []
    try:
        for direction, source_endpoint in enumerate(endpoints):
            destination_endpoint = endpoints[1 - direction]
            source_host, source_port, source = source_endpoint[:3]
            destination = source_endpoint[3]
            capture_host, capture_port = destination_endpoint[:2]
            capture_device = destination_endpoint[5]
            identifier = int(uuid.uuid4().hex[:4], 16) or 1
            remote_base = "/tmp/macsec_block_{}_{}".format(
                token, direction)
            pcap = remote_base + ".pcap"
            stats = remote_base + ".stats"
            packet_filter = (
                "icmp and src host {source} and dst host {destination} "
                "and icmp[icmptype] = icmp-echo and icmp[4:2] = {identifier}"
            ).format(
                source=source, destination=destination,
                identifier=identifier)

            source_capability = source_host.command(
                _namespace_shell(
                    source_host, source_port,
                    "ping -h 2>&1 | grep -q -- '-e <identifier>'"),
                module_ignore_errors=True, verbose=False)
            capture_capability = capture_host.command(
                _namespace_shell(
                    capture_host, capture_port,
                    "command -v tcpdump && command -v timeout"),
                module_ignore_errors=True, verbose=False)
            if (
                    source_capability.get("failed")
                    or source_capability.get("rc") != 0
                    or capture_capability.get("failed")
                    or capture_capability.get("rc") != 0):
                if capability_probe:
                    pytest.skip(
                        "Both-invalid request capture tools are unavailable")
                raise AssertionError(
                    "Both-invalid request capture capability disappeared")

            command = (
                "rm -f {pcap} {stats}; "
                "nohup timeout --foreground --signal=INT 30 "
                "tcpdump -U -n -s 96 -i {device} -w {pcap} {filter} "
                ">/dev/null 2>{stats} </dev/null & echo $!"
            ).format(
                pcap=shlex.quote(pcap),
                stats=shlex.quote(stats),
                device=shlex.quote(capture_device),
                filter=shlex.quote(packet_filter))
            result = capture_host.command(
                _namespace_shell(
                    capture_host, capture_port, command),
                module_ignore_errors=True, verbose=False)
            assert (
                not result.get("failed")
                and result.get("rc") == 0
                and result.get("stdout_lines")
                and result["stdout_lines"][-1].strip().isdigit()), \
                "Unable to start both-invalid request capture"
            capture = {
                "direction": direction,
                "source_host": source_host,
                "source_port": source_port,
                "source": source,
                "destination": destination,
                "capture_host": capture_host,
                "capture_port": capture_port,
                "capture_device": capture_device,
                "identifier": identifier,
                "pcap": pcap,
                "stats": stats,
                "filter": packet_filter,
                "pid": int(result["stdout_lines"][-1].strip()),
            }
            captures.append(capture)

            def _capture_ready(c=capture):
                result = c["capture_host"].command(
                    _namespace_shell(
                        c["capture_host"], c["capture_port"],
                        (
                            "kill -0 {pid} && test -e {pcap} "
                            "&& grep -q 'listening on ' {stats}"
                        ).format(
                            pid=c["pid"],
                            pcap=shlex.quote(c["pcap"]),
                            stats=shlex.quote(c["stats"]))),
                    module_ignore_errors=True, verbose=False)
                return not result.get("failed") and result.get("rc") == 0

            assert wait_until(15, 1, 0, _capture_ready), \
                "Both-invalid request capture did not become ready"

        assert routes_ok(), \
            "Protected routes are missing before request transmission"
        assert all(_capture_alive(capture) for capture in captures), \
            "Both-invalid request capture stopped before transmission"
        for capture in captures:
            result = capture["source_host"].command(
                _namespace_shell(
                    capture["source_host"], capture["source_port"],
                    "ping -n -c 3 -W 1 -i 0.2 -e {identifier} "
                    "-I {source} {destination}".format(**capture)),
                module_ignore_errors=True, verbose=False)
            output = "{}\n{}".format(
                result.get("stdout", ""),
                result.get("stderr", ""))
            assert result.get("rc") in (0, 1), \
                "Both-invalid request transmission did not run"
            match = re.search(
                r"(\d+) packets transmitted", output)
            assert match and int(match.group(1)) == 3, \
                "Both-invalid request transmission count is unavailable"
            assert all(_capture_alive(c) for c in captures), \
                "Both-invalid request capture stopped during transmission"
        assert routes_ok(), \
            "Protected routes disappeared during request transmission"
    finally:
        for capture in captures:
            stopped = False
            try:
                removal = capture["capture_host"].command(
                    _namespace_shell(
                        capture["capture_host"],
                        capture["capture_port"],
                        "kill -INT {}".format(capture["pid"])),
                    module_ignore_errors=True, verbose=False)
                stopped = wait_until(
                    15, 1, 0, _capture_stopped, capture)
                if not stopped:
                    capture["capture_host"].command(
                        _namespace_shell(
                            capture["capture_host"],
                            capture["capture_port"],
                            "kill -TERM {}".format(capture["pid"])),
                        module_ignore_errors=True, verbose=False)
                    stopped = wait_until(
                        5, 1, 0, _capture_stopped, capture)
                if not stopped:
                    errors.append(
                        "capture PID {} did not stop".format(
                            capture["pid"]))
                    continue
                readback = capture["capture_host"].command(
                    _namespace_shell(
                        capture["capture_host"],
                        capture["capture_port"],
                        "test -s {pcap} && "
                        "tcpdump -nn -r {pcap} {filter} "
                        "2>/dev/null".format(
                            pcap=shlex.quote(capture["pcap"]),
                            filter=shlex.quote(capture["filter"]))),
                    module_ignore_errors=True, verbose=False)
                if (
                        readback.get("failed")
                        or readback.get("rc") != 0):
                    errors.append(
                        "capture readback failed for direction {}".format(
                            capture["direction"]))
                    continue
                capture["requests_received"] = len([
                    line for line in
                    readback["stdout"].splitlines()
                    if line.strip()
                ])
                stats = capture["capture_host"].command(
                    _namespace_shell(
                        capture["capture_host"],
                        capture["capture_port"],
                        "cat {}".format(
                            shlex.quote(capture["stats"]))),
                    module_ignore_errors=True, verbose=False)
                dropped = re.search(
                    r"(\d+) packets dropped by kernel",
                    stats.get("stdout", ""))
                if (
                        stats.get("failed")
                        or stats.get("rc") != 0
                        or dropped is None
                        or int(dropped.group(1)) != 0):
                    errors.append(
                        "capture counters are incomplete for direction {}".format(
                            capture["direction"]))
                if removal.get("failed") or removal.get("rc") != 0:
                    errors.append(
                        "capture cleanup failed for direction {}".format(
                            capture["direction"]))
            except BaseException as error:
                errors.append(
                    "capture cleanup failed for direction {}: {}".format(
                        capture["direction"], error))
            finally:
                if stopped:
                    try:
                        result = capture["capture_host"].command(
                            _namespace_shell(
                                capture["capture_host"], capture["capture_port"],
                                "rm -f {} {}".format(
                                    shlex.quote(capture["pcap"]),
                                    shlex.quote(capture["stats"]))),
                            module_ignore_errors=True, verbose=False)
                        if result.get("failed") or result.get("rc") != 0:
                            errors.append(
                                "capture file cleanup failed for direction {}".format(
                                    capture["direction"]))
                    except BaseException as error:
                        errors.append(
                            "capture file cleanup failed for direction {}: {}".format(
                                capture["direction"], error))
        assert not errors, "; ".join(errors)

    counts = [
        capture["requests_received"]
        for capture in sorted(
            captures, key=lambda item: item["direction"])
    ]
    logger.info(
        "Both-invalid %s request reception IDs/counts: %s",
        window, [
            (capture["identifier"], capture["requests_received"])
            for capture in sorted(
                captures, key=lambda item: item["direction"])
        ])
    if capability_probe and any(count == 0 for count in counts):
        pytest.skip(
            "Selected neighbor capture points cannot observe plaintext "
            "test ICMP requests in both directions")
    if expect_requests:
        assert all(count > 0 for count in counts), \
            "{} did not receive requests in both directions: {}".format(
                window, counts)
    else:
        assert counts == [0, 0], \
            "{} forwarded requests: {}".format(window, counts)
    return counts


def replies(ping):
    output = ping["host"].shell("cat {}".format(ping["path"]), verbose=False)["stdout"]
    return {int(seq) for seq in PING_REPLY.findall(output)}


def ping_running(ping):
    return not ping["host"].shell("sudo kill -0 {}".format(ping["pid"]), module_ignore_errors=True)["failed"]


def stop_ping(ping):
    """Drain post-transition replies, stop the ping and return (missing sequences, last sequence)."""
    assert ping_running(ping), "Ping on {} exited during the measured window".format(ping["host"].hostname)
    target = max(max(replies(ping), default=0) + 3, 10)
    seen = {}

    def _drained():
        seen["replies"] = replies(ping)
        return ping_running(ping) and max(seen["replies"], default=0) >= target

    drained = wait_until(15, 1, 0, _drained)
    end = max(seen["replies"], default=0)
    ping["host"].shell("sudo kill -INT {}".format(ping["pid"]))
    ping["stopped"] = True
    assert wait_until(15, 1, 0, lambda: not ping_running(ping)), "Ping did not exit after SIGINT"
    received = replies(ping)
    assert drained, "Ping on {} did not reach sequence {} after the transition".format(ping["host"].hostname, target)
    return sorted(set(range(ping["start"] + 1, end + 1)) - received), end


@contextmanager
def transit_traffic(endpoints):
    """Run a 10 Hz ping in each direction; yield once each has ten replies."""
    for endpoint in endpoints:
        assert ping_transit_endpoint(endpoint), "Transit path from {} is not healthy".format(endpoint[0].hostname)
    pings = []
    try:
        for index, (host, port, source, destination, _, _) in enumerate(endpoints):
            path = "/tmp/macsec_fallback_ping_{}.log".format(index)
            pid = host.shell("rm -f {0}; nohup {1} ping -D -i 0.1 -I {2} {3} > {0} 2>&1 < /dev/null & echo $!".format(
                path, _netns_prefix(host, port), source, destination))["stdout_lines"][-1]
            ping = {"host": host, "path": path, "pid": int(pid)}
            pings.append(ping)
            assert wait_until(15, 1, 0, lambda: ping_running(ping) and len(replies(ping)) >= 10), \
                "Ping from {} did not start".format(host.hostname)
            ping["start"] = max(replies(ping))
        yield pings
    finally:
        for ping in pings:
            if not ping.get("stopped"):
                ping["host"].shell("sudo kill -INT {}".format(ping["pid"]), module_ignore_errors=True)
            ping["host"].shell("rm -f {}".format(ping["path"]), module_ignore_errors=True)


def assert_no_loss(pings):
    """Close the measured window: every probe sent after the start boundary must be answered."""
    for ping in pings:
        missing, end = stop_ping(ping)
        assert end - ping["start"] >= 10, "Too few probes in the measured window"
        assert not missing, "{} lost {} probes: {}".format(ping["host"].hostname, len(missing), missing[:50])


def verify_hitless_cak_rotation(env, role, verify_rekey=False):
    """Replace one CAK on the DUT, then on both peers, inside a zero-loss transit window.

    The operator stages this rotation so the other CA stays live on every link. macsecmgrd
    does not guarantee hitless updates; this checks the staged end-to-end behaviour.
    """
    duthost = env["duthost"]
    selected_dut_port = next(iter(env["links"]))
    operations = get_profile_operations(env)
    replacements = {}
    changes = []
    for operation in operations:
        host, port, profile = operation
        original = _key_pair(profile, role)
        key_identity = _key_identity(profile, role)
        if key_identity not in replacements:
            replacements[key_identity] = generate_cak_ckn_pair(profile["cipher_suite"])
        changes.append((operation, original, replacements[key_identity]))

    def _get_peer_convergence_errors():
        peer_errors = []
        for dut_port in env["active_ports"]:
            profile = env["peer_profiles"][dut_port]
            errors = get_peer_protection_errors(env, dut_port, profile["primary_ckn"])
            if errors:
                peer_errors.append((dut_port, errors))
        return peer_errors

    try:
        with transit_path(env, selected_dut_port) as endpoints, transit_traffic(endpoints) as pings:
            if verify_rekey:
                verify_periodic_rekey(env, selected_dut_port)
            before = get_dut_macsec_states(env, env["active_ports"])
            for operation, original, replacement in changes:
                if operation[0] is duthost:
                    replace_profile_key(operation, role, replacement)
            if role == "primary":
                # Peers still have the old primary, so the DUT first moves to the fallback CA.
                wait_for_dut_macsec_convergence(
                    env, before, {port: env["profiles"][port]["fallback_ckn"] for port in before},
                    require_all_live=False)
                before = get_dut_macsec_states(env, env["active_ports"])
            for operation, original, replacement in changes:
                if operation[0] is not duthost:
                    replace_profile_key(operation, role, replacement)
            wait_for_dut_macsec_convergence(
                env, before, {port: env["profiles"][port]["primary_ckn"] for port in before},
                require_rekey=role == "primary")
            # One budget shared by all peers.
            wait_until_no_errors(
                30 + 15 * len(env["active_ports"]), _get_peer_convergence_errors, "Peers did not converge")
            for dut_port in env["active_ports"]:
                assert not get_dut_protection_errors(env, dut_port, env["profiles"][dut_port]["primary_ckn"]), \
                    "DUT {} regressed".format(dut_port)
            if verify_rekey:
                verify_periodic_rekey(env, selected_dut_port)
            assert_no_loss(pings)
    finally:
        with ExitStack() as cleanup:
            for operation, original, replacement in reversed(changes):
                cleanup.callback(restore_profile_key, operation, role, original, replacement)
        wait_for_primary_macsec_links(env)


def create_unattached_profile(env, name, fallback=True):
    """Create *name* on the DUT and return its (primary, fallback) keys."""
    profile = env["profile"]
    primary = generate_cak_ckn_pair(profile["cipher_suite"])
    fallback_key = generate_cak_ckn_pair(profile["cipher_suite"])
    set_macsec_profile(
        env["duthost"], name, profile["priority"], profile["cipher_suite"], *primary,
        profile["policy"], profile["send_sci"], REKEY_PERIOD, *(fallback_key if fallback else ()))
    return primary, fallback_key


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

def get_fallback_routed_links(
        duthost, tbinfo, ctrl_links, upstream_links):
    """Recover routed controlled peers for regional topologies locally."""
    if tbinfo["topo"]["type"] not in ("lrh", "urh"):
        return upstream_links

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    neighbors = mg_facts.get("minigraph_neighbors", {})
    bgp = mg_facts.get("minigraph_bgp", [])
    routed = dict(upstream_links)
    for dut_port, controlled in ctrl_links.items():
        if dut_port in routed:
            continue
        neighbor = neighbors.get(dut_port)
        if not neighbor or neighbor.get("name") != controlled["name"]:
            continue
        sessions = [
            session for session in bgp
            if session.get("name") == controlled["name"]
            and isinstance(
                ipaddress.ip_address(session["addr"]),
                ipaddress.IPv4Address)
        ]
        if len(sessions) != 1:
            continue
        session = sessions[0]
        if not session.get("peer_addr"):
            continue
        routed[dut_port] = {
            "name": controlled["name"],
            "host": controlled["host"],
            "port": neighbor["port"],
            "local_ipv4_addr": session["addr"],
            "peer_ipv4_addr": session["peer_addr"],
        }
    return routed


def select_pair(duthost, ctrl_links, upstream_links):
    """Pick two same-ASIC links to distinct routed neighbors, preferring cEOS peers."""
    portchannels = get_portchannel(duthost)
    eligible = [port for port in ctrl_links if port in upstream_links and len(
        (find_portchannel_from_member(port, portchannels) or {"members": [port]})["members"]) == 1]
    eligible.sort(key=lambda port: not isinstance(ctrl_links[port]["host"], EosHost))
    for port in eligible:
        for other in eligible:
            if (other != port and ctrl_links[other]["name"] != ctrl_links[port]["name"]
                    and upstream_links[other]["local_ipv4_addr"] != upstream_links[port]["local_ipv4_addr"]
                    and getns_prefix(duthost, other) == getns_prefix(duthost, port)):
                return {port: ctrl_links[port], other: ctrl_links[other]}
    return pytest.skip(
        "Need two same-ASIC MACsec links to distinct routed neighbors, each direct or a 1-member PortChannel")


def get_bound_profile_settings(host, port, candidates):
    """Read the bound or explicitly selected installed profile, never unrelated candidates."""
    name = bound_profile(host, port)
    originally_bound = name is not None
    if name is None:
        name = candidates[0]["name"]
    fields = eos_profile(host, name) if isinstance(host, EosHost) else profile_fields(host, port, name)
    if fields is None:
        assert not originally_bound, "Bound MACsec profile is missing"
        return dict(candidates[0], name=None)
    ck_names = ({line.split()[1].lower() for line in fields if line.startswith("key ")}
                if isinstance(host, EosHost) else {
                    fields[key].lower() for key in ("primary_ckn", "fallback_ckn") if key in fields})
    matches = [candidate for candidate in candidates if _expected_ckns(candidate) == ck_names]
    profile = dict(matches[0] if matches else candidates[0], name=name)
    for field in ("primary_cak", "primary_ckn", "fallback_cak", "fallback_ckn"):
        profile.pop(field, None)
    if isinstance(host, EosHost):
        keys = [line.split() for line in fields if line.startswith("key ")]
        for key in keys:
            supported_format = len(key) in (4, 5) and key[2] == "7"
            assert supported_format, "Unsupported EOS MACsec key configuration"
            supported_role = len(key) == 4 or key[4] == "fallback"
            assert supported_role, "Unsupported EOS MACsec key role"
            role = "fallback" if len(key) == 5 and key[4] == "fallback" else "primary"
            profile[role + "_ckn"] = key[1]
            profile[role + "_cak"] = key[3]
        priority = [line.split()[-1] for line in fields if line.startswith("mka key-server priority ")]
        period = [line.split()[-1] for line in fields if line.startswith("mka session rekey-period ")]
        cipher = [line.split()[-1] for line in fields if line.startswith("cipher ")]
        cipher_names = {"aes128-gcm": "GCM-AES-128", "aes256-gcm": "GCM-AES-256",
                        "aes128-gcm-xpn": "GCM-AES-XPN-128", "aes256-gcm-xpn": "GCM-AES-XPN-256"}
        assert len(priority) == 1 and len(cipher) == 1, "EOS MACsec profile settings are incomplete"
        profile.update(priority=int(priority[0]), rekey_period=int(period[0]) if period else 0,
                       cipher_suite=cipher_names[cipher[0]], send_sci="true" if "sci" in fields else "false")
    else:
        for role in ("primary", "fallback"):
            ckn = fields.get(role + "_ckn")
            if not ckn:
                continue
            result = host.command(
                "sonic-db-cli {} CONFIG_DB HGET {} {}".format(
                    getns_prefix(host, port), shlex.quote("MACSEC_PROFILE|" + name), role + "_cak"),
                module_ignore_errors=True, verbose=False)
            succeeded = not result.get("failed") and result.get("rc") == 0
            assert succeeded, "Unable to read bound MACsec key"
            cak = result["stdout"].strip()
            assert bool(cak), "Bound MACsec CAK is missing"
            profile[role + "_ckn"] = ckn
            profile[role + "_cak"] = cak
        for field in ("priority", "cipher_suite", "policy", "send_sci"):
            assert field in fields, "MACsec profile setting {} is missing".format(field)
            profile[field] = int(fields[field]) if field == "priority" else fields[field]
        profile["rekey_period"] = int(fields.get("rekey_period", 0))
    assert bool(profile.get("primary_cak")) and bool(profile.get("primary_ckn")), "Bound primary CA is missing"
    assert bool(profile.get("fallback_cak")) == bool(profile.get("fallback_ckn")), "Incomplete bound fallback CA"
    return profile


def wait_for_original_macsec_links(original_bindings):
    """Wait for both original protected endpoints, or cleanup of an originally unbound endpoint."""
    def _original_links_ready():
        for endpoints in original_bindings.values():
            originally_protected = all(name is not None for _, _, name in endpoints)
            for host, port, name in endpoints:
                if bound_profile(host, port) != name:
                    return False
                if originally_protected and not host.iface_macsec_ok(port):
                    return False
                if name is None:
                    if isinstance(host, EosHost):
                        if host.iface_macsec_ok(port):
                            return False
                    else:
                        state = sa_state(host, port)
                        if state["enabled"] or state["tx_saks"] or state["rx_saks"]:
                            return False
        return True

    assert wait_until(300, 3, 0, _original_links_ready), "MACsec did not recover on the original bindings"


@contextmanager
def prepare_fallback_profiles(env, candidates):
    """Reuse bound profiles; isolate managed endpoints when a profile has unmanaged users."""
    cache = {}
    original_bindings = {}
    for port, neighbor in env["control_links"].items():
        original_bindings[port] = [
            (env["duthost"], port, bound_profile(env["duthost"], port)),
            (neighbor["host"], neighbor["port"], bound_profile(neighbor["host"], neighbor["port"])),
        ]
    active = set(env["links"])
    isolated_scopes = set()
    attachment_cache = {}
    while True:
        for port, neighbor in env["control_links"].items():
            if port not in active or port in env["profiles"]:
                continue
            for (host, endpoint_port, _), target in zip(
                    original_bindings[port], (env["profiles"], env["peer_profiles"])):
                known_profiles = [env.get("suite_profiles", {}).get(port, candidates[0])] + candidates
                profile = get_bound_profile_settings(host, endpoint_port, known_profiles)
                scope = _profile_scope(host, endpoint_port, profile)
                target[port] = cache.setdefault(scope, profile)
        operations = get_profile_operations(env, active)
        scopes = {
            _profile_scope(host, endpoint_port, profile):
            (host, endpoint_port, profile)
            for host, endpoint_port, profile in operations
            if profile["name"] is not None
        }
        added = set()
        for scope, (host, endpoint_port, profile) in scopes.items():
            if scope not in attachment_cache:
                attachment_cache[scope] = _profile_attachments(
                    host, endpoint_port, profile["name"])
            attachments = attachment_cache[scope]
            managed = {
                managed_port
                for managed_port, endpoints in original_bindings.items()
                if any(
                    name is not None
                    and _profile_scope(
                        endpoint_host, managed_endpoint,
                        {"name": name}) == scope
                    for endpoint_host, managed_endpoint, name in endpoints)
            }
            managed_attachments = {
                managed_endpoint
                for endpoints in original_bindings.values()
                for endpoint_host, managed_endpoint, name in endpoints
                if name is not None
                and _profile_scope(
                    endpoint_host, managed_endpoint,
                    {"name": name}) == scope
            }
            assert managed_attachments <= attachments, \
                "MACsec profile attachment enumeration is incomplete"
            if attachments - managed_attachments:
                isolated_scopes.add(scope)
            else:
                added.update(managed)
        if added <= active:
            break
        active.update(added)

    for port in active:
        if (env["duthost"].facts["asic_type"] == "vs"
                and isinstance(env["control_links"][port]["host"], EosHost)
                and "false" in (env["profiles"][port]["send_sci"], env["peer_profiles"][port]["send_sci"])):
            pytest.skip("macsec on dut vsonic, neighbor eos, send_sci false")

    created = []
    bindings = []
    owned_profiles = {}

    def _delete_owned(host, endpoint_port, profile):
        assert not _profile_attachments(
            host, endpoint_port, profile["name"]), \
            "Cannot delete an attached test-owned MACsec profile"
        delete_macsec_profile(host, profile["name"], namespace_option=getns_prefix(host, endpoint_port))

    try:
        for port in env["control_links"]:
            if port not in active:
                continue
            dut_profile = env["profiles"][port]
            peer_profile = env["peer_profiles"][port]
            for profile, other in ((dut_profile, peer_profile), (peer_profile, dut_profile)):
                if profile["name"] is None:
                    for field in ("primary_cak", "primary_ckn", "fallback_cak", "fallback_ckn"):
                        if other.get(field):
                            profile[field] = other[field]
            same_primary = _key_identity(dut_profile, "primary") == _key_identity(peer_profile, "primary")
            assert same_primary, (
                "The selected link does not share the suite primary CA")
            endpoint_scopes = [
                _profile_scope(host, endpoint_port, profile)
                for (host, endpoint_port, _), profile in zip(
                    original_bindings[port],
                    (dut_profile, peer_profile))
            ]
            effective_profiles = [
                owned_profiles.get(scope, profile)
                for scope, profile in zip(
                    endpoint_scopes, (dut_profile, peer_profile))
            ]
            fallback_profiles = [
                p for p in effective_profiles
                if p.get("fallback_cak")]
            if len(fallback_profiles) == 2:
                same_fallback = (
                    _key_identity(
                        effective_profiles[0], "fallback")
                    == _key_identity(
                        effective_profiles[1], "fallback"))
                assert same_fallback, (
                    "The selected link does not share the suite fallback CA")
            fallback_pair = (
                _key_pair(fallback_profiles[0], "fallback") if fallback_profiles
                else generate_cak_ckn_pair(dut_profile["cipher_suite"]))
            for (host, endpoint_port, original_name), target in zip(
                    original_bindings[port], (env["profiles"], env["peer_profiles"])):
                profile = target[port]
                scope = _profile_scope(host, endpoint_port, profile)
                needs_owned = (
                    scope in isolated_scopes
                    or profile["name"] is None
                    or not profile.get("fallback_cak"))
                if needs_owned and scope in owned_profiles:
                    profile = owned_profiles[scope]
                elif needs_owned:
                    name = "FC" + uuid.uuid4().hex[:12]
                    assert not profile_exists(host, name), "Refusing to overwrite an existing MACsec profile"
                    profile = dict(profile, name=name, fallback_cak=fallback_pair[0], fallback_ckn=fallback_pair[1])
                    owned_profiles[scope] = profile
                    created.append((host, endpoint_port, profile))
                    set_macsec_profile(
                        host, name, profile["priority"], profile["cipher_suite"],
                        *_key_pair(profile, "primary"), profile["policy"], profile["send_sci"],
                        profile["rekey_period"], *_key_pair(profile, "fallback"),
                        namespace_option=getns_prefix(host, endpoint_port))
                if profile["name"] != original_name:
                    bindings.append((host, endpoint_port, original_name))
                    if original_name is not None:
                        disable_macsec_port(host, endpoint_port)
                    enable_macsec_port(host, endpoint_port, profile["name"])
                target[port] = profile

        env["active_ports"] = [port for port in env["control_links"] if port in active]
        for host, endpoint_port, profile in get_profile_operations(env):
            assert profile.get("fallback_cak") and profile.get("fallback_ckn"), (
                "Every affected MACsec binding must have a suite-known fallback")
            assert configured_ckns(host, endpoint_port, profile["name"]) == _expected_ckns(profile)
        yield
    finally:
        with ExitStack() as cleanup:
            cleanup.callback(wait_for_original_macsec_links, {
                port: original_bindings[port] for port in active})
            for host, endpoint_port, profile in created:
                cleanup.callback(_delete_owned, host, endpoint_port, profile)
            for host, endpoint_port, name in bindings:
                if name is not None:
                    cleanup.callback(enable_macsec_port, host, endpoint_port, name)
                cleanup.callback(disable_macsec_port, host, endpoint_port)


@pytest.fixture(scope="module")
def fallback_env(macsec_duthost, ctrl_links, upstream_links, macsec_profile, port_profiles, tbinfo):
    """Use suite-bound fallback profiles, isolating only profiles unsafe to mutate."""
    duthost = macsec_duthost
    result = duthost.command("show macsec --mka", module_ignore_errors=True)
    if "no such option" in result.get("stderr", "").lower():
        pytest.skip("Image does not support show macsec --mka")

    routed_links = get_fallback_routed_links(
        duthost, tbinfo, ctrl_links, upstream_links)
    links = select_pair(duthost, ctrl_links, routed_links)
    env = {"duthost": duthost, "links": links, "control_links": ctrl_links, "upstream_links": routed_links,
           "profiles": {}, "peer_profiles": {}, "active_ports": list(links),
           "suite_profiles": {port: (port_profiles or {}).get(port, macsec_profile) for port in ctrl_links},
           "base_profile_name": macsec_profile["name"]}
    candidates = [macsec_profile] + list((port_profiles or {}).values())
    with prepare_fallback_profiles(env, candidates):
        env["profile"] = env["profiles"][next(iter(links))]
        wait_for_primary_macsec_links(env)
        yield env


@pytest.fixture
def unattached_profile(fallback_env):
    """Yield the name of a DUT profile that no port uses; delete it afterwards."""
    duthost = fallback_env["duthost"]
    name = FALLBACK_PROFILE + "_UNATTACHED"
    assert not profile_exists(duthost, name), "Refusing to overwrite existing profile {}".format(name)
    yield name
    delete_macsec_profile(duthost, name)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_fallback_operational_state_and_config(fallback_env):
    """Verify effective DUT/peer profiles, configured rekey periods and protected links."""
    env = fallback_env
    for port, nbr in env["links"].items():
        profile = env["profiles"][port]
        peer_profile = env["peer_profiles"][port]
        fields = profile_fields(env["duthost"], port, profile["name"])
        assert int(fields.get("rekey_period", 0)) == profile["rekey_period"]
        assert configured_ckns(env["duthost"], port, profile["name"]) == _expected_ckns(profile)
        if isinstance(nbr["host"], EosHost):
            if peer_profile["rekey_period"]:
                assert "mka session rekey-period {}".format(peer_profile["rekey_period"]) in eos_profile(
                    nbr["host"], peer_profile["name"])
        else:
            assert int(profile_fields(nbr["host"], nbr["port"], peer_profile["name"]).get("rekey_period", 0)) == (
                peer_profile["rekey_period"])
        assert not get_dut_protection_errors(env, port, profile["primary_ckn"])
        assert not get_peer_protection_errors(env, port, peer_profile["primary_ckn"])


@pytest.mark.parametrize("role", ["primary", "fallback"])
def test_cak_rotation_is_hitless(fallback_env, role):
    """A staged primary or fallback rotation keeps transit traffic lossless and ends on the primary CA."""
    verify_hitless_cak_rotation(fallback_env, role)


@pytest.mark.parametrize("role", ["primary", "fallback"])
def test_cak_rotation_with_periodic_rekey(fallback_env, role):
    """Cross natural SAK refreshes before and after CAK rotation without traffic loss."""
    port = next(iter(fallback_env["links"]))
    status = get_mka_status(fallback_env["duthost"], port)
    if get_key_server_rekey_period(fallback_env, port, status) == 0:
        pytest.skip("Selected MACsec key-server profile has periodic rekey disabled")
    verify_hitless_cak_rotation(fallback_env, role, verify_rekey=True)


@pytest.mark.stress_test
def test_back_to_back_cak_rotation_stress(fallback_env):
    """Alternate primary and fallback rotations, each in its own zero-loss window."""
    if fallback_env["base_profile_name"] != FALLBACK_PROFILE:
        pytest.skip("Rotation stress runs only on {}".format(FALLBACK_PROFILE))
    for iteration in range(STRESS_ROTATIONS):
        role = "fallback" if iteration % 2 else "primary"
        logger.info("Stress rotation %d/%d: %s", iteration + 1, STRESS_ROTATIONS, role)
        verify_hitless_cak_rotation(fallback_env, role)


def test_primary_mismatch_falls_back_hitlessly(fallback_env):
    """A peer with a wrong primary CAK fails over to the fallback CA and back without traffic loss.

    cEOS peers first delete the primary key alone; SONiC can only replace it.
    """
    env = fallback_env
    selected_port = next(iter(env["links"]))
    profile = env["profiles"][selected_port]
    operation = get_profile_operations(env, [selected_port], side="peer")[0]
    peer_profile = operation[2]
    peer_host = env["links"][selected_port]["host"]
    profile_name = peer_profile["name"]
    primary_key = _key_pair(peer_profile, "primary")
    mismatched_key = generate_cak_ckn_pair(profile["cipher_suite"])
    mismatched_profile = dict(peer_profile, primary_cak=mismatched_key[0], primary_ckn=mismatched_key[1])
    fallback_ckn = profile["fallback_ckn"]

    def _get_primary_removal_errors():
        return get_dut_protection_errors(env, selected_port, fallback_ckn, require_all_live=False) + (
            [] if configured_ckns(peer_host, None, profile_name) == {fallback_ckn.lower()}
            else ["peer primary remains"])

    try:
        with transit_path(env, selected_port) as endpoints, transit_traffic(endpoints) as pings:
            before = get_dut_macsec_states(env, [selected_port])
            if isinstance(peer_host, EosHost):
                configure_eos_key(peer_host, profile_name, primary_key, remove=True)
                wait_until_no_errors(
                    MKA_TIMEOUT, _get_primary_removal_errors,
                    "DUT did not fail over after the peer primary was deleted")
                configure_eos_key(peer_host, profile_name, mismatched_key)
                peer_profile["primary_cak"], peer_profile["primary_ckn"] = mismatched_key
            else:
                replace_profile_key(operation, "primary", mismatched_key)
            wait_for_dut_macsec_convergence(env, before, fallback_ckn, require_all_live=False)
            wait_until_no_errors(
                MKA_TIMEOUT,
                lambda: get_peer_protection_errors(env, selected_port, fallback_ckn, False, mismatched_profile),
                "Peer did not fail over to the fallback CA")

            before = get_dut_macsec_states(env, [selected_port])
            replace_profile_key(operation, "primary", primary_key)
            wait_for_dut_macsec_convergence(env, before, profile["primary_ckn"], require_rekey=True)
            wait_until_no_errors(
                MKA_TIMEOUT, lambda: get_peer_protection_errors(env, selected_port, profile["primary_ckn"]),
                "Peer did not return to the primary CA")
            assert_no_loss(pings)
    finally:
        restore_profile_key(operation, "primary", primary_key, mismatched_key)
        wait_for_primary_macsec_links(env)


@pytest.mark.parametrize("case", ["half_cak", "half_ckn", "duplicate_ckn", "invalid_fallback_cak"])
def test_profile_add_rejects_invalid_fallback(fallback_env, unattached_profile, case):
    """`config macsec profile add` rejects an incomplete or invalid fallback key and creates nothing."""
    duthost = fallback_env["duthost"]
    profile = fallback_env["profile"]
    port = next(iter(fallback_env["links"]))
    primary_cak, primary_ckn = generate_cak_ckn_pair(profile["cipher_suite"])
    fallback_cak, fallback_ckn = generate_cak_ckn_pair(profile["cipher_suite"])
    fallback_options = {
        "half_cak": "--fallback_cak {}".format(fallback_cak),
        "half_ckn": "--fallback_ckn {}".format(fallback_ckn),
        "duplicate_ckn": "--fallback_cak {} --fallback_ckn {}".format(fallback_cak, primary_ckn),
        "invalid_fallback_cak": "--fallback_cak 00 --fallback_ckn {}".format(fallback_ckn),
    }[case]
    result = duthost.command(
        "config macsec {} profile add {} --priority {} --cipher_suite {} --primary_cak {} --primary_ckn {} "
        "--policy {} --send_sci {}".format(
            getns_prefix(duthost, port), unattached_profile, profile["priority"], profile["cipher_suite"],
            primary_cak, primary_ckn, profile["policy"], fallback_options),
        module_ignore_errors=True, verbose=False)
    assert result["failed"], "Invalid fallback ({}) was accepted".format(case)
    assert profile_fields(duthost, port, unattached_profile) is None


def test_unattached_profile_update_replaces_primary(fallback_env, unattached_profile):
    """`config macsec profile update_cak` replaces the primary key of a profile no port uses."""
    duthost = fallback_env["duthost"]
    port = next(iter(fallback_env["links"]))
    primary, fallback = create_unattached_profile(fallback_env, unattached_profile)
    replacement = generate_cak_ckn_pair(fallback_env["profile"]["cipher_suite"])
    update_macsec_profile_key(duthost, unattached_profile, *primary, *replacement)
    assert configured_ckns(duthost, port, unattached_profile) == {replacement[1].lower(), fallback[1].lower()}


@pytest.mark.parametrize("case", ["unchanged", "unknown_old_ckn", "fallback_collision", "invalid_cak", "invalid_ckn"])
def test_profile_update_rejects_invalid_key(fallback_env, unattached_profile, case):
    """`config macsec profile update_cak` rejects an invalid replacement and leaves the profile unchanged."""
    duthost = fallback_env["duthost"]
    port = next(iter(fallback_env["links"]))
    (primary_cak, primary_ckn), (fallback_cak, fallback_ckn) = create_unattached_profile(
        fallback_env, unattached_profile)
    new_cak, new_ckn = generate_cak_ckn_pair(fallback_env["profile"]["cipher_suite"])
    old_ckn, cak, ckn = {
        "unchanged": (primary_ckn, primary_cak, primary_ckn),
        "unknown_old_ckn": ("00" * (len(primary_ckn) // 2), new_cak, new_ckn),
        "fallback_collision": (primary_ckn, fallback_cak, fallback_ckn),
        "invalid_cak": (primary_ckn, "00", new_ckn),
        "invalid_ckn": (primary_ckn, new_cak, "not-hex"),
    }[case]
    result = duthost.command("config macsec {} profile update_cak {} --old_ckn {} --new_ckn {} --new_cak {}".format(
        getns_prefix(duthost, port), unattached_profile, old_ckn, ckn, cak),
        module_ignore_errors=True, verbose=False)
    assert result["failed"], "Invalid update ({}) was accepted".format(case)
    assert configured_ckns(duthost, port, unattached_profile) == {primary_ckn.lower(), fallback_ckn.lower()}


def test_primary_only_profile_update_rejected(fallback_env, unattached_profile):
    """`config macsec profile update_cak` is rejected for a profile without a fallback key."""
    duthost = fallback_env["duthost"]
    port = next(iter(fallback_env["links"]))
    (primary_cak, primary_ckn), _ = create_unattached_profile(fallback_env, unattached_profile, fallback=False)
    new_cak, new_ckn = generate_cak_ckn_pair(fallback_env["profile"]["cipher_suite"])
    result = duthost.command("config macsec {} profile update_cak {} --old_ckn {} --new_ckn {} --new_cak {}".format(
        getns_prefix(duthost, port), unattached_profile, primary_ckn, new_ckn, new_cak),
        module_ignore_errors=True, verbose=False)
    assert result["failed"], "Primary-only profile update was accepted"
    assert configured_ckns(duthost, port, unattached_profile) == {primary_ckn.lower()}


def test_primary_update_applies_without_live_fallback(fallback_env):
    """A DUT primary update is applied in place even when the configured fallback has no live peer.

    The update is unsafe on that port, so traffic loss is allowed until the operator updates the peers.
    """
    env = fallback_env
    duthost = env["duthost"]
    unsafe_port, safe_port = env["links"]
    unsafe_profile = env["profiles"][unsafe_port]
    safe_profile = env["profiles"][safe_port]
    unsafe_peer = get_profile_operations(env, [unsafe_port], side="peer")[0]
    safe_peer = get_profile_operations(env, [safe_port], side="peer")[0]
    if _profile_scope(*unsafe_peer) == _profile_scope(*safe_peer):
        pytest.skip("This scenario requires independently configurable peer profiles")
    original_fallback = _key_pair(unsafe_peer[2], "fallback")
    mismatched_fallback = generate_cak_ckn_pair(unsafe_profile["cipher_suite"])
    replacement_primary = generate_cak_ckn_pair(unsafe_profile["cipher_suite"])
    changed_dut = (duthost, unsafe_port, unsafe_profile)
    original_primary = _key_pair(unsafe_profile, "primary")
    shared_dut_profile = _profile_scope(*changed_dut) == _profile_scope(duthost, safe_port, safe_profile)
    affected_ports = [
        port for port in env["active_ports"]
        if env["profiles"][port] is unsafe_profile]
    original_peer_keys = [(operation, _key_pair(operation[2], "primary"))
                          for operation in get_profile_operations(env, affected_ports, side="peer")]
    changed_peer_keys = []

    def _get_fallback_liveness_errors():
        state = get_mka_status(duthost, unsafe_port)
        live = state["participants"].get(original_fallback[1].lower(), {}).get("live") if state else None
        return [] if live == 0 else ["fallback live peers: {}".format(live)]

    def _get_precondition_errors():
        return (
            get_dut_protection_errors(env, unsafe_port, original_primary[1], require_all_live=False)
            + _get_fallback_liveness_errors()
            + get_dut_protection_errors(env, safe_port, safe_profile["primary_ckn"])
            + get_peer_protection_errors(env, safe_port, safe_peer[2]["primary_ckn"]))

    try:
        # 1. Leave the unsafe port with no live fallback peer.
        replace_profile_key(unsafe_peer, "fallback", mismatched_fallback)
        wait_until_no_errors(
            MKA_CONVERGE_TIMEOUT, _get_precondition_errors,
            "Unsafe port has a live fallback, or safe port is not secured with both CAs")

        # 2. One profile update affects only ports actually bound to that profile.
        replace_profile_key(changed_dut, "primary", replacement_primary)
        assert configured_ckns(duthost, unsafe_port, unsafe_profile["name"]) == _expected_ckns(unsafe_profile)
        wait_until_no_errors(
            MKA_TIMEOUT,
            lambda: get_applied_ckn_errors(
                get_mka_status(duthost, unsafe_port), replacement_primary[1], unsafe_profile["fallback_ckn"]),
            "Unsafe port did not apply the new primary")
        safe_principal = safe_profile["fallback_ckn"] if shared_dut_profile else safe_profile["primary_ckn"]
        wait_until_no_errors(
            MKA_CONVERGE_TIMEOUT,
            lambda: get_dut_protection_errors(env, safe_port, safe_principal, not shared_dut_profile),
            "Safe sibling did not retain the expected protected state")
        assert configured_ckns(duthost, safe_port, safe_profile["name"]) == _expected_ckns(safe_profile)

        # 3. Reconcile only peers of the changed DUT profile, including other shared bindings.
        restore_profile_key(unsafe_peer, "fallback", original_fallback, mismatched_fallback)
        for operation, original in original_peer_keys:
            changed_peer_keys.append((operation, original))
            replace_profile_key(operation, "primary", replacement_primary)
        for port in (safe_port, unsafe_port):
            def _get_reconciliation_errors():
                return (
                    get_dut_protection_errors(env, port, env["profiles"][port]["primary_ckn"])
                    + get_peer_protection_errors(env, port, env["peer_profiles"][port]["primary_ckn"]))

            wait_until_no_errors(
                MKA_CONVERGE_TIMEOUT, _get_reconciliation_errors,
                "{} did not converge on the new primary".format(port))
    finally:
        with ExitStack() as cleanup:
            for operation, original in changed_peer_keys:
                cleanup.callback(restore_profile_key, operation, "primary", original, replacement_primary)
            cleanup.callback(restore_profile_key, changed_dut, "primary", original_primary, replacement_primary)
            cleanup.callback(restore_profile_key, unsafe_peer, "fallback", original_fallback, mismatched_fallback)
        wait_for_primary_macsec_links(env)


def test_both_invalid_blocks_traffic_and_recovers(fallback_env):
    """With both peer CAKs wrong, the link is blocked in both directions; matching keys restore traffic.

    Each update keeps a configured alternate, so the CLI accepts both. Traffic loss is expected.
    """
    env = fallback_env
    selected_port = next(iter(env["links"]))
    operation = get_profile_operations(env, [selected_port], side="peer")[0]
    profile = operation[2]
    peer_host = env["links"][selected_port]["host"]
    if isinstance(peer_host, EosHost):
        pytest.skip(
            "EOS may retain a removed principal MKA participant, so hot "
            "key removal cannot reliably create a both-invalid peer")
    primary_key = (profile["primary_cak"], profile["primary_ckn"])
    fallback_key = (profile["fallback_cak"], profile["fallback_ckn"])
    invalid_primary_key = generate_cak_ckn_pair(profile["cipher_suite"])
    invalid_fallback_key = generate_cak_ckn_pair(profile["cipher_suite"])

    def _get_both_invalid_errors():
        dut_profile = env["profiles"][selected_port]
        return (
            get_link_blocking_errors(
                get_mka_status(env["duthost"], selected_port),
                dut_profile["primary_ckn"], dut_profile["fallback_ckn"])
            + get_link_blocking_errors(
                get_mka_status(peer_host, operation[1]), invalid_primary_key[1], invalid_fallback_key[1]))

    with stable_transit_path(env, selected_port) as path:
        endpoints = path["endpoints"]
        observe_transit_requests(
            endpoints, path["routes_ok"], "baseline",
            expect_requests=True, capability_probe=True)
        try:
            replace_profile_key(operation, "primary", invalid_primary_key)
            replace_profile_key(operation, "fallback", invalid_fallback_key)
            # The second role update can be queued behind the first, so allow full MKA convergence.
            wait_until_no_errors(
                MKA_CONVERGE_TIMEOUT, _get_both_invalid_errors,
                "Link with both CAKs mismatched is not blocked")
            assert path["routes_ok"](), \
                "Protected routes disappeared while both CAKs were invalid"
            observe_transit_requests(
                endpoints, path["routes_ok"], "blocked",
                expect_requests=False)
        finally:
            with ExitStack() as cleanup:
                cleanup.callback(restore_profile_key, operation, "fallback", fallback_key, invalid_fallback_key)
                cleanup.callback(restore_profile_key, operation, "primary", primary_key, invalid_primary_key)
            wait_for_primary_macsec_links(env)
        observe_transit_requests(
            endpoints, path["routes_ok"], "recovery",
            expect_requests=True)
