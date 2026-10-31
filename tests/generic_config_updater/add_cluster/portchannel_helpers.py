"""Shared config parsing and operational checks for add-cluster GCU tests."""

import ast
import ipaddress
import json
import logging
import shlex

import requests

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.generic_config_updater.add_cluster.constants import (
    COUNTERS_DB_TX_FIELDS,
    INTERNAL_PORT_PREFIXES,
    NHIPV4,
    PORTCHANNEL_UP_WAIT_INTERVAL,
    PORTCHANNEL_UP_WAIT_TIME,
)
from tests.generic_config_updater.add_cluster.helpers import (
    filter_oper_up_ports,
    get_asic_interface_status_map,
    get_portchannel_status_map,
    verify_routev4_existence,
)

logger = logging.getLogger(__name__)


def restore_dut_via_minigraph(duthost, loganalyzer=None):
    """
    Restore the selected DUT with minigraph config reload.
    """
    config_reload(
        duthost,
        config_source="minigraph",
        safe_reload=True,
        wait_for_bgp=True,
        ignore_loganalyzer=loganalyzer,
    )


def escape_json_pointer_key(key):
    """
    Escape a CONFIG_DB key segment for a JSON patch path.
    """
    return key.replace('~', '~0').replace('/', '~1')


def queue_key_matches_port(queue_key, port):
    """
    Return True when a QUEUE key belongs to the selected physical port.
    """
    if queue_key.startswith("QUEUE|"):
        queue_key = queue_key.split('|', 1)[1]
    return port in queue_key.split('|')


def format_sonic_queue_dict(queue_dict):
    """
    Convert QUEUE config_facts into CONFIG_DB key/value form.
    """
    formatted_queue_dict = {}
    for key, value in queue_dict.items():
        nested_queue_table = (
            isinstance(value, dict) and
            value and
            all(
                isinstance(nested_value, dict)
                for nested_value in value.values()
            )
        )
        if nested_queue_table:
            for nested_key, nested_value in value.items():
                queue_key = "{}|{}".format(key, nested_key)
                if queue_key.startswith("QUEUE|"):
                    queue_key = queue_key.split('|', 1)[1]
                formatted_queue_dict[queue_key] = nested_value
            continue

        queue_key = key
        if queue_key.startswith("QUEUE|"):
            queue_key = queue_key.split('|', 1)[1]
        formatted_queue_dict[queue_key] = value
    return formatted_queue_dict


def normalize_acl_ports(value):
    """
    Return ACL table ports as a normalized list.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [
            port.strip()
            for port in value.split(',')
            if port.strip()
        ]
    return list(value)


def parse_counter_value(counter_value):
    """
    Parse a SONiC counter value into an integer.
    """
    if counter_value is None:
        return None
    try:
        return int(str(counter_value).replace(',', ''))
    except ValueError:
        return None


def db_hget(duthost, cli_namespace_prefix, db_name, key, field):
    """
    Return one Redis DB hash field value, or None on command failure.
    """
    cmd = "sonic-db-cli {} {} HGET {} {}".format(
        cli_namespace_prefix,
        db_name,
        shlex.quote(key),
        shlex.quote(field),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to read %s field %s/%s: rc=%s stdout=%s stderr=%s",
            db_name,
            key,
            field,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None
    return output.get("stdout", "").strip()


def db_hgetall(duthost, cli_namespace_prefix, db_name, key):
    """
    Return one Redis DB hash as a dictionary, or None on command/parse failure.
    """
    cmd = "sonic-db-cli {} {} HGETALL {}".format(
        cli_namespace_prefix,
        db_name,
        shlex.quote(key),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to read %s hash %s: rc=%s stdout=%s stderr=%s",
            db_name,
            key,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None

    lines = output.get("stdout_lines", [])
    if len(lines) == 1:
        try:
            parsed_output = ast.literal_eval(lines[0])
        except (SyntaxError, ValueError):
            parsed_output = None
        if isinstance(parsed_output, dict):
            return {
                str(hash_key): str(hash_value)
                for hash_key, hash_value in parsed_output.items()
            }

    if not lines:
        return {}
    if len(lines) % 2:
        logger.warning(
            "Failed to parse %s hash %s HGETALL output: %s",
            db_name,
            key,
            lines,
        )
        return None
    return dict(zip(lines[0::2], lines[1::2]))


def db_keys(duthost, cli_namespace_prefix, db_name, pattern):
    """
    Return Redis keys matching a pattern.
    """
    cmd = "sonic-db-cli {} {} KEYS {}".format(
        cli_namespace_prefix,
        db_name,
        shlex.quote(pattern),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to query %s keys %s: rc=%s stdout=%s stderr=%s",
            db_name,
            pattern,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None
    return output.get("stdout_lines", [])


def get_counters_db_port_oid(duthost, cli_namespace_prefix, port):
    """
    Return SAI object ID for a port from COUNTERS_DB.
    """
    port_oid = db_hget(
        duthost,
        cli_namespace_prefix,
        "COUNTERS_DB",
        "COUNTERS_PORT_NAME_MAP",
        port,
    )
    pytest_assert(
        port_oid,
        "COUNTERS_DB missing COUNTERS_PORT_NAME_MAP entry for {}".format(
            port
        ),
    )
    return port_oid


def get_counters_db_counter_value(duthost, cli_namespace_prefix, port):
    """
    Return one usable TX counter field/value for a port from COUNTERS_DB.
    """
    port_oid = get_counters_db_port_oid(
        duthost,
        cli_namespace_prefix,
        port,
    )
    counter_hash = db_hgetall(
        duthost,
        cli_namespace_prefix,
        "COUNTERS_DB",
        "COUNTERS:{}".format(port_oid),
    )
    pytest_assert(
        counter_hash,
        "COUNTERS_DB missing readable COUNTERS hash for {} ({})".format(
            port,
            port_oid,
        ),
    )
    for field in COUNTERS_DB_TX_FIELDS:
        counter_value = parse_counter_value(counter_hash.get(field))
        if counter_value is not None:
            return field, counter_value
    pytest_assert(
        False,
        "COUNTERS_DB for {} ({}) lacks TX fields {}; available fields={}".format(
            port,
            port_oid,
            COUNTERS_DB_TX_FIELDS,
            sorted(counter_hash.keys()),
        ),
    )
    raise AssertionError("pytest_assert(False) did not raise")


def get_portstat_counter(duthost, port, counter_name):
    """
    Return one counter from ``portstat -j`` output.
    """
    output = duthost.shell(
        "portstat -ji {}".format(shlex.quote(port)),
        module_ignore_errors=True,
    )
    if output["rc"]:
        logger.info(
            "Failed to read portstat for %s: rc=%s stdout=%s stderr=%s",
            port,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None

    stdout = output.get("stdout", "")
    json_start = stdout.find("{")
    if json_start == -1:
        logger.info("portstat output for %s has no JSON payload: %s", port, stdout)
        return None

    try:
        port_stats = json.loads(stdout[json_start:])
    except ValueError:
        logger.exception("Failed to parse portstat JSON for %s: %s", port, stdout)
        return None

    return parse_counter_value(
        port_stats.get(port, {}).get(counter_name),
    )


def get_member_counter_snapshot(duthost, cli_namespace_prefix, member):
    """
    Return portstat and COUNTERS_DB TX counter values for one member.
    """
    counters_db_field, counters_db_value = get_counters_db_counter_value(
        duthost,
        cli_namespace_prefix,
        member,
    )
    snapshot = {
        "portstat_TX_OK": get_portstat_counter(duthost, member, "TX_OK"),
        "counters_db_field": counters_db_field,
        "counters_db_value": counters_db_value,
    }
    pytest_assert(
        snapshot["portstat_TX_OK"] is not None,
        "portstat TX_OK counter is not readable for {}".format(member),
    )
    pytest_assert(
        snapshot["counters_db_value"] is not None,
        "COUNTERS_DB TX counter is not readable for {}".format(member),
    )
    return snapshot


def runner_member_selected(member_state):
    """
    Return True when teamd reports the member selected and link-up.
    """
    runner_state = member_state.get("runner", {})
    link_state = member_state.get("link", {})
    selected = runner_state.get("selected")
    link_up = link_state.get("up")

    if isinstance(selected, bool):
        selected_ok = selected
    else:
        selected_ok = str(selected).lower() in ("true", "yes", "1")

    if link_up is None:
        return selected_ok
    if isinstance(link_up, bool):
        return selected_ok and link_up
    return selected_ok and str(link_up).lower() in ("true", "yes", "1")


def get_interface_neighbor_and_intfs(mg_facts, selected_port):
    """
    Resolve BGP neighbor name and addresses for one DUT interface.
    """
    vm_neighbors = mg_facts.get("minigraph_neighbors", {})
    pytest_assert(
        selected_port in vm_neighbors,
        "No minigraph neighbor found for {}".format(selected_port),
    )
    neighbor_name = vm_neighbors[selected_port]['name']
    neighbor_addr = []
    neighbor_ipv4_addr = ""
    neighbor_ipv6_addr = ""

    for neighbor_info in mg_facts.get("minigraph_bgp", []):
        if neighbor_info.get("name") != neighbor_name:
            continue
        addr = neighbor_info.get("addr")
        if not addr:
            continue
        neighbor_addr.append(addr)
        try:
            parsed_addr = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if parsed_addr.version == 4:
            neighbor_ipv4_addr = addr
        elif parsed_addr.version == 6:
            neighbor_ipv6_addr = addr

    neighbor_addr = sorted(set(neighbor_addr))
    logger.info(
        "Found neighbor %s with addresses %s for DUT port %s. "
        "IPv4=%s IPv6=%s",
        neighbor_name,
        neighbor_addr,
        selected_port,
        neighbor_ipv4_addr,
        neighbor_ipv6_addr,
    )
    return neighbor_name, neighbor_addr, neighbor_ipv4_addr, neighbor_ipv6_addr


def change_static_route_no_proxy(operation, tbinfo, neighbor_ip,
                                 exabgp_port, route_ip, mask='32',
                                 aspath=65500, nhipv4=NHIPV4):
    """
    Announce or withdraw a PTF ExaBGP route without using proxy env settings.
    """
    common_config = tbinfo['topo']['properties']['configuration_properties'].get(
        'common',
        {},
    )
    ptf_ip = tbinfo['ptf_ip']
    dst_prefix = "{}/{}".format(route_ip, mask)
    nexthop = common_config.get('nhipv4', nhipv4)
    url = "http://{}:{}".format(ptf_ip, exabgp_port)
    data = {
        "command": "{} route {} next-hop {} as-path [ {} ]".format(
            operation,
            dst_prefix,
            nexthop,
            aspath,
        )
    }
    logger.info(
        "%s route through PTF ExaBGP: url=%s dst_prefix=%s nexthop=%s "
        "aspath=%s neighbor=%s",
        operation.capitalize(),
        url,
        dst_prefix,
        nexthop,
        aspath,
        neighbor_ip,
    )
    session = requests.Session()
    session.trust_env = False
    response = session.post(url, data=data, timeout=10)
    pytest_assert(
        response.status_code == 200,
        "{} route request failed: url={} status={} body={}".format(
            operation,
            url,
            response.status_code,
            response.text[:500],
        ),
    )


def add_static_route_no_proxy(tbinfo, neighbor_ip, exabgp_port, route_ip):
    """
    Announce a static route through PTF ExaBGP without proxy env settings.
    """
    change_static_route_no_proxy(
        "announce",
        tbinfo,
        neighbor_ip,
        exabgp_port,
        route_ip,
    )


def remove_static_route_no_proxy(tbinfo, neighbor_ip, exabgp_port, route_ip):
    """
    Withdraw a static route through PTF ExaBGP without proxy env settings.
    """
    change_static_route_no_proxy(
        "withdraw",
        tbinfo,
        neighbor_ip,
        exabgp_port,
        route_ip,
    )


def select_ptf_source_port(duthost, asic_namespace, mg_facts,
                           excluded_interfaces):
    """
    Select a frontend PTF source port that is not in the tested PortChannel.
    """
    status_map = get_asic_interface_status_map(duthost, asic_namespace)
    ptf_indices = mg_facts.get("minigraph_ptf_indices", {})
    oper_up_ports = set(filter_oper_up_ports(ptf_indices, status_map))
    for interface, ptf_index in sorted(
        ptf_indices.items(),
        key=lambda item: item[1],
    ):
        if interface in excluded_interfaces:
            continue
        if interface.startswith(INTERNAL_PORT_PREFIXES):
            continue
        if interface not in oper_up_ports:
            continue
        logger.info(
            "Selected PTF source interface %s ptf_index=%s",
            interface,
            ptf_index,
        )
        return interface, ptf_index

    pytest_assert(
        False,
        "No oper-up frontend PTF source port found outside {}".format(
            sorted(excluded_interfaces)
        ),
    )
    raise AssertionError("pytest_assert(False) did not raise")


def select_unused_portchannel_traffic_dst_ip(duthost, asic_index, traffic_dst_ips):
    """
    Select a route prefix that is absent before dataplane validation starts.
    """
    for dst_ip in traffic_dst_ips:
        if verify_routev4_existence(
            duthost,
            asic_index,
            dst_ip,
            should_exist=False,
        ):
            logger.info(
                "Selected unused PortChannel traffic destination %s",
                dst_ip,
            )
            return dst_ip
        logger.info(
            "PortChannel traffic destination candidate %s already exists",
            dst_ip,
        )

    pytest_assert(
        False,
        "No unused PortChannel traffic destination found from candidates {}".format(
            traffic_dst_ips,
        ),
    )
    raise AssertionError("pytest_assert(False) did not raise")


def route_uses_portchannel(duthost, asic_index, dst_ip, portchannel):
    """Return whether all resolved nexthops for a test prefix use the expected LAG."""
    route_info = duthost.asic_instance(asic_index).get_ip_route_info(
        ipaddress.ip_network("{}/32".format(dst_ip))
    )
    nexthops = route_info.get("nexthops", [])
    logger.info("Route %s expected PortChannel=%s nexthops=%s", dst_ip, portchannel, nexthops)
    return bool(nexthops) and all(interface == portchannel for _gateway, interface in nexthops)


def wait_for_portchannel_up_or_log(duthost, asic_namespace, portchannel,
                                   operation_description="min_links update"):
    """
    Wait for a PortChannel to become up and log an error on timeout.

    The caller decides whether timeout is fatal for the current stage.
    """
    last_result = {"stdout": "", "stderr": "", "rc": None}
    last_status = {}

    def _is_portchannel_up():
        nonlocal last_result, last_status
        last_status, last_result = get_portchannel_status_map(
            duthost,
            asic_namespace,
            portchannels_to_check={portchannel},
        )
        logger.info(
            "PortChannel %s status while waiting for up: %s",
            portchannel,
            last_status.get(portchannel),
        )
        return last_status.get(portchannel) == "up"

    if wait_until(
        PORTCHANNEL_UP_WAIT_TIME,
        PORTCHANNEL_UP_WAIT_INTERVAL,
        0,
        _is_portchannel_up,
    ):
        return True

    logger.error(
        "PortChannel %s did not come up after %s. "
        "Last status=%s rc=%s stdout=%s stderr=%s",
        portchannel,
        operation_description,
        last_status.get(portchannel),
        last_result.get("rc"),
        last_result.get("stdout", ""),
        last_result.get("stderr", ""),
    )
    return False
