import logging
import re
from enum import IntEnum
from os import path
from time import sleep

import ptf.packet as scapy
import ptf.testutils as testutils
import pytest

from jinja2 import Template

from constants import TEMPLATE_DIR

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# DASH config ordering utility
#
# DASH objects pushed to the DPU via gNMI (``gnmi_utils.apply_messages``) have
# inter-table dependencies (e.g. ``DASH_ENI_TABLE`` references a
# ``DASH_VNET_TABLE`` and ``DASH_METER_POLICY_TABLE``;
# ``DASH_ENI_ROUTE_TABLE`` binds an ENI to a ``DASH_ROUTE_GROUP_TABLE``).
# Historically each test fixture has manually re-implemented the same
# table-bucketing-and-apply order. ``apply_dash_configs`` below centralises
# that policy: callers pass any number of config dicts keyed by
# ``DASH_<TABLE_NAME>_TABLE:<key>`` and the helper groups + applies them in
# the dependency order defined by ``DASH_TABLE_PHASE``.
#
# To add a new DASH table type, add an entry to ``DASH_TABLE_PHASE`` choosing
# the ``DashPhase`` that satisfies its dependencies. To make an entry land in
# a non-default phase from a specific call site, split it into its own dict
# and rely on the registry; per-call overrides intentionally aren't supported.
# --------------------------------------------------------------------------- #


class DashPhase(IntEnum):
    """Phases for applying DASH configurations in dependency order.

    Lower-numbered phases are applied first on setup and deleted last on
    teardown. Two table names may share a phase if they have no ordering
    dependency relative to each other (or if their inter-dependency is
    handled within a single gNMI batch by orchagent/SAI).

    Phase contents (canonical ordering):
      - ``GROUP_1`` — APPLIANCE
      - ``GROUP_2`` — ROUTING_TYPE, METER_POLICY, OUTBOUND_PORT_MAP, VNET
      - ``GROUP_3`` — METER_RULE
      - ``GROUP_4`` — TUNNEL, OUTBOUND_PORT_MAP_RANGE, ENI, ROUTE_GROUP
      - ``GROUP_5`` — ROUTE_RULE, ROUTE, VNET_MAPPING
      - ``GROUP_6`` — ENI_ROUTE
    """
    GROUP_1 = 1
    GROUP_2 = 2
    GROUP_3 = 3
    GROUP_4 = 4
    GROUP_5 = 5
    GROUP_6 = 6


DASH_TABLE_PHASE = {
    "APPLIANCE":               DashPhase.GROUP_1,
    "ROUTING_TYPE":            DashPhase.GROUP_2,
    "METER_POLICY":            DashPhase.GROUP_2,
    "OUTBOUND_PORT_MAP":       DashPhase.GROUP_2,
    "VNET":                    DashPhase.GROUP_2,
    "METER_RULE":              DashPhase.GROUP_3,
    "TUNNEL":                  DashPhase.GROUP_4,
    "OUTBOUND_PORT_MAP_RANGE": DashPhase.GROUP_4,
    "ENI":                     DashPhase.GROUP_4,
    "ROUTE_GROUP":             DashPhase.GROUP_4,
    "ROUTE_RULE":              DashPhase.GROUP_5,
    "ROUTE":                   DashPhase.GROUP_5,
    "VNET_MAPPING":            DashPhase.GROUP_5,
    "ENI_ROUTE":               DashPhase.GROUP_6,
}

# Phase used for any ``DASH_<UNKNOWN>_TABLE`` key not present in
# ``DASH_TABLE_PHASE``. Defaulting to the latest phase makes new tables
# effectively "apply last / delete first", which is the safer fallback when
# their real dependencies aren't yet known.
DEFAULT_DASH_PHASE = DashPhase.GROUP_6

# Captures DASH_<TABLE_NAME>_TABLE at the start of a redis-style key.
# Greedy ``\w+`` correctly handles multi-word table names such as
# ``DASH_OUTBOUND_PORT_MAP_RANGE_TABLE``.
_DASH_KEY_RE = re.compile(r"^DASH_(\w+)_TABLE(?::|$)")


def dash_table_name(key):
    """Extract the DASH table name from a redis-style DASH key.

    Args:
        key: A string like ``"DASH_VNET_MAPPING_TABLE:Vnet1:10.0.0.1"`` or
            just ``"DASH_APPLIANCE_TABLE"``.

    Returns:
        The table name without the ``DASH_`` prefix or ``_TABLE`` suffix
        (e.g. ``"VNET_MAPPING"``, ``"APPLIANCE"``).

    Raises:
        ValueError: if ``key`` does not match the DASH table key shape.
    """
    m = _DASH_KEY_RE.match(key)
    if not m:
        raise ValueError("Not a DASH table key: {!r}".format(key))
    return m.group(1)


def bucket_dash_configs(*config_dicts):
    """Merge config dicts and group entries by their :class:`DashPhase`.

    Entries from later dicts that share a key with earlier dicts overwrite
    the earlier value (the same semantics as ``{**a, **b}``), but a warning
    is logged when the two values differ so silent config drift is visible.

    Args:
        *config_dicts: Any number of dicts keyed by
            ``"DASH_<TABLE>_TABLE:<key>"``.

    Returns:
        A list of ``(phase, merged_dict)`` tuples sorted by ascending phase.
        Empty if no input entries were supplied.

    Raises:
        ValueError: if any key is not a DASH table key.
    """
    by_phase = {}
    seen = {}
    for d in config_dicts:
        for k, v in d.items():
            if k in seen and seen[k] != v:
                logger.warning(
                    "Duplicate DASH key %r with conflicting values across "
                    "input dicts; later value wins",
                    k,
                )
            seen[k] = v
            tbl = dash_table_name(k)
            phase = DASH_TABLE_PHASE.get(tbl)
            if phase is None:
                logger.warning(
                    "Unknown DASH table %r in key %r; defaulting to phase %s. "
                    "Add an entry to DASH_TABLE_PHASE to silence this "
                    "warning.",
                    tbl, k, DEFAULT_DASH_PHASE.name,
                )
                phase = DEFAULT_DASH_PHASE
            by_phase.setdefault(phase, {})[k] = v
    return sorted(by_phase.items(), key=lambda item: item[0])


def apply_dash_configs(
    localhost, duthost, ptfhost, dpu_index, *config_dicts,
    set_db=True, wait_after_apply=5, max_updates_in_single_cmd=1024,
    apply_fn=None,
):
    """Apply DASH configs to the DPU in dependency order based on table name.

    Buckets entries from all ``config_dicts`` by :class:`DashPhase` (see
    ``DASH_TABLE_PHASE``) and calls the underlying gNMI apply function once
    per non-empty phase, in ascending phase order on setup or descending
    order when ``set_db=False`` (delete) so dependents are removed first.

    Args:
        localhost, duthost, ptfhost, dpu_index: passed through to ``apply_fn``.
        *config_dicts: Any number of dicts keyed by
            ``"DASH_<TABLE>_TABLE:<key>"``. Empty / ``None`` dicts are
            tolerated and skipped (so callers can use conditional inclusion
            patterns like ``*(extra if condition else [])``).
        set_db: ``True`` (default) to write configs; ``False`` to delete.
        wait_after_apply: seconds to wait after each phase's apply; forwarded
            to ``apply_fn`` per phase.
        max_updates_in_single_cmd: forwarded to ``apply_fn``.
        apply_fn: optional callable matching the signature of
            ``gnmi_utils.apply_messages``. Defaults to a lazy import so this
            module does not require ``gnmi_utils`` to be on ``sys.path`` at
            import time. Pass an injectable fake for unit tests.
    """
    if apply_fn is None:
        # Lazy import: ``tests/common/dash_utils.py`` is imported by both
        # DASH and HA tests, each of which provides its own ``gnmi_utils``
        # module on ``sys.path`` with a compatible ``apply_messages``.
        from gnmi_utils import apply_messages as _default_apply_fn
        apply_fn = _default_apply_fn

    non_empty = [d for d in config_dicts if d]
    if not non_empty:
        logger.info("apply_dash_configs called with no entries; nothing to do")
        return

    buckets = bucket_dash_configs(*non_empty)
    if not set_db:
        buckets = list(reversed(buckets))

    op_label = "SET" if set_db else "DEL"
    for phase, messages in buckets:
        tables = sorted({dash_table_name(k) for k in messages})
        logger.info(
            "[%s] DASH phase %s (priority %d): %d entries across tables %s",
            op_label, phase.name, int(phase), len(messages), tables,
        )
        apply_fn(
            localhost, duthost, ptfhost, messages, dpu_index,
            set_db=set_db,
            wait_after_apply=wait_after_apply,
            max_updates_in_single_cmd=max_updates_in_single_cmd,
        )


def safe_open_template(template_path):
    """
    Safely loads Jinja2 template from given path

    Note:
        All Jinja2 templates should be accessed with this method to ensure proper garbage disposal

    Args:
        template_path: String containing the location of the template file to be opened

    Returns:
        A Jinja2 Template object read from the provided file
    """

    with open(template_path) as template_file:
        return Template(template_file.read())


def combine_dicts(*args):
    """
    Combines multiple Python dictionaries into a single dictionary

    Used primarily to pass arguments contained in multiple dictionaries to the `render()` method for Jinja2 templates

    Args:
        *args: The dictionaries to be combined

    Returns:
        A single Python dictionary containing the key/value pairs of all the input dictionaries
    """

    combined_args = {}

    for arg in args:
        combined_args.update(arg)

    return combined_args


def render_template_to_host(template_name, host, dest_file, *template_args, **template_kwargs):
    """
    Renders a template with the given arguments and copies it to the host

    Args:
        template_name: A template inside the "templates" folder (without the preceding "templates/")
        host: The host device to copy the rendered template to (either a PTF or DUT host object)
        dest_file: The location on the host to copy the rendered template to
        *template_args: Any arguments to be passed to j2 during rendering
        **template_kwargs: Any keyword arguments to be passed to j2 during rendering
    """

    combined_args = combine_dicts(*template_args)

    rendered = safe_open_template(path.join(TEMPLATE_DIR, template_name)).render(combined_args, **template_kwargs)

    host.copy(content=rendered, dest=dest_file)


def render_template(template_name, *template_args, **template_kwargs):
    """
    Renders a template with the given arguments and copies it to the host

    Args:
        template_name: A template inside the "templates" folder (without the preceding "templates/")
        *template_args: Any arguments to be passed to j2 during rendering
        **template_kwargs: Any keyword arguments to be passed to j2 during rendering
    """

    combined_args = combine_dicts(*template_args)

    return safe_open_template(path.join(TEMPLATE_DIR, template_name)).render(combined_args, **template_kwargs)


def apply_swssconfig_file(duthost, file_path):
    """
    Copies config file from the DUT host to the SWSS docker and applies them with swssconfig

    Args:
        duthost: DUT host object
        file: Path to config file on the host
    """
    logger.info("Applying config files on DUT")
    file_name = path.basename(file_path)

    duthost.shell("docker cp {}  swss:/{}".format(file_path, file_name))
    duthost.shell("docker exec swss sh -c \"swssconfig /{}\"".format(file_name))
    sleep(5)


def verify_tunnel_packets(ptfadapter, ports, exp_dpu_to_vm_pkt, tunnel_endpoint_counts):
    timeout = 1
    if isinstance(ports, list):
        target_ports = ports
    else:
        target_ports = [ports]

    result = testutils.dp_poll(ptfadapter, timeout=timeout, exp_pkt=exp_dpu_to_vm_pkt)
    if isinstance(result, ptfadapter.dataplane.PollSuccess):
        pkt_repr = scapy.Ether(result.packet)
        if result.port in target_ports:
            if pkt_repr["IP"].dst in tunnel_endpoint_counts:
                tunnel_endpoint_counts[pkt_repr["IP"].dst] += 1
                logging.debug(
                    f"Packet sent to tunnel endpoint {pkt_repr['IP'].dst} matches: \
                        \n{result.format()} \nExpected: \n{exp_dpu_to_vm_pkt}"
                )
                return
            else:
                pytest.fail(
                    f"Received packet has unexpected dst IP {pkt_repr['IP'].dst}, \
                        expected one of {tunnel_endpoint_counts.keys()} \
                        \n{result.format()} \nExpected: \n{exp_dpu_to_vm_pkt}"
                )
        else:
            pytest.fail(f"Got expected packet on unexpected port {result.port}: {pkt_repr}")
    pytest.fail(f"DP poll failed: \n{result.format()}")
