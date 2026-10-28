# flake8: noqa: F401
"""
TC2-specific additions on top of tests/snappi_tests/rocev2/files/helper.py.

Import everything from the upstream helper first, then these additions:

    from tests.snappi_tests.rocev2.files.helper import *
    from tests.snappi_tests.rocev2.files.helper_tc2_portable import (
        run_rocev2_step_portable, collect_flow_queue_stats_portable,
    )

Only new/replacement functions live here - build_incast_topology(),
configure_rocev2_topology(), queue_stats(), pfc_counters(), make_check(),
assert_queries(), etc. are reused as-is from the upstream helper.py.

Why this file exists (not just reusing helper.run_rocev2_step /
helper.collect_flow_queue_stats directly): the upstream run_rocev2_step()
unconditionally calls the IxNetwork-only REST SDK via `api._ixnetwork`, which
does not exist on non-IxNetwork snappi clients (e.g. VIAVI TestCenter via
stc-x2rest). See README.md in this folder for the full explanation. Both
IxNetwork-only calls are non-load-bearing for TC1/TC2's checks, so this file
reimplements run_rocev2_step() without them.
"""
import copy
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait, wait_until  # noqa: F401

from tests.snappi_tests.rocev2.files.helper import (
    configure_rocev2_topology, start_stop, sample_flow_rates,
    wait_with_message, get_stats, queue_stats,
)

import pandas as pd  # noqa: F401
from tabulate import tabulate

logger = logging.getLogger(__name__)

__all__ = [
    "derive_dscp_by_qp",
    "run_rocev2_step_portable",
    "collect_flow_queue_stats_portable",
    "override_rocev2_qp_verb",
    "make_scale_qp_configs",
]


def derive_dscp_by_qp(topology):
    """
    Rebuild the flow_name -> ip_dscp mapping directly from the `topology` dict
    the test already built for configure_rocev2_topology(), instead of querying
    it back from IxNetwork's proprietary object tree
    (`api._ixnetwork.Traffic.find()...RoceV2Stream.find()`).

    Mirrors the exact QP-name convention configure_rocev2_topology() uses:
    f"QP{tx_port_id}_{index}" for the index-th entry in that tx port's
    qp_configs (see helper.py's `configure_rocev2_topology`, ~line 213-216).
    """
    dscp_by_qp = {}
    for tx_port_id, topo_entry in topology.items():
        qp_cfgs = topo_entry.get("qp_configs")
        if not qp_cfgs:
            continue
        for idx, qp_cfg in enumerate(qp_cfgs):
            flow_name = f"QP{tx_port_id}_{idx}"
            dscp_by_qp[flow_name] = qp_cfg.get("dscp")
    return dscp_by_qp



def run_rocev2_step_portable(api, base_config, port_config_list, topology, *,
                             traffic_duration, duthosts=None, sample_rates=False,
                             sample_start=3, sample_count=3, sample_gap=2,
                             post_configure_hook=None, settle_time=0):
    """
    Vendor-neutral replacement for helper.run_rocev2_step(). Same behavior and
    return-value shape for the per-QP flow stats DataFrame, EXCEPT:

      * dscp_by_qp is derived locally via derive_dscp_by_qp(topology) instead of
        querying api._ixnetwork.Traffic.find()...RoceV2Stream.find() - works on
        any OTG backend.
      * The debug .ixncfg config snapshot (api._ixnetwork.SaveConfig) is
        dropped - it was a debug convenience, not read by any check.
      * The "Port Statistics" / StatViewAssistant pull is dropped - TC1/TC2
        checks use pfc_counters() (DUT-side `show pfc counters`) as the
        authoritative PFC signal; the snappi-side port stat was already noted
        upstream as unreliable on IxNetwork and is not consumed by any check.
        Callers that relied on the second (ps_df) return value from the
        original run_rocev2_step() should use pfc_counters() instead.

    post_configure_hook: optional callable(config) invoked after
        configure_rocev2_topology() builds the config but before
        api.set_config(config) - the hook point for post-processing, e.g.
        override_rocev2_qp_verb() to give one QP a non-default rocev2_verb.

    Returns: flow_df (per-QP stats, with ip_dscp inserted after port_rx, and
    data_tx_rate_live/data_rx_rate_live merged in when sample_rates=True).
    """
    pytest_assert(duthosts is not None, "run_rocev2_step_portable requires duthosts")

    config = configure_rocev2_topology(copy.deepcopy(base_config), port_config_list, topology)
    if post_configure_hook is not None:
        post_configure_hook(config)
    # The shared snappi fixtures force location_preemption=True (IxNetwork default).
    # STC supports preemption but it is not recommended; explicitly set False here.
    config.options.port_options.location_preemption = False
    api.set_config(config)

    if settle_time > 0:
        wait(settle_time, f"Waiting {settle_time}s for set_config to settle before starting protocols")

    start_stop(api, operation="start", op_type="protocols")
    for duthost in duthosts:
        duthost.command("sonic-clear queuecounters")
        duthost.command("sonic-clear pfccounters")
    start_stop(api, operation="start", op_type="traffic")

    live_rate_df = None
    if sample_rates:
        wait(sample_start, "For traffic to reach steady state before rate sampling")
        live_rate_df = sample_flow_rates(api, n=sample_count, gap=sample_gap)
        remaining = int(traffic_duration - sample_start - max(0, sample_count - 1) * sample_gap)
        if remaining > 0:
            wait_with_message("Waiting for traffic completion...", remaining)
    else:
        wait_with_message("Waiting for traffic completion...", traffic_duration)

    start_stop(api, operation="stop", op_type="traffic")

    dscp_by_qp = derive_dscp_by_qp(topology)
    df = get_stats(api, stat_name="per_qp", return_type='df')
    # STC does not populate all per-QP counters (e.g. message_fail); treat missing as 0
    # so pandas query() does not misfire on NaN != 0.
    df = df.fillna(0)
    df.insert(df.columns.get_loc('port_rx') + 1, 'ip_dscp', df['flow_name'].map(dscp_by_qp))

    if live_rate_df is not None:
        live = live_rate_df.rename(columns={"data_tx_rate": "data_tx_rate_live",
                                            "data_rx_rate": "data_rx_rate_live"})
        df = df.merge(live[["flow_name", "data_tx_rate_live", "data_rx_rate_live"]],
                      on="flow_name", how="left")

    logger.info(f"Traffic Stats:\n{tabulate(df.set_index('flow_name').T, headers='keys', tablefmt='psql')}")
    return df


def collect_flow_queue_stats_portable(*, snappi_api, duthosts, plist, tconfig,
                                       snappi_dut_port_map, topology, prio_dscp_map,
                                       queue_ids, traffic_duration,
                                       queue_cols=("totalpacket",), sample_rates=True,
                                       sample_start=3, sample_count=3, sample_gap=2, log=True,
                                       post_configure_hook=None, settle_time=0):
    """
    Portable counterpart to helper.collect_flow_queue_stats() (the upstream
    "universal collector for ANY topology... congestion / incast / custom
    layouts" helper) - built on run_rocev2_step_portable() instead of
    run_rocev2_step(), so it does not require api._ixnetwork.

    post_configure_hook: forwarded to run_rocev2_step_portable() - see there
        (e.g. override_rocev2_qp_verb() for TC2's mixed-message-size scenario).

    Returns: (merged_df, flow_df, dut_queue_df, sched_df) - one fewer value
    than the upstream collect_flow_queue_stats(), which also returns
    port_stats_df; use pfc_counters() for PFC validation instead.
    """
    flow_df = run_rocev2_step_portable(
        api=snappi_api, base_config=tconfig, port_config_list=plist, topology=topology,
        traffic_duration=traffic_duration, duthosts=duthosts, sample_rates=sample_rates,
        sample_start=sample_start, sample_count=sample_count, sample_gap=sample_gap,
        post_configure_hook=post_configure_hook, settle_time=settle_time)

    merged_df, dut_queue_df, sched_df = queue_stats(
        flow_df, snappi_dut_port_map, prio_dscp_map=prio_dscp_map,
        queue_ids=list(queue_ids), queue_cols=list(queue_cols))

    if log:
        merged_display_df = merged_df.set_index('flow_name').T if len(merged_df) <= 10 else merged_df
        for name, d in (("DUT Queue Counters", dut_queue_df),
                        ("Scheduler Weights", sched_df),
                        ("Traffic and DUT Stats", merged_display_df)):
            logger.info(f"{name}:\n{tabulate(d, headers='keys', tablefmt='psql')}")

    return merged_df, flow_df, dut_queue_df, sched_df


def override_rocev2_qp_verb(config, tx_port_id, qp_index, verb_choice, **verb_kwargs):
    """
    Post-process a config already built by configure_rocev2_topology() to
    override one QP's rocev2_verb after the config has already been built.

    configure_rocev2_topology() reads the verb from each qp_cfg entry
    (defaulting to "send_with_immediate"), so you can also set the verb
    upfront via qp_cfg["verb"]. Use this function when you need to change
    the verb on a specific QP after the topology is already constructed.

    Needed for test plan steps 7-8 (TC2 mixed message size): rank1's QP is
    specified as "4KB message size (WRITE only message)", i.e. an RDMA WRITE
    verb, not send_with_immediate.

    Confirmed against the OTG schema source (open-traffic-generator/models,
    flow/rocev2flow.yaml, `Rocev2.Verb`): valid `choice` values are
    write / write_with_immediate / send / send_with_immediate / read.
    "WRITE only" (test-plan wording) = choice="write" - confirmed correct.

    Schema nuance that matters here: only `write_with_immediate` and
    `send_with_immediate` have a backing sub-object (`Rocev2.ImmediateData`,
    with an `immediate_data` field) - the bare `write` / `send` / `read`
    choices have NO corresponding property at all. So for choice="write"
    (this test's case), pass no verb_kwargs - there is nothing to set beyond
    the choice itself. Only pass verb_kwargs when verb_choice is one of the
    two *_with_immediate variants (e.g. immediate_data=...).

    Args:
        config: the object returned by configure_rocev2_topology().
        tx_port_id: the tx port whose QP should be overridden.
        qp_index: index into that port's qp_configs list (matches the
            QP{tx_port_id}_{index} naming configure_rocev2_topology() uses).
        verb_choice: "write", "write_with_immediate", "send",
            "send_with_immediate", or "read".
        **verb_kwargs: attributes to set on the chosen verb sub-object -
            ONLY valid for write_with_immediate / send_with_immediate (e.g.
            immediate_data="bb"). Leave empty for write / send / read.
    """
    flow_name = f"QP{tx_port_id}_{qp_index}"
    target_port_name = f"Port {tx_port_id}"
    for stf_peer in config.stateful_flows.rocev2:
        for tx_port in stf_peer.tx_ports:
            if tx_port.port_name != target_port_name:
                continue
            for flow in tx_port.transmit_type.target_line_rate.flows:
                if flow.name != flow_name:
                    continue
                flow.rocev2_verb.choice = verb_choice
                # Bare write/send/read have no backing sub-object in the OTG
                # schema - only *_with_immediate does. Only reach for the
                # sub-object when there is something to set on it.
                if verb_kwargs:
                    verb_obj = getattr(flow.rocev2_verb, verb_choice)
                    for k, v in verb_kwargs.items():
                        setattr(verb_obj, k, v)
                return
    pytest_assert(False, f"override_rocev2_qp_verb: flow {flow_name} not found on {target_port_name}")


def make_scale_qp_configs(num_endpoints, dscp, message_size_kb, qp_num_base=100, extra_qp_fields=None):
    """
    Generate `num_endpoints` qp_configs entries on one DSCP/queue, for the
    test plan's "increase number of endpoints per port to 4K for testing T2"
    scale step (TC2 step 9, and the equivalent step in TC3/TC4/TC6).

    Each entry gets a unique qp_num (qp_num_base, qp_num_base+1, ...) so
    configure_rocev2_topology() creates one distinct QP per endpoint.

    NOTE: 4096 QP config objects is a lot of protobuf construction; expect
    config.set_config() to take noticeably longer than the 1-QP-per-rank
    tests. Not yet measured against a real backend - if set_config() proves
    too slow at full 4K scale, consider chunking or a lower first-pass count
    (e.g. 256/1024) while validating the mechanism.
    """
    base = {"qp_num": 0, "dscp": dscp, "message_size_unit": "kb", "message_size": message_size_kb}
    if extra_qp_fields:
        base.update(extra_qp_fields)
    return [{**base, "qp_num": qp_num_base + i} for i in range(num_endpoints)]
