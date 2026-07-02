"""
Self-contained telemetry collection for the SRv6 performance test.

This module is the entire on-DUT telemetry pipeline for the SRv6 test in one
file. It reuses the existing ``tests.common.telemetry`` *primitives* (metric
classes, label constants, base ``MetricCollection``) but does **not modify
any code outside** ``tests/snappi_tests/srv6/``.

================================================================================
WHY A LOCAL POLLER (instead of reusing test_switch_capacity.py's poll_stats)
================================================================================

The neighboring ``test_switch_capacity.py`` has a private ``poll_stats``
function that collects port/queue/PSU/temperature counters. The SRv6 test
needs the same counters PLUS the new ``show srv6 stat --json`` data. To keep
this test fully self-contained (per project requirement: only modify files
under ``srv6/``) we re-implement the loop here and add the SRv6 MY_SID
collection alongside.

================================================================================
WHAT GETS COLLECTED
================================================================================

Every ``interval_sec`` seconds, for each DUT in ``dut_tg_port_map``, we run:

    +-----------------------+--------------------------------------------+
    | DUT command           | Metrics emitted                            |
    +-----------------------+--------------------------------------------+
    | show queue watermark  | queue.watermark.bytes per port/queue       |
    |   unicast --json      |                                            |
    | show platform psu     | psu.voltage/current/power/status/led       |
    |   --json              |                                            |
    | show platform         | temperature.reading/high_th/low_th/...     |
    |   temperature --json  |                                            |
    | portstat -i <ports>   | port.rx/tx.bps/util/ok/err/drop/overrun    |
    |   -j                  |                                            |
    | show srv6 stat --json | srv6.my_sid.rx.bytes / srv6.my_sid.rx.     |
    |   (NEW per testplan)  |   packets, labelled with device.srv6.my_sid|
    +-----------------------+--------------------------------------------+

Each emit goes through ``db_reporter``, which is the standard sonic-mgmt
telemetry sink (typically a metrics database / time-series backend).

================================================================================
INTERNAL ARCHITECTURE
================================================================================

::

    poll_srv6_perf_stats(...)                  -- outer loop, sleeps interval_sec
        get_dut_stats(dut_tg_port_map)         -- runs all show commands per DUT
            _flatten_srv6_mysid(raw)           -- normalize SRv6 JSON shape
        for each stat_type in configs:
            record_metrics(...)                -- generic label/field dispatcher
                metric_obj.<method>.record(value, labels)

The ``configs`` dict is the heart of the dispatcher: each entry says
"for this command's parsed output, here's how to derive labels and here's
how to map JSON fields to metric methods on the metric object." Adding a
new on-box command becomes a matter of adding one more entry.
"""
import json
import logging
import time
from typing import Dict, List, Optional

# We import from the existing telemetry framework (read-only) so the SRv6
# metrics flow through the same DB reporter and use the same label/unit
# conventions as the rest of sonic-mgmt.
from tests.common.telemetry import (
    METRIC_LABEL_DEVICE_ID,
    METRIC_LABEL_DEVICE_PORT_ID,
    METRIC_LABEL_DEVICE_PSU_ID,
    METRIC_LABEL_DEVICE_QUEUE_ID,
    METRIC_LABEL_DEVICE_SENSOR_ID,
)
from tests.common.telemetry.base import MetricCollection, MetricDefinition, Reporter
from tests.common.telemetry.constants import (
    METRIC_LABEL_DEVICE_PSU_MODEL,
    METRIC_LABEL_DEVICE_PSU_SERIAL,
    METRIC_LABEL_DEVICE_PSU_HW_REV,
    METRIC_LABEL_DEVICE_QUEUE_CAST,
    UNIT_BYTES,
    UNIT_COUNT,
)
from tests.common.telemetry.metrics.device import (
    DevicePortMetrics,
    DevicePSUMetrics,
    DeviceQueueMetrics,
    DeviceTemperatureMetrics,
)


logger = logging.getLogger(__name__)


# ===========================================================================
# Local SRv6 MY_SID metric definitions
#
# We declare the new label name + metric names locally rather than amending
# tests/common/telemetry/constants.py. If/when this gets promoted to the
# shared module, search for these three constants and delete this block.
# ===========================================================================
METRIC_LABEL_DEVICE_SRV6_MY_SID = "device.srv6.my_sid"
METRIC_NAME_SRV6_MY_SID_BYTES = "srv6.my_sid.rx.bytes"
METRIC_NAME_SRV6_MY_SID_PACKETS = "srv6.my_sid.rx.packets"


class DeviceSRv6Metrics(MetricCollection):
    """Per-SID receive counters reported via ``show srv6 stat``.

    Conforms to the same ``MetricCollection`` pattern as
    ``DevicePortMetrics`` / ``DevicePSUMetrics``: declare a class-level
    ``METRICS_DEFINITIONS`` list, and the base class wires up each entry
    as an attribute (e.g. ``self.rx_bytes`` becomes a GaugeMetric you can
    call ``.record(value, labels)`` on).

    Labels expected on each record:
      * ``device.id`` - DUT hostname.
      * ``device.srv6.my_sid`` - the SID prefix, e.g. ``fcbb:bbbb:1::/48``.
    """

    METRICS_DEFINITIONS: List[MetricDefinition] = [
        MetricDefinition(
            "rx_bytes",
            METRIC_NAME_SRV6_MY_SID_BYTES,
            "SRv6 MY_SID RX bytes",
            UNIT_BYTES,
        ),
        MetricDefinition(
            "rx_packets",
            METRIC_NAME_SRV6_MY_SID_PACKETS,
            "SRv6 MY_SID RX packets",
            UNIT_COUNT,
        ),
    ]

    def __init__(self, reporter: Reporter, labels: Optional[Dict[str, str]] = None):
        super().__init__(reporter, labels)


# ===========================================================================
# PSU field decoders
# ===========================================================================
# ``show platform psu --json`` reports ``status`` and ``led_status`` as plain
# strings (e.g. "OK", "green"), so we map them to the numeric codes the PSU
# metrics expect. Older/alternate schemas occasionally nest the value as
# ``{"value": <n>}``; we still honor that form for robustness.
def _psu_status_value(record):
    """Decode PSU ``status`` to 0=error, 1=ok."""
    status = record.get("status", 0)
    if isinstance(status, dict):
        return status.get("value", 0)
    if isinstance(status, str):
        return 1 if status.strip().upper() == "OK" else 0
    return status


def _psu_led_value(record):
    """Decode PSU LED color to 0=off, 1=green, 2=amber, 3=red."""
    led = record.get("led_status", record.get("led", 0))
    if isinstance(led, dict):
        return led.get("value", 0)
    if isinstance(led, str):
        return {"off": 0, "green": 1, "amber": 2, "red": 3}.get(led.strip().lower(), 0)
    return led


# ===========================================================================
# Raw stats collection from DUTs
# ===========================================================================
def _flatten_srv6_mysid(raw):
    """Normalize the output of ``show srv6 stat --json``.

    SONiC's CLI sometimes returns this command's JSON as a dict (``{sid:
    {packets, bytes}}``) and sometimes as a list of records. To keep
    ``record_metrics`` simple, we flatten both forms into one canonical
    list:

        ``[{"sid": <prefix>, "packets_count": <int>, "packets_bytes": <int>}, ...]``

    Unknown keys are tolerated (``.get(...) or 0``) so we still emit
    something useful on future schema variations.
    """
    records = []
    if isinstance(raw, dict):
        for sid, stats in raw.items():
            if not isinstance(stats, dict):
                continue
            records.append({
                "sid": sid,
                "packets_count": stats.get("packets", stats.get("packets_count", 0)),
                "packets_bytes": stats.get("bytes", stats.get("packets_bytes", 0)),
            })
    elif isinstance(raw, list):
        for r in raw:
            if not isinstance(r, dict):
                continue
            records.append({
                "sid": r.get("sid") or r.get("my_sid") or "",
                "packets_count": r.get("packets") or r.get("packets_count") or 0,
                "packets_bytes": r.get("bytes") or r.get("packets_bytes") or 0,
            })
    return records


def get_dut_stats(dut_tg_port_map):
    """Run every telemetry command on every DUT and parse the JSON output.

    Args:
        dut_tg_port_map: ``{duthost: {peer_port: tg_port_name, ...}}`` -
                         which DUT-side interfaces this poll should look
                         at. Used to (a) target ``portstat -i <ports>`` and
                         (b) filter queue records down to the test's ports.

    Returns:
        ``{duthostname: {command_name: parsed_output}}``. ``parsed_output``
        is ``None`` if the command failed; for ``srv6_mysid`` an empty list
        is returned on empty/failed output so the downstream record_metrics
        is a no-op rather than an exception.
    """
    commands = {
        "queue":      "show queue watermark unicast --json",
        "psu":        "show platform psu --json",
        "temp":       "show platform temperature --json",
        "portstat":   "portstat -i {} -j",   # {} is replaced per-DUT below
        "srv6_mysid": "show srv6 stat --json",
    }

    result = {}
    for duthost, interfaces in dut_tg_port_map.items():
        duthostname = duthost.hostname
        logger.info(f"Collecting stats from {duthostname}")
        result[duthostname] = {}

        for command_name, command in commands.items():
            # portstat needs the explicit comma-separated interface list.
            if command_name == "portstat":
                command = command.format(",".join(interfaces.keys()))
            try:
                # module_ignore_errors=True so a transient stderr (e.g. the
                # command not yet being available on the DUT image) is not
                # fatal to the whole poll loop.
                raw_output = duthost.command(command, module_ignore_errors=True)["stdout"]
                if not raw_output or not raw_output.strip():
                    # Empty output: treat as no-records-this-poll. Use [] for
                    # srv6_mysid (list-shaped) and None for the others.
                    result[duthostname][command_name] = [] if command_name == "srv6_mysid" else None
                    continue
                json_output = json.loads(raw_output)

                # Per-command shape normalization.
                if command_name == "queue":
                    # Flatten {Port, UC0, UC1, ...} dicts into
                    # one record per (Port, queue_id, watermark_byte).
                    # Filter down to ports we asked about so the metric set
                    # stays focused on the test's interfaces.
                    json_output = [
                        {"Port": d["Port"], "queue_id": key, "watermark_byte": d[key]}
                        for d in json_output
                        for key in d.keys()
                        if d["Port"] in interfaces.keys() and (key.startswith("UC") or key.startswith("MC"))
                    ]
                elif command_name == "srv6_mysid":
                    json_output = _flatten_srv6_mysid(json_output)

                result[duthostname][command_name] = json_output
            except Exception as e:
                # Catch-all on purpose: telemetry must never crash the test.
                logger.error(f"[{duthostname}] Failed to run '{command}': {e}")
                result[duthostname][command_name] = None
    return result


# ===========================================================================
# Generic record -> metric writer
# ===========================================================================
def record_metrics(metric_obj, records, duthostname, label_template, label_map, field_map):
    """Emit one set of metrics from a list/dict of telemetry records.

    Args:
        metric_obj:     a ``MetricCollection`` instance (e.g.
                        ``DeviceSRv6Metrics``). Each metric definition on
                        it is an attribute we call ``.record(value, labels)``
                        on.
        records:        the parsed JSON output for one command on one DUT.
                        Dict-shaped records (e.g. portstat: ``{port: stats}``)
                        and list-shaped records (e.g. PSU list) are both
                        accepted.
        duthostname:    hostname string used as the ``device.id`` label.
        label_template: starting dict of static labels (keys are label
                        constants, values are filled in below per-record).
        label_map:      ``{label_const: <source>}`` - the source can be
                        either a string key (looked up in the record) or
                        a callable ``(record, key) -> value`` for custom
                        derivation.
        field_map:      ``{metric_method: <source>}`` - same source rules
                        as label_map but the value goes into a metric.

    Returns:
        None. The metric_obj writes via its reporter as a side effect.
    """
    if not records:
        return
    # Both shapes iterate uniformly with .items() / enumerate() yielding (k, v).
    items = records.items() if isinstance(records, dict) else enumerate(records)
    for key, record in items:
        # Copy so we don't mutate the caller's template.
        labels = label_template.copy()
        labels[METRIC_LABEL_DEVICE_ID] = duthostname

        # Resolve each label - either lookup or computed.
        for label_key, src in label_map.items():
            if callable(src):
                labels[label_key] = src(record, key)
            else:
                labels[label_key] = record.get(src, "Unknown") if isinstance(record, dict) else "Unknown"

        # Resolve each metric value and record it with the labels.
        for method_name, field in field_map.items():
            if callable(field):
                value = field(record)
            else:
                value = record.get(field, 0) if isinstance(record, dict) else 0
            getattr(metric_obj, method_name).record(value, labels)


# ===========================================================================
# Main poll loop
# ===========================================================================
def poll_srv6_perf_stats(dut_tg_port_map, duration_sec, interval_sec, db_reporter):
    """Drive the telemetry collection loop for ``duration_sec`` seconds.

    Args:
        dut_tg_port_map: ``{duthost: {peer_port: tg_port_name}}`` -
                         the universe of DUTs/ports to poll.
        duration_sec:    total run time in seconds (matches
                         ``test_duration`` from the parametrize matrix).
        interval_sec:    sleep between polls. The loop subtracts the time
                         spent doing the actual poll so it does not drift.
        db_reporter:     telemetry sink that backs every metric object.

    Returns:
        None. Metrics are appended to db_reporter throughout the run; the
        caller is responsible for ``db_reporter.report()`` to flush them.
    """
    # ---- Static label templates per stat type ----
    # These set the *keys* that should appear on every record of each kind.
    # ``device.id`` is filled in inside record_metrics; the rest are filled
    # in per-record by label_map.
    label_templates = {
        "portstat":   {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_PORT_ID: None},
        "psu":        {
            METRIC_LABEL_DEVICE_ID: None,
            METRIC_LABEL_DEVICE_PSU_ID: None,
            METRIC_LABEL_DEVICE_PSU_MODEL: None,
            METRIC_LABEL_DEVICE_PSU_SERIAL: None,
            METRIC_LABEL_DEVICE_PSU_HW_REV: None,
        },
        "queue":      {
            METRIC_LABEL_DEVICE_ID: None,
            METRIC_LABEL_DEVICE_PORT_ID: None,
            METRIC_LABEL_DEVICE_QUEUE_ID: None,
            METRIC_LABEL_DEVICE_QUEUE_CAST: "unicast",
        },
        "temp":       {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_SENSOR_ID: None},
        "srv6_mysid": {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_SRV6_MY_SID: None},
    }

    # ---- Metric objects (instantiated once, reused every poll). ----
    metrics = {
        "portstat":   DevicePortMetrics(reporter=db_reporter),
        "psu":        DevicePSUMetrics(reporter=db_reporter),
        "queue":      DeviceQueueMetrics(reporter=db_reporter),
        "temp":       DeviceTemperatureMetrics(reporter=db_reporter),
        "srv6_mysid": DeviceSRv6Metrics(reporter=db_reporter),
    }

    # ---- Dispatcher map ----
    # For each stat type, declare:
    #   * metric_obj      -- where the values go
    #   * label_template  -- which label keys we expect on each record
    #   * label_map       -- how to fill those label values from the record
    #   * field_map       -- which record field -> which metric method
    # To add a new on-box command, also add a new entry here.
    configs = {
        # Queue watermarks. Records come pre-flattened by get_dut_stats.
        "queue": dict(
            metric_obj=metrics["queue"],
            label_template=label_templates["queue"],
            label_map={
                METRIC_LABEL_DEVICE_PORT_ID:    "Port",
                METRIC_LABEL_DEVICE_QUEUE_ID:   "queue_id",
                METRIC_LABEL_DEVICE_QUEUE_CAST: lambda r, _: "unicast",
            },
            field_map={"watermark_bytes": "watermark_byte"},
        ),
        # PSU readings. PSU JSON reports "status"/"led_status" as plain
        # strings, so we decode them to numeric codes via callables.
        "psu": dict(
            metric_obj=metrics["psu"],
            label_template=label_templates["psu"],
            label_map={
                METRIC_LABEL_DEVICE_PSU_ID:     "name",
                METRIC_LABEL_DEVICE_PSU_MODEL:  "model",
                METRIC_LABEL_DEVICE_PSU_SERIAL: "serial",
                METRIC_LABEL_DEVICE_PSU_HW_REV: "revision",
            },
            field_map={
                "voltage": "voltage",
                "current": "current",
                "power":   "power",
                "status":  _psu_status_value,
                "led":     _psu_led_value,
            },
        ),
        # Per-sensor temperatures + thresholds.
        "temp": dict(
            metric_obj=metrics["temp"],
            label_template=label_templates["temp"],
            label_map={METRIC_LABEL_DEVICE_SENSOR_ID: "Sensor"},
            field_map={
                "reading":      "Temperature",
                "high_th":      "High_TH",
                "low_th":       "Low_TH",
                "crit_high_th": "Crit_High_TH",
                "crit_low_th":  "Crit_Low_TH",
                "warning":      "Warning",
            },
        ),
        # portstat: the outer JSON is a dict {port: stats}, so the label
        # callable receives the dict-key as `k` (the port name) directly.
        "portstat": dict(
            metric_obj=metrics["portstat"],
            label_template=label_templates["portstat"],
            label_map={METRIC_LABEL_DEVICE_PORT_ID: lambda _, k: k},
            field_map={
                "rx_bps":     "RX_BPS",
                "tx_bps":     "TX_BPS",
                "rx_util":    "RX_UTIL",
                "tx_util":    "TX_UTIL",
                "rx_ok":      "RX_OK",
                "tx_ok":      "TX_OK",
                "rx_err":     "RX_ERR",
                "tx_err":     "TX_ERR",
                "rx_drop":    "RX_DRP",
                "tx_drop":    "TX_DRP",
                "rx_overrun": "RX_OVR",
                "tx_overrun": "TX_OVR",
            },
        ),
        # SRv6 MY_SID counters (NEW per testplan). Records are the flat
        # list produced by _flatten_srv6_mysid.
        "srv6_mysid": dict(
            metric_obj=metrics["srv6_mysid"],
            label_template=label_templates["srv6_mysid"],
            label_map={METRIC_LABEL_DEVICE_SRV6_MY_SID: "sid"},
            field_map={
                "rx_bytes":   "packets_bytes",
                "rx_packets": "packets_count",
            },
        ),
    }

    end_time = time.time() + duration_sec
    logger.info(f"Started polling every {interval_sec:.2f}s for {duration_sec}s")

    while time.time() < end_time:
        poll_start = time.time()
        results = get_dut_stats(dut_tg_port_map)

        # Walk every DUT's results through every dispatcher entry.
        for duthostname, outputs in results.items():
            logger.info(f"Stats from {duthostname}: {outputs}")
            for stat_type, cfg in configs.items():
                record_metrics(
                    cfg["metric_obj"],
                    outputs.get(stat_type),
                    duthostname,
                    cfg["label_template"],
                    cfg["label_map"],
                    cfg["field_map"],
                )

        # Sleep the remainder of the interval - this guards against drift
        # when the poll itself takes a non-trivial amount of time.
        time.sleep(max(0, interval_sec - (time.time() - poll_start)))

    logger.info(f"Finished polling after {duration_sec}s.")


def poll_srv6_perf_stats_backup(dut_tg_port_map, duration_sec, interval_sec, db_reporter):
    """Drive the telemetry collection loop for ``duration_sec`` seconds.

    Args:
        dut_tg_port_map: ``{duthost: {peer_port: tg_port_name}}`` -
                         the universe of DUTs/ports to poll.
        duration_sec:    total run time in seconds (matches
                         ``test_duration`` from the parametrize matrix).
        interval_sec:    sleep between polls. The loop subtracts the time
                         spent doing the actual poll so it does not drift.
        db_reporter:     telemetry sink that backs every metric object.

    Returns:
        None. Metrics are appended to db_reporter throughout the run; the
        caller is responsible for ``db_reporter.report()`` to flush them.
    """
    # ---- Static label templates per stat type ----
    # These set the *keys* that should appear on every record of each kind.
    # ``device.id`` is filled in inside record_metrics; the rest are filled
    # in per-record by label_map.
    label_templates = {
        "portstat":   {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_PORT_ID: None},
        "psu":        {
            METRIC_LABEL_DEVICE_ID: None,
            METRIC_LABEL_DEVICE_PSU_ID: None,
            METRIC_LABEL_DEVICE_PSU_MODEL: None,
            METRIC_LABEL_DEVICE_PSU_SERIAL: None,
            METRIC_LABEL_DEVICE_PSU_HW_REV: None,
        },
        "queue":      {
            METRIC_LABEL_DEVICE_ID: None,
            METRIC_LABEL_DEVICE_PORT_ID: None,
            METRIC_LABEL_DEVICE_QUEUE_ID: None,
            METRIC_LABEL_DEVICE_QUEUE_CAST: "unicast",
        },
        "temp":       {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_SENSOR_ID: None},
        "srv6_mysid": {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_SRV6_MY_SID: None},
    }

    # ---- Metric objects (instantiated once, reused every poll). ----
    metrics = {
        "portstat":   DevicePortMetrics(reporter=db_reporter),
        "psu":        DevicePSUMetrics(reporter=db_reporter),
        "queue":      DeviceQueueMetrics(reporter=db_reporter),
        "temp":       DeviceTemperatureMetrics(reporter=db_reporter),
        "srv6_mysid": DeviceSRv6Metrics(reporter=db_reporter),
    }

    # ---- Dispatcher map ----
    # For each stat type, declare:
    #   * metric_obj      -- where the values go
    #   * label_template  -- which label keys we expect on each record
    #   * label_map       -- how to fill those label values from the record
    #   * field_map       -- which record field -> which metric method
    # To add a new on-box command, also add a new entry here.
    configs = {
        # Queue watermarks. Records come pre-flattened by get_dut_stats.
        "queue": dict(
            metric_obj=metrics["queue"],
            label_template=label_templates["queue"],
            label_map={
                METRIC_LABEL_DEVICE_PORT_ID:    "Port",
                METRIC_LABEL_DEVICE_QUEUE_ID:   "queue_id",
                METRIC_LABEL_DEVICE_QUEUE_CAST: lambda r, _: "unicast",
            },
            field_map={"watermark_bytes": "watermark_byte"},
        ),
        # PSU readings. PSU JSON reports "status"/"led_status" as plain
        # strings, so we decode them to numeric codes via callables.
        "psu": dict(
            metric_obj=metrics["psu"],
            label_template=label_templates["psu"],
            label_map={
                METRIC_LABEL_DEVICE_PSU_ID:     "name",
                METRIC_LABEL_DEVICE_PSU_MODEL:  "model",
                METRIC_LABEL_DEVICE_PSU_SERIAL: "serial",
                METRIC_LABEL_DEVICE_PSU_HW_REV: "revision",
            },
            field_map={
                "voltage": "voltage",
                "current": "current",
                "power":   "power",
                "status":  _psu_status_value,
                "led":     _psu_led_value,
            },
        ),
        # Per-sensor temperatures + thresholds.
        "temp": dict(
            metric_obj=metrics["temp"],
            label_template=label_templates["temp"],
            label_map={METRIC_LABEL_DEVICE_SENSOR_ID: "Sensor"},
            field_map={
                "reading":      "Temperature",
                "high_th":      "High_TH",
                "low_th":       "Low_TH",
                "crit_high_th": "Crit_High_TH",
                "crit_low_th":  "Crit_Low_TH",
                "warning":      "Warning",
            },
        ),
        # portstat: the outer JSON is a dict {port: stats}, so the label
        # callable receives the dict-key as `k` (the port name) directly.
        "portstat": dict(
            metric_obj=metrics["portstat"],
            label_template=label_templates["portstat"],
            label_map={METRIC_LABEL_DEVICE_PORT_ID: lambda _, k: k},
            field_map={
                "rx_bps":     "RX_BPS",
                "tx_bps":     "TX_BPS",
                "rx_util":    "RX_UTIL",
                "tx_util":    "TX_UTIL",
                "rx_ok":      "RX_OK",
                "tx_ok":      "TX_OK",
                "rx_err":     "RX_ERR",
                "tx_err":     "TX_ERR",
                "rx_drop":    "RX_DRP",
                "tx_drop":    "TX_DRP",
                "rx_overrun": "RX_OVR",
                "tx_overrun": "TX_OVR",
            },
        ),
        # SRv6 MY_SID counters (NEW per testplan). Records are the flat
        # list produced by _flatten_srv6_mysid.
        "srv6_mysid": dict(
            metric_obj=metrics["srv6_mysid"],
            label_template=label_templates["srv6_mysid"],
            label_map={METRIC_LABEL_DEVICE_SRV6_MY_SID: "sid"},
            field_map={
                "rx_bytes":   "packets_bytes",
                "rx_packets": "packets_count",
            },
        ),
    }

    end_time = time.time() + duration_sec
    logger.info(f"Started polling every {interval_sec:.2f}s for {duration_sec}s")

    while time.time() < end_time:
        poll_start = time.time()
        results = get_dut_stats(dut_tg_port_map)

        # Walk every DUT's results through every dispatcher entry.
        for duthostname, outputs in results.items():
            logger.info(f"Stats from {duthostname}: {outputs}")
            for stat_type, cfg in configs.items():
                record_metrics(
                    cfg["metric_obj"],
                    outputs.get(stat_type),
                    duthostname,
                    cfg["label_template"],
                    cfg["label_map"],
                    cfg["field_map"],
                )

        # Sleep the remainder of the interval - this guards against drift
        # when the poll itself takes a non-trivial amount of time.
        time.sleep(max(0, interval_sec - (time.time() - poll_start)))

    logger.info(f"Finished polling after {duration_sec}s.")
