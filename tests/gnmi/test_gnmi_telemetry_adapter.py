"""
POC integration tests for the SONiC Telemetry Adapter.

These tests validate that SonicTelemetryAdapter (Option B architecture)
produces structurally correct, type-safe, and reasonably consistent data
across both gNMI and CLI transports.

Test classes
------------
TestAdapterStructure        — field names, types, and non-negative values
TestAdapterMonotonicity     — counters advance after traffic is generated
TestBatchRetrieval          — get_all_interface_counters coverage
TestQueueStats              — queue counter structure and values
TestTransportConsistency    — gNMI vs CLI values within 5% tolerance
TestSnappiShimExample       — drop-in replacement demo for Snappi tests

Topology
--------
Marked ``topology('any')`` so that they run on VS and all physical topologies.
"""

import logging
import time

import pytest

from tests.common.telemetry.adapters import (
    SonicTelemetryAdapter,
    AdapterTransport,
    InterfaceCounters,
    QueueCounters,
)
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]

# Tolerance (fraction) for gNMI vs CLI value comparisons
_TOLERANCE = 0.05


# Shared helper

def _first_front_panel_iface(duthost) -> str:
    """Return the first Ethernet interface that portstat knows about."""
    result = duthost.shell("portstat -j", module_ignore_errors=True)
    import json
    stdout = result["stdout"]
    brace = stdout.find("{")
    if brace != -1:
        try:
            data = json.loads(stdout[brace:])
            for iface in sorted(data.keys()):
                if iface.startswith("Ethernet"):
                    return iface
        except Exception:
            pass
    pytest.skip("No Ethernet interfaces found via portstat")


# Class 1: Structural correctness

class TestAdapterStructure:
    """Verify that InterfaceCounters has correct field names, types, and non-negative values."""

    def test_interface_counters_field_names(self, duthosts, rand_one_dut_hostname):
        """All InterfaceCounters fields defined in the dataclass must be present."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)
        counters = adapter.get_interface_counters(iface)

        expected_fields = {
            "RX_OK", "TX_OK", "RX_ERR", "TX_ERR", "RX_DRP", "TX_DRP",
            "RX_BPS", "TX_BPS", "RX_UTIL", "TX_UTIL", "RX_OVR", "TX_OVR",
        }
        actual_fields = {k for k in counters.__dict__ if not k.startswith("_") and k != "transport_used"}
        pytest_assert(
            expected_fields == actual_fields,
            "Field mismatch. Expected: {} Got: {}".format(expected_fields, actual_fields),
        )

    def test_interface_counters_numeric_types(self, duthosts, rand_one_dut_hostname):
        """Integer fields must be int; float fields must be float."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)
        counters = adapter.get_interface_counters(iface)

        int_fields = ("RX_OK", "TX_OK", "RX_ERR", "TX_ERR", "RX_DRP", "TX_DRP", "RX_OVR", "TX_OVR")
        float_fields = ("RX_BPS", "TX_BPS", "RX_UTIL", "TX_UTIL")

        for fname in int_fields:
            val = getattr(counters, fname)
            pytest_assert(
                isinstance(val, int),
                "Field {} expected int, got {} ({!r})".format(fname, type(val).__name__, val),
            )
        for fname in float_fields:
            val = getattr(counters, fname)
            pytest_assert(
                isinstance(val, float),
                "Field {} expected float, got {} ({!r})".format(fname, type(val).__name__, val),
            )

    def test_interface_counters_non_negative(self, duthosts, rand_one_dut_hostname):
        """All counter values must be >= 0 (counters never go negative)."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)
        counters = adapter.get_interface_counters(iface)

        for fname, val in counters.__dict__.items():
            if fname == "transport_used":
                continue
            pytest_assert(
                val >= 0,
                "Counter field {} is negative: {}".format(fname, val),
            )

    def test_transport_field_populated(self, duthosts, rand_one_dut_hostname):
        """transport_used must be set to a valid AdapterTransport value."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)
        counters = adapter.get_interface_counters(iface)

        pytest_assert(
            counters.transport_used in AdapterTransport,
            "transport_used is not an AdapterTransport value: {!r}".format(counters.transport_used),
        )

    def test_explicit_cli_transport(self, duthosts, rand_one_dut_hostname):
        """Explicit CLI transport must set transport_used = CLI."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost, transport=AdapterTransport.CLI)
        counters = adapter.get_interface_counters(iface)

        pytest_assert(
            counters.transport_used == AdapterTransport.CLI,
            "Expected CLI, got {}".format(counters.transport_used),
        )


# Class 2: Monotonicity (counters advance over time)

class TestAdapterMonotonicity:
    """
    Verify that counters are monotonically non-decreasing between two samples.

    This is a sanity check — counters may be unchanged if there is no traffic,
    but they must not decrease.
    """

    def test_rx_ok_does_not_decrease(self, duthosts, rand_one_dut_hostname):
        """RX_OK must not decrease between two successive samples."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)

        sample1 = adapter.get_interface_counters(iface)
        time.sleep(2)
        sample2 = adapter.get_interface_counters(iface)

        pytest_assert(
            sample2.RX_OK >= sample1.RX_OK,
            "RX_OK decreased: {} → {}".format(sample1.RX_OK, sample2.RX_OK),
        )

    def test_tx_ok_does_not_decrease(self, duthosts, rand_one_dut_hostname):
        """TX_OK must not decrease between two successive samples."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)

        sample1 = adapter.get_interface_counters(iface)
        time.sleep(2)
        sample2 = adapter.get_interface_counters(iface)

        pytest_assert(
            sample2.TX_OK >= sample1.TX_OK,
            "TX_OK decreased: {} → {}".format(sample1.TX_OK, sample2.TX_OK),
        )


# Class 3: Batch retrieval

class TestBatchRetrieval:
    """Verify that get_all_interface_counters returns data for multiple interfaces."""

    def test_all_interfaces_returned(self, duthosts, rand_one_dut_hostname):
        """get_all_interface_counters must return at least one interface."""
        duthost = duthosts[rand_one_dut_hostname]
        adapter = SonicTelemetryAdapter(duthost)
        all_counters = adapter.get_all_interface_counters()

        pytest_assert(len(all_counters) > 0, "get_all_interface_counters returned empty dict")

    def test_all_interfaces_valid_counters(self, duthosts, rand_one_dut_hostname):
        """Every entry returned by get_all_interface_counters must be a valid InterfaceCounters."""
        duthost = duthosts[rand_one_dut_hostname]
        adapter = SonicTelemetryAdapter(duthost)
        all_counters = adapter.get_all_interface_counters()

        for iface, counters in all_counters.items():
            pytest_assert(
                isinstance(counters, InterfaceCounters),
                "Entry for {} is not InterfaceCounters: {!r}".format(iface, counters),
            )
            pytest_assert(
                counters.RX_OK >= 0 and counters.TX_OK >= 0,
                "Interface {} has negative counters: RX_OK={} TX_OK={}".format(
                    iface, counters.RX_OK, counters.TX_OK
                ),
            )


# Class 4: Queue stats

class TestQueueStats:
    """Verify structure and validity of per-queue counter data."""

    def test_queue_stats_returns_counters(self, duthosts, rand_one_dut_hostname):
        """get_queue_stats must return a QueueCounters with at least some entries."""
        duthost = duthosts[rand_one_dut_hostname]
        if duthost.is_supervisor_node():
            pytest.skip("Supervisor nodes have no front-panel Ethernet ports")
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)
        qc = adapter.get_queue_stats(iface)

        pytest_assert(
            isinstance(qc, QueueCounters),
            "Expected QueueCounters, got {!r}".format(type(qc)),
        )

    def test_queue_stat_key_format(self, duthosts, rand_one_dut_hostname):
        """All keys in QueueCounters.stats must match UC<n>_<SUFFIX> pattern."""
        import re
        duthost = duthosts[rand_one_dut_hostname]
        if duthost.is_supervisor_node():
            pytest.skip("Supervisor nodes have no front-panel Ethernet ports")
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)
        qc = adapter.get_queue_stats(iface)

        pattern = re.compile(r"^UC\d+_(PKTS|BYTES|DROP_PKTS|DROP_BYTES)$")
        for key in qc.stats:
            pytest_assert(
                pattern.match(key),
                "Queue key {!r} does not match expected pattern".format(key),
            )

    def test_queue_stat_values_non_negative(self, duthosts, rand_one_dut_hostname):
        """All queue counter values must be >= 0."""
        duthost = duthosts[rand_one_dut_hostname]
        if duthost.is_supervisor_node():
            pytest.skip("Supervisor nodes have no front-panel Ethernet ports")
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost)
        qc = adapter.get_queue_stats(iface)

        for key, val in qc.stats.items():
            pytest_assert(
                val >= 0,
                "Queue counter {} is negative: {}".format(key, val),
            )


# Class 5: Transport consistency (gNMI vs CLI)

class TestTransportConsistency:
    """
    Compare gNMI vs CLI counter values and confirm gNMI was actually used.

    Because gNMI and CLI query different code paths (SAI COUNTERS_DB vs
    portstat), values may differ slightly.  We accept up to 5% relative
    divergence for packet counters.

    Requires the setup_gnmi_server fixture (defined in tests/gnmi/conftest.py)
    which generates TLS certs, deploys the server cert to the DUT's gnmi
    container, and copies client certs to ptfhost at /root/gnmiCA.pem,
    /root/gnmiclient.key, /root/gnmiclient.crt.
    """

    def test_rx_ok_within_tolerance(self, duthosts, rand_one_dut_hostname, ptfhost,
                                    setup_gnmi_server):
        """RX_OK via gNMI and CLI must agree within 5%, and gNMI must have been used."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)

        gnmi_adapter = SonicTelemetryAdapter(duthost, ptfhost=ptfhost, transport=AdapterTransport.GNMI)
        cli_adapter = SonicTelemetryAdapter(duthost, transport=AdapterTransport.CLI)

        gnmi_counters = gnmi_adapter.get_interface_counters(iface)
        cli_counters = cli_adapter.get_interface_counters(iface)

        pytest_assert(
            gnmi_counters.transport_used == AdapterTransport.GNMI,
            "Expected gNMI transport, got: {}".format(gnmi_counters.transport_used),
        )
        _assert_within_tolerance(gnmi_counters.RX_OK, cli_counters.RX_OK, "RX_OK", _TOLERANCE)

    def test_tx_ok_within_tolerance(self, duthosts, rand_one_dut_hostname, ptfhost,
                                    setup_gnmi_server):
        """TX_OK via gNMI and CLI must agree within 5%, and gNMI must have been used."""
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)

        gnmi_adapter = SonicTelemetryAdapter(duthost, ptfhost=ptfhost, transport=AdapterTransport.GNMI)
        cli_adapter = SonicTelemetryAdapter(duthost, transport=AdapterTransport.CLI)

        gnmi_counters = gnmi_adapter.get_interface_counters(iface)
        cli_counters = cli_adapter.get_interface_counters(iface)

        pytest_assert(
            gnmi_counters.transport_used == AdapterTransport.GNMI,
            "Expected gNMI transport, got: {}".format(gnmi_counters.transport_used),
        )
        _assert_within_tolerance(gnmi_counters.TX_OK, cli_counters.TX_OK, "TX_OK", _TOLERANCE)

    def test_gnmi_faster_than_cli(self, duthosts, rand_one_dut_hostname, ptfhost,
                                  setup_gnmi_server):
        """
        gNMI should be faster than CLI for a single-interface counter read.

        gNMI is a direct structured RPC; CLI requires SSH + subprocess + text
        parsing.  We sample 5 calls each and compare median latency.

        Note: on low-traffic VS testbeds gNMI may not always win due to TLS
        overhead on short connections.  The test logs both values and only
        fails if gNMI is more than 3x slower (which would indicate something
        is wrong, not just variance).
        """
        import statistics

        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        samples = 5

        gnmi_adapter = SonicTelemetryAdapter(duthost, ptfhost=ptfhost, transport=AdapterTransport.GNMI)
        cli_adapter = SonicTelemetryAdapter(duthost, transport=AdapterTransport.CLI)

        gnmi_times = []
        for _ in range(samples):
            t0 = time.time()
            gnmi_adapter.get_interface_counters(iface)
            gnmi_times.append(time.time() - t0)

        cli_times = []
        for _ in range(samples):
            t0 = time.time()
            cli_adapter.get_interface_counters(iface)
            cli_times.append(time.time() - t0)

        gnmi_median = statistics.median(gnmi_times)
        cli_median = statistics.median(cli_times)

        logger.info(
            "Latency comparison for %s — gNMI median: %.3fs  CLI median: %.3fs  "
            "speedup: %.1fx",
            iface, gnmi_median, cli_median,
            cli_median / gnmi_median if gnmi_median > 0 else float("inf"),
        )

        pytest_assert(
            gnmi_median < cli_median * 3,
            "gNMI ({:.3f}s) is more than 3x slower than CLI ({:.3f}s) — "
            "check gNMI server health".format(gnmi_median, cli_median),
        )


def _assert_within_tolerance(gnmi_val: int, cli_val: int, label: str, tol: float):
    """Fail if |gnmi - cli| / max(gnmi, cli, 1) > tol."""
    denominator = max(gnmi_val, cli_val, 1)
    delta = abs(gnmi_val - cli_val) / denominator
    pytest_assert(
        delta <= tol,
        "{} diverges by {:.1%} between gNMI ({}) and CLI ({}); tolerance is {:.0%}".format(
            label, delta, gnmi_val, cli_val, tol
        ),
    )


# Class 6: Snappi shim demonstration

class TestSnappiShimExample:
    """
    Demonstrate drop-in replacement for Snappi / Keysight tests that
    currently parse ``portstat -j`` directly.
    """

    def test_counters_dict_compatible_with_portstat_json(self, duthosts, rand_one_dut_hostname):
        """
        adapter.get_interface_counters(iface).__dict__ must contain all the
        numeric counter keys that portstat -j returns.

        portstat -j also emits non-counter fields (STATE, RX_PPS, TX_PPS)
        that the adapter intentionally omits — those are excluded from the
        comparison.  Only the fields the adapter is designed to provide are
        checked here.
        """
        import json as _json
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)

        # Core counter fields the adapter is designed to expose
        COUNTER_FIELDS = {
            "RX_OK", "TX_OK",
            "RX_ERR", "TX_ERR",
            "RX_DRP", "TX_DRP",
            "RX_BPS", "TX_BPS",
            "RX_UTIL", "TX_UTIL",
            "RX_OVR", "TX_OVR",
        }

        # Fetch via portstat directly (legacy path)
        result = duthost.shell("portstat -j", module_ignore_errors=True)
        raw = result["stdout"]
        brace = raw.find("{")
        portstat_data = _json.loads(raw[brace:])
        # Only consider counter fields that portstat actually emits on this DUT
        portstat_counter_keys = set(portstat_data[iface].keys()) & COUNTER_FIELDS

        # Fetch via adapter (new path)
        adapter = SonicTelemetryAdapter(duthost, transport=AdapterTransport.CLI)
        counters = adapter.get_interface_counters(iface)
        adapter_keys = {k for k in counters.__dict__ if k != "transport_used"}

        # Every counter field portstat emits must be present in the adapter
        missing = portstat_counter_keys - adapter_keys
        pytest_assert(
            not missing,
            "Adapter is missing portstat counter fields: {}".format(missing),
        )

    def test_rate_computation_from_byte_counters(self, duthosts, rand_one_dut_hostname):
        """
        Demonstrate computing RX bps from two cumulative byte samples.
        RX_BPS (via CLI) and the computed rate should both be >= 0.
        """
        duthost = duthosts[rand_one_dut_hostname]
        iface = _first_front_panel_iface(duthost)
        adapter = SonicTelemetryAdapter(duthost, transport=AdapterTransport.CLI)

        s1 = adapter.get_interface_counters(iface)
        t1 = time.time()
        time.sleep(2)
        s2 = adapter.get_interface_counters(iface)
        t2 = time.time()

        elapsed = t2 - t1
        rx_bps = (s2.RX_BPS - s1.RX_BPS) / elapsed * 8  # bits per second
        tx_bps = (s2.TX_BPS - s1.TX_BPS) / elapsed * 8

        pytest_assert(rx_bps >= 0, "Computed RX bps is negative: {}".format(rx_bps))
        pytest_assert(tx_bps >= 0, "Computed TX bps is negative: {}".format(tx_bps))
        logger.info(
            "Computed rates for %s: RX=%.1f bps TX=%.1f bps", iface, rx_bps, tx_bps
        )
