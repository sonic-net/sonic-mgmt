"""
ThriftAdapter base class for TAI framework.

Provides SAI thrift-based counter operations for PTF context.
These methods require a PTF test_case object carrying thrift clients
(src_client, dst_client) and the port_list global from the switch module.
"""

import logging
from typing import Any, Dict, Optional

from .base import AdapterBase

logger = logging.getLogger(__name__)

try:
    from switch import (
        sai_thrift_read_port_counters,
        sai_thrift_read_pg_counters,
        port_list,
    )
    from ptf.testutils import send_packet
    _SAI_THRIFT_AVAILABLE = True
    logger.debug("SAI thrift imported successfully")
except ImportError:
    _SAI_THRIFT_AVAILABLE = False
    logger.debug("SAI thrift not available (not in PTF context)")

# Index of TX packet count in sai_thrift_read_port_counters output (matches TRANSMITTED_PKTS in sai_qos_tests.py)
_TRANSMITTED_PKTS = 11


class ThriftAdapter(AdapterBase):
    """
    Base adapter for SAI thrift counter operations in PTF context.

    Methods accept a PTF test_case object that carries:
        - src_client / dst_client: thrift clients
        - asic_type: ASIC type string
        - ingress_counters / egress_counters: counter index lists
        - platform_asic: platform ASIC identifier

    Supported features must be declared in each platform subclass.
    """

    def get_pg_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                        baseline: Optional[Dict] = None) -> Dict:
        """
        Read PG and port counters, returning a snapshot or delta.

        If baseline is None, returns absolute counter values.
        If baseline is provided, returns the delta from that baseline.

        Args:
            test_case:   PTF test instance (carries thrift clients + counter indices)
            src_port_id: Source port index (into port_list['src'])
            dst_port_id: Destination port index (into port_list['dst'])
            baseline:    Previous snapshot from get_pg_counters() for delta mode

        Returns:
            dict with keys:
                pg_counters    - list of PG counter values
                recv_counters  - list of ingress port counter values
                xmit_counters  - list of egress port counter values
                total_received - sum of all pg_counters
                ingress_drops  - ingress drop count
                egress_drops   - egress drop count
                total_drops    - ingress_drops + egress_drops

        Raises:
            RuntimeError: if not running in PTF context (thrift unavailable)
        """
        if not _SAI_THRIFT_AVAILABLE:
            raise RuntimeError(
                "SAI thrift not available — ThriftAdapter methods require PTF context"
            )

        pg_counters = sai_thrift_read_pg_counters(
            test_case.src_client, port_list['src'][src_port_id])
        recv_counters, _ = sai_thrift_read_port_counters(
            test_case.src_client, test_case.asic_type, port_list['src'][src_port_id])
        xmit_counters, _ = sai_thrift_read_port_counters(
            test_case.dst_client, test_case.asic_type, port_list['dst'][dst_port_id])

        # primary drop counter for the snapshot; per-counter drop checks use check_rx_drop/check_tx_drop
        ingress = recv_counters[test_case.ingress_counters[0]]
        egress = xmit_counters[test_case.egress_counters[0]]

        snapshot = {
            'pg_counters': pg_counters,
            'recv_counters': recv_counters,
            'xmit_counters': xmit_counters,
            'total_received': sum(pg_counters),
            'ingress_drops': ingress,
            'egress_drops': egress,
            'total_drops': ingress + egress,
        }

        if baseline is None:
            return snapshot

        delta = dict(snapshot)
        for key in ('total_received', 'ingress_drops', 'egress_drops', 'total_drops'):
            delta[key] = snapshot[key] - baseline[key]
        return delta

    def get_pg_drop_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                             baseline: Optional[Dict] = None) -> int:
        """
        Get platform-appropriate drop count (or delta from baseline).

        Base implementation returns egress_drops (Tomahawk).
        Qumran overrides to return ingress_drops.

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            baseline:    Previous snapshot for delta mode

        Returns:
            Drop count as integer
        """
        counters = self.get_pg_counters(test_case, src_port_id, dst_port_id, baseline)
        return counters['egress_drops']

    def get_pg_all_drop_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                                 baseline: Optional[Dict] = None) -> Dict[str, int]:
        """
        Get all drop counter types (or deltas from baseline).

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            baseline:    Previous snapshot for delta mode

        Returns:
            dict with keys: ingress_drops, egress_drops, total_drops
        """
        counters = self.get_pg_counters(test_case, src_port_id, dst_port_id, baseline)
        return {
            'ingress_drops': counters['ingress_drops'],
            'egress_drops': counters['egress_drops'],
            'total_drops': counters['total_drops'],
        }

    def compensate_leakout(self, test_case: Any, dst_port_id: int, src_port_id: int,
                           pkt: Any, xmit_counters_base: list, max_retry: int = 10) -> int:
        """
        Compensate for Broadcom packet leakout after TX disable.

        Polls the egress TX counter on dst_port_id and sends extra packets on
        src_port_id to fill any leaked gap, repeating until no more leakout or
        max_retry is reached.

        Args:
            test_case:          PTF test instance (carries dst_client, asic_type)
            dst_port_id:        Destination port index (into port_list['dst'])
            src_port_id:        Source port index to send compensation packets from
            pkt:                Packet to send for compensation
            xmit_counters_base: TX counter snapshot taken before TX was disabled
            max_retry:          Maximum compensation iterations (default 10)

        Returns:
            Total number of compensation packets sent
        """
        if not _SAI_THRIFT_AVAILABLE:
            raise RuntimeError(
                "SAI thrift not available — ThriftAdapter methods require PTF context"
            )

        import time
        prev = xmit_counters_base
        time.sleep(1.5)
        curr, _ = sai_thrift_read_port_counters(
            test_case.dst_client, test_case.asic_type, port_list['dst'][dst_port_id])
        leakout_num = curr[_TRANSMITTED_PKTS] - prev[_TRANSMITTED_PKTS]
        retry = 0
        num = 0
        while leakout_num > 0 and retry < max_retry:
            send_packet(test_case, src_port_id, pkt, leakout_num)
            num += leakout_num
            time.sleep(1)
            prev = curr
            curr, _ = sai_thrift_read_port_counters(
                test_case.dst_client, test_case.asic_type, port_list['dst'][dst_port_id])
            leakout_num = curr[_TRANSMITTED_PKTS] - prev[_TRANSMITTED_PKTS]
            retry += 1
        logger.debug('Compensated %d packets to port %d, retried %d times', num, src_port_id, retry)
        return num

    def get_pkts_num_leak_out(self, pkts_num_leak_out: int) -> int:
        """
        Return the effective pkts_num_leak_out for this platform.

        Platforms that handle leakout dynamically via compensate_leakout
        (Tomahawk, Qumran) override this to return 0 so the static value
        from test_params is not double-counted.

        Args:
            pkts_num_leak_out: Raw value from test_params

        Returns:
            Effective leakout count to use in packet send calculations
        """
        return pkts_num_leak_out

    def get_ingress_drop_margin(self) -> int:
        """
        Return the allowed ingress drop counter margin for this platform.

        Some platforms may receive a small number of extra background packets
        (e.g. IPv6 NS/RA) that increment ingress drop counters unexpectedly.
        The margin allows up to this many unexpected drops before asserting.

        Base returns 0 (strict — no margin).
        TH5/TH6 override to 2.  Q3D overrides to 10.

        Returns:
            Allowed margin as a non-negative integer
        """
        return 0

    def get_active_ingress_drop_counters(self, ingress_counters: list) -> list:
        """
        Return the subset of ingress counters that are expected to increase on drop.

        On broadcom-dnx (Qumran) only counter index 1 tracks ingress drops; the
        other indices are not reliable.  On all other platforms every counter in
        ``ingress_counters`` is expected to increment.

        Base implementation returns all counters unchanged.
        Qumran overrides to filter for index 1 only.

        Args:
            ingress_counters: List of counter indices from get_counter_names()

        Returns:
            Filtered list of counter indices to assert on
        """
        return list(ingress_counters)

    def get_port_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                          baseline=None):
        """
        Read recv and xmit port counters.

        Returns (recv_counters, xmit_counters) as lists.
        If baseline (a previously returned (recv, xmit) tuple) is provided,
        returns element-wise deltas instead of absolute values.

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            baseline:    (recv_counters, xmit_counters) from a previous call,
                         or None for absolute snapshot

        Returns:
            (recv_counters, xmit_counters) — absolute lists or delta lists
        """
        if not _SAI_THRIFT_AVAILABLE:
            raise RuntimeError(
                "SAI thrift not available — ThriftAdapter methods require PTF context"
            )
        recv, _ = sai_thrift_read_port_counters(
            test_case.src_client, test_case.asic_type, port_list['src'][src_port_id])
        xmit, _ = sai_thrift_read_port_counters(
            test_case.dst_client, test_case.asic_type, port_list['dst'][dst_port_id])
        if baseline is None:
            return recv, xmit
        base_recv, base_xmit = baseline
        return (
            [r - b for r, b in zip(recv, base_recv)],
            [x - b for x, b in zip(xmit, base_xmit)],
        )

    def check_rx_drop(self, recv_delta: list, ingress_counters: list):
        """
        Check whether ingress drops occurred on the platform-appropriate counters.

        Returns (True, reason) when drops are present above the platform margin.
        Use ``not ok`` at the call site when asserting no drops should have occurred.
        The reason string describes the counter state either way, so it is useful
        whether the caller asserts ``ok`` or ``not ok``.

        Margin and active counter selection come from the adapter's own
        get_ingress_drop_margin() and get_active_ingress_drop_counters().

        Args:
            recv_delta:       Delta recv list from get_port_counters()
            ingress_counters: Counter index list from get_counter_names()

        Returns:
            (True, reason_str) if drops occurred above margin, (False, reason_str) otherwise
        """
        margin = self.get_ingress_drop_margin()
        active = self.get_active_ingress_drop_counters(ingress_counters)
        for cntr in active:
            if recv_delta[cntr] > margin:
                return True, 'cntr={} delta={} margin={}'.format(
                    cntr, recv_delta[cntr], margin)
        return False, 'no ingress drop above margin={} on counters {}'.format(
            margin, {c: recv_delta[c] for c in active})

    def check_tx_drop(self, xmit_delta: list, egress_counters: list):
        """
        Check whether egress drops occurred.

        Returns (True, reason) when drops are present.  Use ``not ok`` at the
        call site when asserting that no drops should have occurred.  The reason
        string describes the counter state either way.

        Args:
            xmit_delta:      Delta xmit list from get_port_counters()
            egress_counters: Counter index list from get_counter_names()

        Returns:
            (True, reason_str) if drops occurred, (False, reason_str) otherwise
        """
        for cntr in egress_counters:
            if xmit_delta[cntr] != 0:
                return True, 'cntr={} delta={}'.format(cntr, xmit_delta[cntr])
        return False, 'no egress drop on counters {}'.format(
            {c: xmit_delta[c] for c in egress_counters})

    def check_pfc_triggered(self, recv_delta: list, pg: int):
        """
        Check whether the PFC counter increased (PFC was triggered).

        Returns (True, reason) when PFC fired, (False, reason) otherwise; the
        reason string describes the counter state in both cases.  Use ``not ok``
        at the call site when asserting that PFC should NOT have triggered, or
        ``ok`` when asserting that it should have.

        Same logic for all platforms; the pg counter index is platform-invariant.

        Args:
            recv_delta: Delta recv list from get_port_counters()
            pg:         PFC counter index (test_params['pg'] + 2)

        Returns:
            (True, reason_str) if PFC triggered, (False, reason_str) otherwise
        """
        triggered = recv_delta[pg] > 0
        return triggered, 'pg={} delta={}'.format(pg, recv_delta[pg])

    def get_pg_pkts_received(self, test_case: Any, src_port_id: int, dst_port_id: int,
                             pg_number: int, baseline: Optional[Dict] = None) -> int:
        """
        Platform-adjusted received packet count for a given PG.

        Consistent with the other thrift methods: reads counters internally and
        returns the delta from baseline when baseline is provided, or the absolute
        pg_counters[pg_number] when baseline is None.

        Base (Tomahawk): pg_counter[pg_number] delta only.
        Qumran override: adds ingress drops (broadcom-dnx counts drops on ingress).

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            pg_number:   PG index to read from pg_counters list
            baseline:    Previous snapshot from get_pg_counters() for delta mode

        Returns:
            Platform-adjusted received packet count (or absolute if no baseline)
        """
        counters = self.get_pg_counters(test_case, src_port_id, dst_port_id)
        if baseline is None:
            return counters['pg_counters'][pg_number]
        return counters['pg_counters'][pg_number] - baseline['pg_counters'][pg_number]

    # -------------------------------------------------------------------------
    # TX control helpers
    # -------------------------------------------------------------------------

    def tx_disable(self, test_case: Any, dst_port_id: int) -> None:
        """
        Disable TX on dst_port_id.

        Wraps test_case.sai_thrift_port_tx_disable so platform adapters can
        override with additional setup (e.g. Cisco may need extra steps).

        Args:
            test_case:   PTF test instance
            dst_port_id: Destination port index
        """
        test_case.sai_thrift_port_tx_disable(
            test_case.dst_client, test_case.asic_type, [dst_port_id])

    def tx_enable(self, test_case: Any, dst_port_id: int) -> None:
        """
        Re-enable TX on dst_port_id.

        Args:
            test_case:   PTF test instance
            dst_port_id: Destination port index
        """
        test_case.sai_thrift_port_tx_enable(
            test_case.dst_client, test_case.asic_type, [dst_port_id])

    # -------------------------------------------------------------------------
    # Packet send helpers
    # -------------------------------------------------------------------------

    def send_pkts_short_of_pfc(self, test_case: Any, src_port_id: int, pkt: Any,
                               pkts_num_leak_out: int, pkts_num_trig_pfc: int,
                               cell_occupancy: int, margin: int, **kwargs) -> int:
        """
        Send packets that fill the queue just short of triggering PFC.

        Base formula (Broadcom Tomahawk / Qumran):
            count = (pkts_num_leak_out + pkts_num_trig_pfc) // cell_occupancy - 1 - margin

        Platform adapters may override to include extra variables (e.g. a future
        adapter might factor in pkts_num_egr_mem via ``kwargs``) or issue
        fill-leakout prologue packets before the main send.

        Args:
            test_case:         PTF test instance
            src_port_id:       Source port index
            pkt:               Packet to send
            pkts_num_leak_out: Static leakout packet count from test params
            pkts_num_trig_pfc: Packets needed to trigger PFC from test params
            cell_occupancy:    Cells per packet (packet_length / cell_size)
            margin:            Packet count margin
            **kwargs:          Reserved for platform-specific overrides

        Returns:
            Number of packets sent
        """
        if not _SAI_THRIFT_AVAILABLE:
            raise RuntimeError(
                "SAI thrift not available — ThriftAdapter methods require PTF context"
            )
        count = (pkts_num_leak_out + pkts_num_trig_pfc) // cell_occupancy - 1 - margin
        send_packet(test_case, src_port_id, pkt, count)
        return count
