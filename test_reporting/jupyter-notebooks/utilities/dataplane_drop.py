import urllib
import pandas as pd
from enum import Enum
from pandas import DataFrame
from utilities.kusto import VERITAS_CLUSTER, VERITAS_CLUSTER_URI, execute_kusto_query
from utilities.sonic_shift import normalize_timestamp_to_iso_utc

# A pingmesh receive rate strictly between these bounds (percent) indicates partial packet
# loss (a drop). Rates at or below the lower bound (full loss) are handled separately.
PINGMESH_DROP_LOWER_RATE = 1
PINGMESH_DROP_UPPER_RATE = 99


def get_upgrade_method_window_pingmesh_drops_batch(upgrades: DataFrame) -> DataFrame:
    """Flag pingmesh drops for many upgrades with a SINGLE Kusto query.

    The ``upgrades`` DataFrame must have the columns ``DeviceName`` (host), ``StartTime``
    and ``EndTime`` (upgrade-method window). Builds one datatable row per upgrade (keyed by
    the DataFrame index) and joins it to the per-node/5-minute-bucket send/recv rate
    (RecvCount / SendCount * 100), scoped to each row's own [bin(start, 5m), end) window.
    A drop is any node/bucket whose rate falls strictly between the lower and upper bounds
    (partial loss). Upgrades with no pingmesh data in their window are treated as no drop.

    Returns a DataFrame aligned to ``upgrades.index`` with columns ``HasDrop`` (bool) and
    ``DropBuckets`` (list of per-bucket dicts: Timestamp, NodeId, SendCount, RecvCount) for
    the partial-loss buckets in each window. Results are merged back in pandas (one query, not one
    query per row); upgrades with no drop buckets get HasDrop=False and an empty list.
    """
    required_columns = {"DeviceName", "StartTime", "EndTime"}
    missing_columns = required_columns - set(upgrades.columns)
    assert not missing_columns, f"upgrades is missing required columns: {sorted(missing_columns)}"

    if upgrades.empty:
        return DataFrame(columns=["HasDrop", "DropBuckets"], index=upgrades.index)

    # One datatable row per upgrade, keyed by the (stringified) DataFrame index.
    literal_rows = []
    for idx, row in upgrades.iterrows():
        start_iso = normalize_timestamp_to_iso_utc(row["StartTime"])
        end_iso = normalize_timestamp_to_iso_utc(row["EndTime"])
        device = str(row["DeviceName"])
        literal_rows.append(
            '    "{idx}", "{device}", datetime({start}), datetime({end})'.format(
                idx=idx, device=device, start=start_iso, end=end_iso
            )
        )

    upgrades_literal = ",\n".join(literal_rows)
    query = f"""
let upgrades = datatable(UpgradeKey: string, TorName: string, StartTime: datetime, EndTime: datetime)
[
{upgrades_literal}
];
let lo = toscalar(upgrades | summarize min(bin(StartTime, 5m)));
let hi = toscalar(upgrades | summarize max(EndTime));
let hosts = toscalar(upgrades | summarize make_set(tolower(TorName)));
let sendRecv =
    cluster('{VERITAS_CLUSTER_URI}').database('veritas').TorPingSendAggreEvent
    | where TIMESTAMP >= lo and TIMESTAMP < hi
    | where tolower(TorName) in (hosts)
    | summarize SendCount = max(SendCount) by TIMESTAMP, NodeId, TorName
    | join kind = leftouter (
        cluster('{VERITAS_CLUSTER_URI}').database('veritas').TorPingRecvAggreEvent
        | where TIMESTAMP >= lo and TIMESTAMP < hi
        | where tolower(TorName) in (hosts)
        | summarize RecvCount = max(RecvCount) by TIMESTAMP, NodeId, TorName
    ) on TIMESTAMP, NodeId, TorName
    | extend RecvCount = iff(isnull(RecvCount), 0, RecvCount)
    | extend rate = todouble(RecvCount) / todouble(SendCount) * 100
    | extend jkey = tolower(TorName);
upgrades
| extend jkey = tolower(TorName)
| join kind = inner sendRecv on jkey
| where TIMESTAMP >= bin(StartTime, 5m) and TIMESTAMP < EndTime
| where rate > {PINGMESH_DROP_LOWER_RATE} and rate < {PINGMESH_DROP_UPPER_RATE}
| summarize DropBuckets = make_list(pack(
    "Timestamp", TIMESTAMP, "NodeId", NodeId, "SendCount", SendCount, "RecvCount", RecvCount))
    by UpgradeKey
"""
    # Kusto rejects query text larger than 1 MB; if batches ever grow that large, split them.
    df = execute_kusto_query(VERITAS_CLUSTER, "veritas", query)

    # Map drop buckets back by key. Only upgrades with partial-loss buckets appear in the
    # result; any upgrade absent had no drops (or no pingmesh data) -> HasDrop False, empty list.
    buckets_by_key = {}
    if not df.empty:
        buckets_by_key = dict(zip(df["UpgradeKey"].astype(str), df["DropBuckets"]))
    return DataFrame(
        {
            "HasDrop": [str(idx) in buckets_by_key for idx in upgrades.index],
            "DropBuckets": [buckets_by_key.get(str(idx), []) for idx in upgrades.index],
        },
        index=upgrades.index,
    )


def get_warmboot_window_pingmesh_drops_batch(upgrades: DataFrame, warmboot_windows: DataFrame) -> DataFrame:
    """Flag pingmesh drops during the warm-reboot window for many upgrades (no Kusto query).

    Pure aggregator over two already-fetched result sets:

      * ``upgrades`` rows carry the upgrade-method pingmesh drops in
        ``RawData['PingMeshDropBuckets']`` (from get_upgrade_method_window_pingmesh_drops_batch).
      * ``warmboot_windows`` is the start/stop syslog result set from
        get_warmboot_window_bounds_batch (columns UpgradeKey, WbStart, WbEndRaw).

    For each upgrade the warmboot window is [WbStart, WbEnd) with WbEnd = WbEndRaw. If the
    teardown log is missing there is no end (no fallback): WbEnd is None, ``WbEndMissing`` is
    set, and the drop status is undetermined (HasDrop None). Otherwise a drop is any RawData
    bucket whose 5-minute timestamp falls in [bin(WbStart, 5m), WbEnd). Upgrades with no
    warm-reboot window at all are likewise unknown (HasDrop None, WbStart/WbEnd None).

    Returns a DataFrame aligned to ``upgrades.index`` with ``HasDrop`` (bool or None),
    ``WbStart``, ``WbEnd`` and ``WbEndMissing`` (bool).
    """
    required_columns = {"RawData"}
    missing_columns = required_columns - set(upgrades.columns)
    assert not missing_columns, f"upgrades is missing required columns: {sorted(missing_columns)}"

    result_columns = ["HasDrop", "WbStart", "WbEnd", "WbEndMissing"]
    if upgrades.empty:
        return DataFrame(columns=result_columns, index=upgrades.index)

    # Map each derived window back by key; upgrades without one keep no window (HasDrop None).
    windows_by_key = {}
    if not warmboot_windows.empty:
        for _, r in warmboot_windows.iterrows():
            wb_end_raw = r["WbEndRaw"]
            end_missing = wb_end_raw is None or wb_end_raw != wb_end_raw  # None or NaT (no teardown log)
            windows_by_key[str(r["UpgradeKey"])] = {
                "WbStart": r["WbStart"],
                "WbEnd": None if end_missing else wb_end_raw,
                "WbEndMissing": end_missing,
            }

    def _warmboot_window_has_drop(idx, wb_start, wb_end):
        # A drop is any already-detected upgrade-method bucket whose 5-minute timestamp
        # falls in the warmboot window [bin(wb_start, 5m), wb_end).
        raw = upgrades.at[idx, "RawData"]
        buckets = raw.get("PingMeshDropBuckets", []) if isinstance(raw, dict) else []
        if not buckets:
            return False
        window_lo = pd.to_datetime(wb_start, utc=True).floor("5min")
        window_hi = pd.to_datetime(wb_end, utc=True)
        for bucket in buckets:
            ts = pd.to_datetime(bucket.get("Timestamp"), utc=True)
            if window_lo <= ts < window_hi:
                return True
        return False

    has_drop, wb_start_col, wb_end_col, wb_missing_col = [], [], [], []
    for idx in upgrades.index:
        window = windows_by_key.get(str(idx))
        if window is None:
            # No derived warmboot window -> unknown outcome (None), not a definitive no-drop.
            has_drop.append(None)
            wb_start_col.append(None)
            wb_end_col.append(None)
            wb_missing_col.append(False)
            continue
        wb_end = window["WbEnd"]
        # No warmboot end found -> window is open-ended, so drop status is undetermined (None).
        has_drop.append(None if wb_end is None else _warmboot_window_has_drop(idx, window["WbStart"], wb_end))
        wb_start_col.append(window["WbStart"])
        wb_end_col.append(wb_end)
        wb_missing_col.append(window["WbEndMissing"])

    return DataFrame(
        {
            "HasDrop": has_drop,
            "WbStart": wb_start_col,
            "WbEnd": wb_end_col,
            "WbEndMissing": wb_missing_col,
        },
        index=upgrades.index,
    )


def get_host_tor_pingmesh_node_availablity_during_window(tor_name: str, start_time: str, end_time: str) -> DataFrame:
    # Query node downtime

    node_downtime_query = '''
let startTime = datetime("{startTime}");
let endTime = datetime("{endTime}");
let torName = "{torName}";
cluster('{veritasCluster}').database('veritas').TorPingSendAggreEvent
    | where TIMESTAMP >= startTime and TIMESTAMP < endTime
    | where TorName =~ torName
    | summarize SendCount = max(SendCount) by TIMESTAMP, NodeId, TorName
    | join kind = leftouter
    (
        cluster('{veritasCluster}').database('veritas').TorPingRecvAggreEvent
    | where TIMESTAMP >= startTime and TIMESTAMP < endTime
    | where TorName =~ torName
    | summarize RecvCount = max(RecvCount) by TIMESTAMP, NodeId, TorName
    )on TIMESTAMP, NodeId, TorName
    | extend RecvCount = iff(isnull(RecvCount), 0, RecvCount)
    | project TIMESTAMP, TorName, NodeId,
        Availability = todouble(RecvCount) / todouble(SendCount) * 100,
        SendCount = toint(SendCount),
        RecvCount = toint(RecvCount),
        TimeWindowInMinutes = int(5)

    '''

    query = node_downtime_query.format(
        startTime=start_time, endTime=end_time, torName=tor_name, veritasCluster=VERITAS_CLUSTER_URI
    )
    df_node_downtime = execute_kusto_query(VERITAS_CLUSTER, "veritas", query)
    return df_node_downtime


def get_host_tor_pingmesh_tor_availability_during_window(tor_name: str, start_time: str, end_time: str) -> DataFrame:
    query_template = """
let torName = '{torName}';
let startTime = datetime('{startTime}');
let endTime = datetime('{endTime}');
let nodeIdlist = (cluster('azphynet.kusto.windows.net').database('azdhmds').DeviceInterfaceLinks
                | where EndDevice =~ torName and LinkType =~ 'DeviceInterfaceLink'
                | summarize by DeviceName = StartDevice
                | join kind = inner (
                    cluster('azphynet.kusto.windows.net').database('azdhmds').Servers
                ) on DeviceName
                | summarize by NodeId);
                cluster('{veritasCluster}').database('veritas').TorPingSendAggreEvent
                | where TIMESTAMP >= bin(startTime, 5m) and TIMESTAMP <  endTime
                | where NodeId in~ (nodeIdlist)
                | summarize SendCount = max(SendCount) by TIMESTAMP, NodeId
                | join kind = leftouter (
                    cluster('{veritasCluster}').database('veritas').TorPingRecvAggreEvent
                    | where TIMESTAMP >= bin(startTime, 5m) and TIMESTAMP < endTime
                    | where NodeId in~ (nodeIdlist)
                    | summarize RecvCount = max(RecvCount) by TIMESTAMP, NodeId
                ) on TIMESTAMP, NodeId
                | extend RecvCount = iff(isnull(RecvCount), 0, RecvCount)
                | project TIMESTAMP, rate = todouble(RecvCount)/todouble(SendCount) * 100, NodeId, RecvCount, SendCount
                | summarize
                    rate = max(rate),
                    SendCount = toint(sum(SendCount)),
                    RecvCount = toint(sum(RecvCount)) by TIMESTAMP

"""

    query = query_template.format(
        startTime=start_time, endTime=end_time, torName=tor_name, veritasCluster=VERITAS_CLUSTER_URI
    )
    df_tor_downtime = execute_kusto_query(VERITAS_CLUSTER, "veritas", query)
    return df_tor_downtime


class Availability(Enum):
    NO_DROP = "NO_DROP"
    NODE_DROP = "NODE_DROP"
    TOR_DROP = "TOR_DROP"
    BOTH_DROP = "BOTH_DROP"
    INCONCLUSIVE = "INCONCLUSIVE"

    def __lt__(self, other):
        if not isinstance(other, Availability):
            return NotImplemented
        return self.value < other.value

    def __gt__(self, other):
        if not isinstance(other, Availability):
            return NotImplemented
        return self.value > other.value


def apply_all_dataplane_drop_info_on_row(row):
    """
    Apply all dataplane drop information on a row.
    """
    # Add pingmesh data
    row = add_pingmesh_data_on_row(row)

    # Filter for worst drop window
    row = filter_for_worst_drop_window_on_row(row)

    # Apply availability status
    row = apply_availability_status_on_row(row)

    # Build netvma URL
    device = row["device"]
    start_time = row["startTime"]
    end_time = row["endTime"]
    row["netvma_url"] = build_netvma_url(device, start_time, end_time)

    return row


def add_pingmesh_data_on_row(row):
    tor_name = row.at["device"]
    start_time = row.at["startTime"].isoformat()
    end_time = row.at["endTime"].isoformat()

    df_tor_pingmesh_tor_downtime = get_host_tor_pingmesh_tor_availability_during_window(tor_name, start_time, end_time)
    row["tor_availability"] = df_tor_pingmesh_tor_downtime
    df_tor_pingmesh_node_downtime = get_host_tor_pingmesh_node_availablity_during_window(tor_name, start_time, end_time)
    row["node_availability"] = df_tor_pingmesh_node_downtime

    return row


def filter_for_worst_drop_window_on_row(row):
    tor_availability = row["tor_availability"]
    if not tor_availability.empty:
        # Total the sent packets and received packets
        total_tor_sent = tor_availability["SendCount"].sum()
        total_tor_recv = tor_availability["RecvCount"].sum()
        row["tor_availability_total_pkt_sent"] = total_tor_sent
        row["tor_availability_total_pkt_recv"] = total_tor_recv
        row["tor_availability_pkts_dropped_count"] = total_tor_sent - total_tor_recv
        row["tor_availability_pkts_dropped_pct"] = (total_tor_sent - total_tor_recv) / total_tor_sent

        # Sort by rate ascending
        tor_availability = tor_availability.sort_values("rate")
        # Take the worst one
        tor_availability = tor_availability.iloc[0]
        row["tor_availability"] = tor_availability
    else:
        row["tor_availability_total_pkt_sent"] = None
        row["tor_availability_total_pkt_recv"] = None
        row["tor_availability_pkts_dropped_count"] = None
        row["tor_availability_pkts_dropped_pct"] = None

    node_availability = row["node_availability"]
    if not node_availability.empty:
        # Total the sent packets and received packets
        total_node_sent = node_availability["SendCount"].sum()
        total_node_recv = node_availability["RecvCount"].sum()

        row["node_availability_total_pkt_sent"] = total_node_sent
        row["node_availability_total_pkt_recv"] = total_node_recv
        row["node_availability_pkts_dropped_count"] = total_node_sent - total_node_recv
        row["node_availability_pkts_dropped_pct"] = (total_node_sent - total_node_recv) / total_node_sent

        # Sort by Availability ascending
        node_availability = node_availability.sort_values("Availability")
        # Take the worst one
        node_availability = node_availability.iloc[0]
        row["node_availability"] = node_availability
    else:
        row["node_availability_total_pkt_sent"] = None
        row["node_availability_total_pkt_recv"] = None
        row["node_availability_pkts_dropped_count"] = None
        row["node_availability_pkts_dropped_pct"] = None

    return row


def apply_availability_status_on_row(row):
    tor_availability_row = row["tor_availability"]
    if not tor_availability_row.empty:
        tor_availability_send_cnt = tor_availability_row["SendCount"]
        tor_availability_recv_cnt = tor_availability_row["RecvCount"]

        tor_drops = Availability.INCONCLUSIVE
        if tor_availability_send_cnt == 0 and tor_availability_recv_cnt == 0:
            tor_drops = Availability.INCONCLUSIVE
        elif (abs(tor_availability_send_cnt - tor_availability_recv_cnt)) > 5:
            tor_drops = Availability.TOR_DROP
        else:
            tor_drops = Availability.NO_DROP
    else:
        # No tor availability data
        tor_drops = Availability.INCONCLUSIVE

    node_availability_row = row["node_availability"]
    if not node_availability_row.empty:
        node_availability_send_cnt = node_availability_row["SendCount"]
        node_availability_recv_cnt = node_availability_row["RecvCount"]

        node_drops = Availability.INCONCLUSIVE
        if node_availability_send_cnt == 0 and node_availability_recv_cnt == 0:
            node_drops = Availability.INCONCLUSIVE
        elif (abs(node_availability_send_cnt - node_availability_recv_cnt)) > 5:
            node_drops = Availability.NODE_DROP
        else:
            node_drops = Availability.NO_DROP
    else:
        # No node availability data
        node_drops = Availability.INCONCLUSIVE

    consolidated_status = Availability.INCONCLUSIVE

    # Consolidate status
    if tor_drops == Availability.NO_DROP:
        if node_drops == Availability.NO_DROP:
            consolidated_status = Availability.NO_DROP
        elif node_drops == Availability.NODE_DROP:
            consolidated_status = Availability.NODE_DROP
        elif node_drops == Availability.INCONCLUSIVE:
            consolidated_status = Availability.INCONCLUSIVE
        else:
            raise ValueError(f"Unexpected node_drops value: {node_drops}")
    elif tor_drops == Availability.TOR_DROP:
        if node_drops == Availability.NO_DROP:
            consolidated_status = Availability.TOR_DROP
        elif node_drops == Availability.NODE_DROP:
            consolidated_status = Availability.BOTH_DROP
        elif node_drops == Availability.INCONCLUSIVE:
            consolidated_status = Availability.TOR_DROP
        else:
            raise ValueError(f"Unexpected node_drops value: {node_drops}")
    elif tor_drops == Availability.INCONCLUSIVE:
        if node_drops == Availability.NO_DROP:
            consolidated_status = Availability.INCONCLUSIVE
        elif node_drops == Availability.NODE_DROP:
            consolidated_status = Availability.NODE_DROP
        elif node_drops == Availability.INCONCLUSIVE:
            consolidated_status = Availability.INCONCLUSIVE
        else:
            raise ValueError(f"Unexpected node_drops value: {node_drops}")
    else:
        raise ValueError(f"Unexpected tor_drops value: {tor_drops}")

    row["consolidated_status"] = consolidated_status

    return row


def build_netvma_url(device_name, start_time, end_time):
    base_url = "https://netvma.azure.net/"

    def _format(t):
        # Produce "YYYY-MM-DD HH:MM:SS" (no fractional seconds, no timezone)
        if hasattr(t, "strftime"):
            return t.strftime("%Y-%m-%d %H:%M:%S")
        return str(t)

    params = {
        "startTime": _format(start_time),
        "endTime": _format(end_time),
        "value": device_name
    }
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    return url


def get_t1_peers_bgp_flap_logs_in_time_window(tor_name: str, start_time: str, end_time: str):
    query = f'''

let tor_name = "{tor_name}";
let startTime = datetime("{start_time}");
let endTime = datetime("{end_time}");
let peer_t1_devices= cluster('azphynet.kusto.windows.net').database('azdhmds').DeviceInterfaceLinks
| where StartDevice =~ tor_name
| where LinkType =~ "DeviceInterfaceLink"
| project StartDevice=tolower(StartDevice), EndDevice=tolower(EndDevice)
| distinct EndDevice;
cluster('azphynet.kusto.windows.net').database('azdhmds').SyslogData
| where Device in~ (peer_t1_devices)
| where TIMESTAMP between (startTime .. endTime)
| where
    Message matches regex ".*teamd_PortChannel[0-9]{4}.*: carrier changed to DOWN.*"
    or Message matches regex ".*updatePortOperStatus: Port PortChannel[0-9]{4}.* oper state set from up to down"
    or Message matches regex ".*updatePortOperStatus: Port PortChannel[0-9]{4}.* oper state set from down to up"
| project TIMESTAMP, Device, Message


'''
    df_t1_peers_bgp_flap_logs = execute_kusto_query("azphynet", "azdhmds", query)
    return df_t1_peers_bgp_flap_logs
