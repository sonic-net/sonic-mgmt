import urllib
from enum import Enum
from pandas import DataFrame
from utilities.kusto import execute_kusto_query


def get_host_tor_pingmesh_node_availablity_during_window(tor_name: str, start_time: str, end_time: str) -> DataFrame:

    # Query node downtime

    node_downtime_query = '''
let startTime = datetime("{startTime}");
let endTime = datetime("{endTime}");
let torName = "{torName}";
let dataplaneLoss = (startTime: datetime, endTime: datetime, torName: string  ) {{
cluster('aznwsdn.kusto.windows.net').database('aznwmds').TorPingSendAggreEvent
    | where TIMESTAMP >= startTime and TIMESTAMP < endTime
    | where TorName =~ torName
    | summarize SendCount = max(SendCount) by TIMESTAMP, NodeId, TorName
    | join kind = leftouter
    (
        cluster('aznwsdn.kusto.windows.net').database('aznwmds').TorPingRecvAggreEvent
    | where TIMESTAMP >= startTime and TIMESTAMP < endTime 
    | where TorName =~ torName
    | summarize RecvCount = max(RecvCount) by TIMESTAMP, NodeId, TorName
    )on TIMESTAMP, NodeId, TorName
    | extend RecvCount = iff(isnull(RecvCount), 0, RecvCount)
    | project TIMESTAMP, TorName, NodeId, Availability = todouble(RecvCount) / todouble(SendCount) * 100, SendCount = toint(SendCount), RecvCount = toint(RecvCount), TimeWindowInMinutes = int(5)
}};
dataplaneLoss(startTime, endTime, torName);

    '''

    query = node_downtime_query.format(startTime=start_time, endTime=end_time, torName=tor_name)
    df_node_downtime = execute_kusto_query("aznwsdn", "aznwmds", query)
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
                cluster('aznwsdn.kusto.windows.net').database('aznwmds').TorPingSendAggreEvent
                | where TIMESTAMP >= bin(startTime, 5m) and TIMESTAMP <  endTime
                | where NodeId in~ (nodeIdlist) 
                | summarize SendCount = max(SendCount) by TIMESTAMP, NodeId
                | join kind = leftouter (
                    cluster('aznwsdn.kusto.windows.net').database('aznwmds').TorPingRecvAggreEvent
                    | where TIMESTAMP >= bin(startTime, 5m) and TIMESTAMP < endTime  
                    | where NodeId in~ (nodeIdlist) 
                    | summarize RecvCount = max(RecvCount) by TIMESTAMP, NodeId
                ) on TIMESTAMP, NodeId
                | extend RecvCount = iff(isnull(RecvCount), 0, RecvCount)
                | project TIMESTAMP, rate = todouble(RecvCount)/todouble(SendCount) * 100, NodeId, RecvCount, SendCount
                | summarize rate = todouble(sum(RecvCount)) / todouble(sum(SendCount)) * 100, SendCount = toint(sum(SendCount)), RecvCount = toint(sum(RecvCount)) by TIMESTAMP

"""

    query = query_template.format(startTime=start_time, endTime=end_time, torName=tor_name)
    df_tor_downtime = execute_kusto_query("azphynet", "azdhmds", query)
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
    params = {
        "startTime": start_time,
        "endTime": end_time,
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
| where Message matches regex ".*teamd_PortChannel[0-9]{4}.*: carrier changed to DOWN.*" or Message matches regex ".*updatePortOperStatus: Port PortChannel[0-9]{4}.* oper state set from up to down" or Message matches regex ".*updatePortOperStatus: Port PortChannel[0-9]{4}.* oper state set from down to up"
| project TIMESTAMP, Device, Message


'''
    df_t1_peers_bgp_flap_logs = execute_kusto_query("azphynet", "azdhmds", query)
    return df_t1_peers_bgp_flap_logs

