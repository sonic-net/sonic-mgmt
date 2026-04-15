from typing import List, Optional

from utilities.kusto import execute_kusto_query


def get_devices_with_excessive_syslog(devices: List[str]):

    formatted_devices = ', '.join([f'"{device}"' for device in devices])
    query = f'''

let devices = dynamic([{formatted_devices}]);
cluster('azphynet.kusto.windows.net').database('HwSwHealth').dhExceessiveSyslogs
| where TIMESTAMP > ago(2h)
| where DeviceName in~ (devices)
| summarize arg_max(TIMESTAMP, *) by DeviceName
| project DeviceName, FailureReason, MetricValue_Count
'''
    df_res = execute_kusto_query("azphynet", "HwSwHealth", query)
    return df_res


def get_syncd_restore_count(device: str, start_time: str, end_time: str):
    """
    Get the syncd restore count in the specified time window.

    """

    query = f'''

let startTime = datetime({start_time});
let endTime = datetime({end_time});
let rgx = @"syncd#syncd.+restore count (\\d+)";
let restoreCounts = cluster('azphynet.kusto.windows.net').database('azdhmds').SyslogData
| where Device =~ "{device}"
| where TIMESTAMP between (startTime .. endTime)
| where Message matches regex rgx
| extend restore_count = extract(rgx, 1, Message)
| project restore_count;
let summaryMessage = restoreCounts
| summarize row_count = count()
| extend output = case(
    row_count == 0, "No warm-reboot count found",
    row_count == 1, strcat("warm-reboot count: ", toscalar(restoreCounts | project restore_count)),
    strcat("Error: More than one warm-reboot count found (", row_count, ")")
)
| project output;
summaryMessage;

'''
    df_res = execute_kusto_query("azphynet", "azdhmds", query)
    result = df_res.iloc[0, 0]
    return result


def get_syslog_for_device_in_window(
    device: str,
    start_time: str,
    end_time: str,
    message_regex: Optional[str] = None,
):
    """
    Fetch syslog rows for a device in a time window.
    If message_regex is provided, filter to only messages matching that KQL regex.
    """

    regex_clause = ""
    if message_regex:
        # KQL expects the regex as a verbatim string literal: @"..."
        safe = message_regex.replace('"', r'\"')
        regex_clause = f'| where Message matches regex @"{safe}"'

    query = f'''
let startTime = datetime({start_time});
let endTime = datetime({end_time});

cluster('azphynet.kusto.windows.net').database('azdhmds').SyslogData
| where Device =~ "{device}"
| where TIMESTAMP between (startTime .. endTime)
| where Message notcontains "audisp"
| where Message notcontains "audisp-syslog:"
| where Message notcontains "auditlogger["
| where Message notcontains "macsec_mka["
{regex_clause}
| project
    Timestamp = TIMESTAMP,
    Device,
    Message
| order by Timestamp asc
'''
    df_res = execute_kusto_query("azphynet", "azdhmds", query)
    return df_res
