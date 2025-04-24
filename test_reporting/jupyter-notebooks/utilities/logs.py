from typing import List

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
let rgx = @"syncd#syncd.+restore count (\d+)";
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