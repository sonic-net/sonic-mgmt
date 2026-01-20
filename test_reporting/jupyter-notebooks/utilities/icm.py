from typing import List

from utilities.kusto import execute_kusto_query


def get_all_icms_since_time_ago(devices: List[str], time_ago: str):

    formatted_devices = ', '.join([f'"{device}"' for device in devices])
    query = f'''

let devices = dynamic([{formatted_devices}]);
cluster('azphynet').database("IcMDataWarehouse").Incidents
| where SourceCreateDate > ago({time_ago})
| where OccurringDeviceName in~ (devices)
| summarize arg_max(SourceModifiedDate, *) by IncidentId
| project IncidentId, SourceModifiedDate, SourceCreateDate, CreateDate, OccurringDeviceName, Severity, Status, Title
'''
    df_t1_peers_bgp_flap_logs = execute_kusto_query("azphynet", "azdhmds", query)
    return df_t1_peers_bgp_flap_logs
