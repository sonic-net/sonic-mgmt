from utilities.kusto import execute_kusto_query
from typing import List
from pandas import DataFrame

def get_devices_by_names(device_names: List[str]) -> DataFrame:
    formatted_devices = ', '.join([f'"{device}"' for device in device_names])
    query = f'''
let devices = dynamic([{formatted_devices}]);
cluster('azphynet').database('azphynetmds').Devices()
| where DeviceName in~ (devices)
| project DeviceName, FirmwareProfile, HardwareSku, OSVersion
    '''

    df_devices = execute_kusto_query("azphynet", "azphynetmds", query)
    return df_devices


def get_runtime_hours_by_version_and_hwsku(os_version: str, hardware_sku: str) -> DataFrame:
    query = f'''

cluster('azphynet').database("dhMonitoring").LatestVersionRunHours() 
| where HardwareSku contains '{hardware_sku}' // replace the hwsku here 
| summarize VersionRunHour=sum(VersionRunHour), VersionDeviceCount=sum(VersionDeviceCount) by OSVersion 
| where OSVersion contains "{os_version}"  // replace the OS version here 
| where VersionDeviceCount != 0

'''
    df_devices = execute_kusto_query("azphynet", "dhMonitoring", query)
    return df_devices