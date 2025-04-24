from utilities.kusto import execute_kusto_query
from pandas import DataFrame

def get_devices_in_schedule(scheduleId: str) -> DataFrame:
    """
    Get the devices in the schedule.
    """
    
    query = f'''

cluster("Azwan").database("FUSE").FuseDevice
| where scheduleIdentifier == "{scheduleId}"
| distinct device=tolower(device)
| join cluster('azphynet').database('azphynetmds').Devices() on $left.device == $right.DeviceName

'''
    
    df_devices_with_config = execute_kusto_query("azwan", "FUSE", query)
    return df_devices_with_config


def get_successful_FirmwareUpgrades_to_version_for_schedule(schedule_id: str, version: str) -> DataFrame:
    """
    Get the successful firmware upgrades to a specific version for a schedule.
    """
    
    query = f'''

cluster("Azwan").database("FUSE").FUSE
| where jobResult contains "Success"
| where action == "FirmwareUpgrade"
| where metaData contains "{version}"
| where scheduleIdentifier == "{schedule_id}"
| project device=tolower(device), startTime, endTime

'''
    
    df_successful_firmware_upgrades = execute_kusto_query("azwan", "FUSE", query)
    return df_successful_firmware_upgrades