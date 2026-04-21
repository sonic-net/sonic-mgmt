try:
    from ..provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from ..common.ansible_common import log_entry_exit, get_default_value
    from ..model.vsp_storage_system_models import (
        VSPSyslogConfig,
        VSPDeviceLimits,
        VSPNormalizedFreeLun,
    )
    from ..common.ansible_common import camel_to_snake_case
except ImportError:
    from provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from common.ansible_common import log_entry_exit, get_default_value
    from model.vsp_storage_system_models import (
        VSPSyslogConfig,
        VSPDeviceLimits,
        VSPNormalizedFreeLun,
    )
    from common.ansible_common import camel_to_snake_case


class VSPStorageSystemReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        self.serial = serial
        self.provisioner = VSPStorageSystemProvisioner(self.connection_info)

    @log_entry_exit
    def storage_system_reconcile(self, spec):
        if spec.date_time is not None:
            return self.provisioner.set_storage_system_date_time(spec.date_time)
        return self.provisioner.get_storage_system(None, None)

    @log_entry_exit
    def get_storage_system(self, get_storage_system_spec):
        return self.provisioner.get_storage_system(
            self.serial, get_storage_system_spec.query
        )


class VSPStorageSystemCommonPropertiesExtractor:
    def __init__(self):
        self.common_properties = {
            "model": str,
            "serialNumber": str,
            "microcodeVersion": str,
            "managementAddress": str,
            "controllerAddress": str,
            "totalCapacity": str,
            "totalCapacityInMb": int,
            "freeCapacity": str,
            "freeCapacityInMb": int,
            "resourceState": str,
            "healthStatus": str,
            "operationalStatus": str,
            "freeGadConsistencyGroupId": int,
            "freeLocalCloneConsistencyGroupId": int,
            "freeRemoteCloneConsistencyGroupId": int,
            "syslogConfig": VSPSyslogConfig,
            "deviceLimits": VSPDeviceLimits,
            "healthDescription": str,
            "journalPools": list,
            "ports": list,
            "storagePools": list,
            "quorumDisks": list,
            "freeLogicalUnitList": VSPNormalizedFreeLun,
            "totalEfficiency": dict,
            "systemDateTime": dict,
            "TimeZonesInfo": dict,
        }

    def extract(self, response):
        new_dict = {}
        for key, value_type in self.common_properties.items():
            # Get the corresponding key from the response or its mapped key
            cased_key = camel_to_snake_case(key)
            response_key = None
            if key in response:
                response_key = response.get(key)
            elif cased_key in response:
                response_key = response.get(cased_key)
            # Assign the value based on the response key and its data type

            if response_key is not None:
                unchanged_types = [
                    "syslogConfig",
                    "deviceLimits",
                    "freeLogicalUnitList",
                    "TimeZonesInfo",
                ]
                if key in unchanged_types:
                    new_dict[cased_key] = response_key
                else:
                    new_dict[cased_key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                query_keys = [
                    "journalPools",
                    "ports",
                    "storagePools",
                    "quorumDisks",
                    "freeLogicalUnitList",
                ]
                if key not in query_keys:
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
        return new_dict
