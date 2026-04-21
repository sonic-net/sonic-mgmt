from typing import Any

try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from ..common.hv_log import Log
    from ..provisioner.vsp_vol_tier_provisioner import VSPVolTierProvisioner

except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from common.hv_log import Log
    from provisioner.vsp_vol_tier_provisioner import VSPVolTierProvisioner


class VSPVolTierReconciler:
    def __init__(self, connection_info, serial, state):

        self.logger = Log()
        self.connectionInfo = connection_info
        self.storage_serial_number = serial
        self.provisioner = VSPVolTierProvisioner(connection_info, serial)
        self.state = state
        self.common_properties = {}

    # 20240822 VSPVolTierReconciler
    @log_entry_exit
    def reconcile(self, spec: Any) -> Any:
        self.provisioner.apply_vol_tiering(spec)

    # F811 Redefinition of unused `__init__`
    # def __init__(self, serial):
    #     self.storage_serial_number = serial
    #     self.common_properties = {
    #         # "resourceId": str,
    #         "consistencyGroupId": int,
    #         "copyPaceTrackSize": int,
    #         "copyRate": int,
    #         "mirrorUnitId": int,
    #         "pairName": str,
    #         "primaryHexVolumeId": str,
    #         "primaryVSMResourceGroupName": str,
    #         "primaryVirtualHexVolumeId": str,
    #         "primaryVirtualStorageId": str,
    #         "primaryVirtualVolumeId": int,
    #         "primaryVolumeId": int,
    #         "primaryVolumeStorageId": int,
    #         "secondaryHexVolumeId": str,
    #         "secondaryVSMResourceGroupName": str,
    #         "secondaryVirtualStorageId": str,
    #         "secondaryVirtualVolumeId": int,
    #         "secondaryVolumeId": int,
    #         "secondaryVolumeStorageId": int,
    #         "status": str,
    #         "svolAccessMode": str,
    #         "type": str,
    #         "secondaryVirtualHexVolumeId": int,
    #         "entitlementStatus": str,
    #         "partnerId": str,
    #         "subscriberId": str,
    #     }

    @log_entry_exit
    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {
                "storage_serial_number": self.storage_serial_number,
            }
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value

            # new_dict["partner_id"] = "apiadmin"
            new_items.append(new_dict)
        return new_items

    @log_entry_exit
    def extract_dict(self, response):
        new_dict = {"storage_serial_number": self.storage_serial_number}
        for key, value_type in self.common_properties.items():
            # Get the corresponding key from the response or its mapped key
            response_key = response.get(key)
            # Assign the value based on the response key and its data type
            cased_key = camel_to_snake_case(key)
            if response_key is not None:
                new_dict[cased_key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[cased_key] = default_value
                # new_dict["partner_id"] = "apiadmin"
        return new_dict
