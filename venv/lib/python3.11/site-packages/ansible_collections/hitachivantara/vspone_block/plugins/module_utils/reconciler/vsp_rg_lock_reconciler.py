try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_rg_lock_provisioner import VSPResourceGroupLockProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
    )
    from common.hv_log import Log
    from ..common.hv_constants import StateValue
    from provisioner.vsp_rg_lock_provisioner import VSPResourceGroupLockProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

logger = Log()


class VSPResourceGroupLockReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.connection_info = connection_info
        self.provisioner = VSPResourceGroupLockProvisioner(connection_info, serial)
        self.storage_serial_number = serial
        if state:
            self.state = state

    @log_entry_exit
    def reconcile_rg_lock(self, spec):
        try:
            if self.state == StateValue.PRESENT:
                response = self.provisioner.lock_resource_group(spec)
                logger.writeDebug("RC:reconcile_rg_lock:response={}", response)
                # if response is not None and isinstance(response, str):
                #     return response
                resp_dict = response.to_dict() if response else {}
                logger.writeDebug("RC:reconcile_rg_lock:resp_dict={}", resp_dict)
                if self.storage_serial_number is None:
                    self.storage_serial_number = self.get_storage_serial_number()
                extracted_data = ResourceGroupLockInfoExtractor(
                    self.storage_serial_number
                ).extract([resp_dict])[0]
                logger.writeDebug(
                    "RC:reconcile_rg_lock:extracted_data={}", extracted_data
                )
                return extracted_data

            elif self.state == StateValue.ABSENT:
                response = self.provisioner.unlock_resource_group(spec)
                if isinstance(response, str):
                    return response
                return None
        except Exception as e:
            logger.writeError(f"RC:reconcile_rg_lock: {str(e)}")
            err_msg = str(e)
            # index = err_msg.find("%!(EXTRA ")
            # logger.writeDebug("RC:reconcile_rg_lock:index={}", index)
            # if index != -1:
            #     err_msg = err_msg[:index]
            raise ValueError(err_msg)

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber


class ResourceGroupLockInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "lock_session_id": int,
            "lock_token": str,
            "remote_lock_session_id": int,
            "remote_lock_token": str,
            "locked_resource_groups": list,
            "remote_locked_resource_groups": list,
            "resourceGroupName": str,
            "resourceGroupId": int,
            "virtualDeviceId": str,
            "virtualDeviceType": str,
            "locked": bool,
            "metaResourceSerial": str,
        }

    @log_entry_exit
    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # if value_type == list:
                #     response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type.
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    # if cased_key in self.parameter_mapping.keys():
                    #     cased_key = self.parameter_mapping[cased_key]
                    new_dict[cased_key] = value_type(response_key)
                # else:
                #     # Handle missing keys by assigning default values
                #     default_value = get_default_value(value_type)
                #     new_dict[key] = default_value
            new_items.append(new_dict)

        return new_items
