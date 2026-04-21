try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_remote_storage_registration_provisioner import (
        VSPRemoteStorageRegistrationProvisioner,
    )
except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from common.hv_log import Log
    from common.hv_constants import StateValue


logger = Log()


class VSPRemoteStorageRegistrationReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.connection_info = connection_info
        self.provisioner = VSPRemoteStorageRegistrationProvisioner(
            connection_info, serial
        )
        if state:
            self.state = state
        if serial:
            self.storage_serial_number = serial

    @log_entry_exit
    def reconcile_remote_storage_registration(self, spec):

        if self.state == StateValue.PRESENT:

            response = self.register_remote_storage(spec)
            logger.writeDebug(
                "RC:reconcile_remote_storage_registration:response={}", response
            )

            if isinstance(response, str):
                return response

            volume_dict = response.to_dict() if response else {}
            logger.writeDebug(
                "RC:reconcile_remote_storage_registration:response={}", response
            )
            extracted_data = RemoteStorageRegistrationExtractor().extract(
                [volume_dict]
            )[0]
            logger.writeDebug(
                "RC:reconcile_remote_storage_registration:extracted_data={}",
                extracted_data,
            )
            return extracted_data

        elif self.state == StateValue.ABSENT:
            return self.unregister_remote_storage(spec)

    @log_entry_exit
    def get_remote_storage_registration_facts(self, spec):
        all_storages = self.provisioner.get_remote_storage_registration_facts(spec)
        extracted_data = RemoteStorageRegistrationExtractor().extract(
            [all_storages.to_dict()]
        )
        return extracted_data

    @log_entry_exit
    def register_remote_storage(self, spec):
        try:
            resp = self.provisioner.register_remote_storage(spec)
            return resp
        except Exception as e:
            logger.writeError("RC:register_remote_storage:exception={}", e)
            return str(e)

    @log_entry_exit
    def unregister_remote_storage(self, spec):
        try:
            self.provisioner.delete_remote_storage(spec)
            return None
        except Exception as e:
            logger.writeError("RC:unregister_remote_storage:exception={}", e)
            return str(e)


class RemoteStorageRegistrationExtractor:
    def __init__(self):
        # self.storage_serial_number = serial
        self.common_properties = {
            "storagesRegisteredInLocal": list,
            "storagesRegisteredInRemote": list,
        }

    @log_entry_exit
    def change_keys(self, response_key):
        new_dict = {}
        if not response_key:
            return new_dict
        for key, value in response_key.items():
            key = camel_to_snake_case(key)
            value_type = type(value)
            if value is None:
                default_value = get_default_value(value_type)
                value = default_value
            new_dict[key] = value
            # if new_dict.get("ldev_hex_id") == "" or new_dict.get("ldev_hex_id") is None:
            #     if new_dict.get("ldev_id") is not None or new_dict.get("ldev_id"):
            #         new_dict["ldev_hex_id"] = volume_id_to_hex_format(
            #             new_dict.get("ldev_id")
            #         )
        return new_dict

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []

        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)
                if value is None:
                    default_value = get_default_value(value_type)
                    value = default_value
                new_dict[key] = value
                # if (
                #     new_dict.get("ldev_hex_id") == ""
                #     or new_dict.get("ldev_hex_id") is None
                # ):
                #     if new_dict.get("ldev_id") is not None or new_dict.get("ldev_id"):
                #         new_dict["ldev_hex_id"] = volume_id_to_hex_format(
                #             new_dict.get("ldev_id")
                #         )
                # if (
                #     new_dict.get("capacity_in_unit") == ""
                #     or new_dict.get("capacit_in_unit") is None
                # ):
                #     if new_dict.get("byte_format_capacity") is not None or new_dict.get(
                #         "byte_format_capacity"
                #     ):
                #         old_value = new_dict.pop("byte_format_capacity")
                #         new_value = old_value.replace(" G", "GB")
                #         new_dict["capacity_in_unit"] = new_value
            new_items.append(new_dict)
        return new_items

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {}
            # new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # if value_type == dict:
                #     response_key = self.change_keys(response_key)
                if value_type == list:
                    response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
