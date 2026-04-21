try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        camel_dict_to_snake_case,
        get_default_value,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_local_copy_group_provisioner import (
        VSPLocalCopyGroupProvisioner,
    )
    from ..model.vsp_local_copy_group_models import (
        LocalCopyGroupSpec,
        LocalCopyGroupInfo,
        LocalCopyGroupInfoList,
        LocalSpecificCopyGroupInfo,
    )

except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        camel_dict_to_snake_case,
        get_default_value,
    )
    from common.hv_log import Log
    from provisioner.vsp_local_copy_group_provisioner import (
        VSPLocalCopyGroupProvisioner,
    )
    from model.vsp_local_copy_group_models import (
        LocalCopyGroupSpec,
        LocalCopyGroupInfo,
        LocalCopyGroupInfoList,
        LocalSpecificCopyGroupInfo,
    )


logger = Log()


class VSPLocalCopyGroupReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.logger = Log()
        self.connection_info = connection_info
        self.provisioner = VSPLocalCopyGroupProvisioner(connection_info, serial)
        if state is not None:
            self.state = state
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.provisioner.get_storage_serial()

    @log_entry_exit
    def get_local_copy_group_facts(self, spec):

        copy_groups = self.provisioner.get_local_copy_groups(spec)
        self.logger.writeDebug("RC:local_copy_groups={}", copy_groups)

        if copy_groups is None:
            return "Operations cannot be performed for the specified copy group {}. ErrorCode: 30000E-0".format(
                spec.name
            )
        elif isinstance(copy_groups, LocalSpecificCopyGroupInfo):
            copy_groups = copy_groups.to_dict()
            return camel_dict_to_snake_case(copy_groups)
        elif isinstance(copy_groups, LocalCopyGroupInfo):
            copy_groups = [copy_groups.to_dict()]
        elif isinstance(copy_groups, LocalCopyGroupInfoList):
            copy_groups = copy_groups.data_to_list()
        self.logger.writeDebug(
            "RC:get_remote_copy_groups_facts:copy_groups={}", copy_groups
        )

        extracted_data = LocalCopyGroupInfoExtractor(
            self.storage_serial_number
        ).extract(copy_groups)
        return extracted_data

    @log_entry_exit
    def delete_copy_group(self, spec):
        return self.provisioner.delete_local_copy_group(spec)

    @log_entry_exit
    def resync_copy_group(self, spec):
        return self.provisioner.resync_local_copy_group(spec)

    @log_entry_exit
    def split_copy_group(self, spec):
        return self.provisioner.split_local_copy_group(spec)

    @log_entry_exit
    def migrate_copy_group(self, spec):
        return self.provisioner.migrate_local_copy_group(spec)

    @log_entry_exit
    def restore_copy_group(self, spec):
        return self.provisioner.restore_local_copy_group(spec)

    @log_entry_exit
    def local_copy_group_reconcile_direct(
        self, state: str, spec: LocalCopyGroupSpec  # , secondary_connection_info: str
    ):
        state = state.lower()
        # if self.secondary_connection_info is None:
        #     raise ValueError(VSPCopyGroupsValidateMsg.SECONDARY_CONNECTION_INFO.value)
        # else:
        #     spec.secondary_connection_info = secondary_connection_info

        resp_data = None
        if state == StateValue.SPLIT:
            resp_data = self.split_copy_group(spec)
        elif state == StateValue.RE_SYNC or state == StateValue.SYNC:
            resp_data = self.resync_copy_group(spec)
        elif state == StateValue.RESTORE:
            resp_data = self.restore_copy_group(spec)
        elif state == StateValue.ABSENT:
            resp_data = self.delete_copy_group(spec)
        elif state == StateValue.MIGRATE:
            resp_data = self.migrate_copy_group(spec)
        else:
            return

        if resp_data:
            logger.writeDebug("RC:resp_data={}  state={}", resp_data, state)

            if isinstance(resp_data, str):
                return resp_data
            elif isinstance(resp_data, LocalSpecificCopyGroupInfo):
                copy_groups = resp_data.to_dict()
                logger.writeDebug(
                    "copy group dict={}", camel_dict_to_snake_case(copy_groups)
                )
                return camel_dict_to_snake_case(copy_groups)
        else:
            return None


class LocalCopyGroupInfoExtractor:
    def __init__(self, serial, secondary_serial=None):
        self.storage_serial_number = serial
        self.common_properties = {
            "copyGroupName": str,
            "localCloneCopygroupId": str,
            "pvolDeviceGroupName": str,
            "svolDeviceGroupName": str,
        }

        self.parameter_mapping = {
            # "mu_number": "mirror_unit_id",
            # "remote_serial_number": "secondary_storage_serial",
            # "serial_number": "primary_storage_serial",
        }

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
                if (
                    new_dict.get("ldev_hex_id") == ""
                    or new_dict.get("ldev_hex_id") is None
                ):
                    if new_dict.get("ldev_id") is not None or new_dict.get("ldev_id"):
                        new_dict["ldev_hex_id"] = volume_id_to_hex_format(
                            new_dict.get("ldev_id")
                        )
                if (
                    new_dict.get("capacity_in_unit") == ""
                    or new_dict.get("capacit_in_unit") is None
                ):
                    if new_dict.get("byte_format_capacity") is not None or new_dict.get(
                        "byte_format_capacity"
                    ):
                        old_value = new_dict.pop("byte_format_capacity")
                        new_value = old_value.replace(" G", "GB")
                        new_dict["capacity_in_unit"] = new_value
            new_items.append(new_dict)
        return new_items

    @log_entry_exit
    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                if value_type == list:
                    response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    if cased_key in self.parameter_mapping.keys():
                        cased_key = self.parameter_mapping[cased_key]
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            if new_dict.get("primary_hex_volume_id") == "":
                new_dict["primary_hex_volume_id"] = volume_id_to_hex_format(
                    new_dict.get("primary_volume_id")
                )
            if new_dict.get("secondary_hex_volume_id") == "":
                new_dict["secondary_hex_volume_id"] = volume_id_to_hex_format(
                    new_dict.get("secondary_volume_id")
                )
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
            # if "v_s_m" in cased_key:
            #     cased_key = self.fix_bad_camel_to_snake_conversion(cased_key)
            if response_key is not None:
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                new_dict[cased_key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[cased_key] = default_value

        if new_dict.get("primary_hex_volume_id") == "":
            new_dict["primary_hex_volume_id"] = volume_id_to_hex_format(
                new_dict.get("primary_volume_id")
            )
        if new_dict.get("secondary_hex_volume_id") == "":
            new_dict["secondary_hex_volume_id"] = volume_id_to_hex_format(
                new_dict.get("secondary_volume_id")
            )

        return new_dict
