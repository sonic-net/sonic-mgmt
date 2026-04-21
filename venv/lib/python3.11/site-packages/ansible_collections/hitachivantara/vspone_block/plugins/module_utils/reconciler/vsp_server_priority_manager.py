try:
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
        volume_id_to_hex_format,
    )
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_spm_provisioner import (
        VSPServerPriorityManagerProvisioner,
    )
    from ..model.vsp_server_priority_manager_models import (
        SpmFactSpec,
        SpmSetObject,
        SpmChangeObject,
    )
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

except ImportError:
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
        volume_id_to_hex_format,
    )
    from common.hv_constants import StateValue
    from provisioner.vsp_spm_provisioner import (
        VSPServerPriorityManagerProvisioner,
    )
    from ..model.vsp_server_priority_manager_models import (
        SpmFactSpec,
        SpmSetObject,
        SpmChangeObject,
    )
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

logger = Log()


class VSPServerPriorityManagerReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        if serial is None:
            self.serial = self.get_storage_serial_number()
        self.provisioner = VSPServerPriorityManagerProvisioner(
            self.connection_info, self.serial
        )

    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def server_priority_manager_facts(self, spec: SpmFactSpec = None):
        if spec.is_empty():
            rsp = self.provisioner.get_all_spms()
            if rsp is None:
                rsp = []
            logger.writeInfo(f"server_priority_manager_facts={rsp}")
            extracted_data = ServerPriorityManagerInfoExtractor(self.serial).extract(
                rsp.data_to_list()
            )
            return extracted_data
        elif spec.ldev_id and (spec.host_wwn or spec.iscsi_name):
            return self.get_one_spm_extracted(spec)
        else:
            return self.get_spms_with_query(spec)

    @log_entry_exit
    def get_spms_with_query(self, spec):
        rsp = self.provisioner.get_spms_with_query(
            spec.ldev_id, spec.host_wwn, spec.iscsi_name
        )
        if rsp is None:
            rsp = []
        logger.writeInfo(f"server_priority_manager_facts={rsp}")
        extracted_data = ServerPriorityManagerInfoExtractor(self.serial).extract(
            rsp.data_to_list()
        )
        return extracted_data

    @log_entry_exit
    def get_one_spm(self, spec):
        hba = None
        if spec.host_wwn:
            hba = spec.host_wwn
        elif spec.iscsi_name:
            hba = spec.iscsi_name
        rsp = self.provisioner.get_one_spm(spec.ldev_id, hba)

        return rsp

    @log_entry_exit
    def get_one_spm_extracted(self, spec):
        rsp = self.get_one_spm(spec)
        if rsp is None:
            rsp = []
        logger.writeDebug(f"external_spm_facts={rsp}")
        extracted_data = ServerPriorityManagerInfoExtractor(self.serial).extract(
            [rsp.to_dict()]
        )
        logger.writeDebug(f"external_spm_facts:extracted_data={extracted_data}")
        return extracted_data

    @log_entry_exit
    def spm_reconcile(self, state, spec):
        spm = self.get_one_spm(spec)
        if state == StateValue.PRESENT:
            if spm is None:
                rsp = self.set_spm(spec)
                msg = "Server Priority Manager information set successfully."
            else:
                rsp = self.change_spm(spm, spec)
                if self.connection_info.changed:
                    msg = "Server Priority Manager information changed successfully."
                else:
                    msg = "Server Priority Manager information change not needed."
            rsp = self.get_one_spm_extracted(spec)
            return rsp, msg
        elif state == StateValue.ABSENT:
            rsp = self.delete_spm(spec)
            self.connection_info.changed = True
            return "Server Priority Manager information deleted successfully.", None

    @log_entry_exit
    def set_spm(self, spec):
        spm_set_object = SpmSetObject()
        spm_set_object.ldev_id = spec.ldev_id
        spm_set_object.host_wwn = spec.host_wwn
        spm_set_object.iscsi_name = spec.iscsi_name
        spm_set_object.upper_limit_for_iops = spec.upper_limit_for_iops
        spm_set_object.upper_limit_for_transfer_rate_in_MBps = (
            spec.upper_limit_for_transfer_rate_in_MBps
        )

        self.connection_info.changed = True
        return self.provisioner.set_spm(spm_set_object)

    @log_entry_exit
    def change_spm(self, spm_object, spec):
        hba = None
        if spec.host_wwn:
            hba = spec.host_wwn
        elif spec.iscsi_name:
            hba = spec.iscsi_name

        change_needed = False
        if spec.upper_limit_for_iops:
            if spm_object.upperLimitForIops != spec.upper_limit_for_iops:
                change_needed = True
        if spec.upper_limit_for_transfer_rate_in_MBps:
            if (
                spm_object.upperLimitForTransferRate
                != spec.upper_limit_for_transfer_rate_in_MBps
            ):
                change_needed = True

        if change_needed:
            spm_change_object = SpmChangeObject()
            spm_change_object.upper_limit_for_iops = spec.upper_limit_for_iops
            spm_change_object.upper_limit_for_transfer_rate_in_MBps = (
                spec.upper_limit_for_transfer_rate_in_MBps
            )

            self.connection_info.changed = True
            return self.provisioner.change_spm(spec.ldev_id, hba, spm_change_object)
        else:
            return spm_object.ioControlLdevWwnIscsiId

    @log_entry_exit
    def delete_spm(self, spec):
        hba = None
        if spec.host_wwn:
            hba = spec.host_wwn
        elif spec.iscsi_name:
            hba = spec.iscsi_name

        return self.provisioner.delete_spm(spec.ldev_id, hba)


class ServerPriorityManagerInfoExtractor:
    def __init__(self, storage_serial_number):
        self.storage_serial_number = storage_serial_number
        self.common_properties = {
            "ioControlLdevWwnIscsiId": str,
            "ldevId": int,
            "ldevIdHex": str,
            "hostWwn": str,
            "iscsiName": str,
            "priority": str,
            "upperLimitForIops": int,
            "upperLimitForTransferRate": int,
        }
        self.parameter_mapping = {
            "upper_limit_for_transfer_rate": "upper_limit_for_transfer_rate_in_MBps",
        }

    @log_entry_exit
    def extract(self, responses):
        logger.writeDebug(
            f"external_path_group_facts={responses} len = {len(responses)}"
        )
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping.get(cased_key)
                if response_key is not None:
                    new_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            if new_dict.get("ldev_id_hex") == "":
                if (
                    new_dict.get("ldev_id") is not None
                    and new_dict.get("ldev_id") != ""
                ):
                    new_dict["ldev_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("ldev_id")
                    )
            new_items.append(new_dict)
        return new_items
