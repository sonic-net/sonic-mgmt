try:
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from ..provisioner.vsp_external_path_group_provisioner import (
        VSPExternalPathGroupProvisioner,
    )
    from ..provisioner.vsp_external_volume_provisioner import (
        VSPExternalVolumeProvisioner,
    )
    from ..model.vsp_external_path_group_models import (
        ExternalPathGroupSpec,
        ExternalPathGroupFactSpec,
    )
    from ..common.hv_constants import StateValue
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..message.vsp_external_path_group_msgs import VSPSExternalPathGroupValidateMsg

except ImportError:
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from provisioner.vsp_external_path_group_provisioner import (
        VSPExternalPathGroupProvisioner,
    )
    from provisioner.vsp_external_volume_provisioner import (
        VSPExternalVolumeProvisioner,
    )
    from model.vsp_external_path_group_models import (
        ExternalPathGroupSpec,
        ExternalPathGroupFactSpec,
    )
    from common.hv_constants import StateValue
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from message.vsp_external_path_group_msgs import VSPSExternalPathGroupValidateMsg

logger = Log()


class VSPExternalPathGroupReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        if serial is None:
            self.serial = self.get_storage_serial_number()
        self.provisioner = VSPExternalPathGroupProvisioner(
            self.connection_info, self.serial
        )
        self.ext_vol_provisioner = VSPExternalVolumeProvisioner(
            self.connection_info, self.serial
        )

    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def external_path_group_reconcile(self, state: str, spec: ExternalPathGroupSpec):
        #  reconcile based on the desired state in the specification
        state = state.lower()

        if state == StateValue.PRESENT:
            # self.validate_create_spec(spec)
            # return self.provisioner.create_external_volume_by_spec(spec)
            pass
        elif state == StateValue.RM_EXTERNAL_PATH:
            self.validate_external_path_spec(spec)
            response = self.provisioner.rm_external_path_from_group(spec)
            return self.get_one_external_path_group(spec.external_path_group_id, True)
        elif state == StateValue.ADD_EXTERNAL_PATH:
            self.validate_external_path_spec(spec)
            response = self.provisioner.add_external_path_to_group(spec)
            return self.get_one_external_path_group(spec.external_path_group_id, True)
        elif state == StateValue.ABSENT:
            # self.validate_delete_spec(spec)
            # return self.provisioner.delete_external_volume_by_spec(spec)
            pass

    @log_entry_exit
    def external_path_group_facts(self, spec: ExternalPathGroupFactSpec = None):
        if spec is None:
            rsp = self.ext_vol_provisioner.get_external_path_groups()
            if rsp is None:
                rsp = []
            logger.writeInfo(f"external_path_group_facts={rsp}")
            extracted_data = PathGroupInfoExtractor(self.serial).extract(
                rsp.data_to_list()
            )
            return extracted_data
        else:
            return self.get_one_external_path_group(spec.external_path_group_id, True)

    # @log_entry_exit
    # def get_one_external_path_group(self, ext_path_grp_id, is_salamander=False):
    #     rsp = self.ext_vol_provisioner.get_one_external_path_group(ext_path_grp_id, is_salamander)
    #     if rsp is None:
    #         rsp = []
    #     logger.writeInfo(f"external_path_group_facts={rsp}")
    #     extracted_data = PathGroupInfoExtractor(self.serial).extract([rsp.to_dict()])
    #     return extracted_data

    @log_entry_exit
    def get_one_external_path_group(self, ext_path_grp_id, is_salamander=False):
        rsp = self.ext_vol_provisioner.get_one_external_path_group(
            ext_path_grp_id, is_salamander
        )

        if rsp is None:
            return []

        logger.writeInfo(f"external_path_group_facts={rsp}")

        # Convert to dict manually (fallback if no .to_dict())
        if hasattr(rsp, "to_dict"):
            response_dict = rsp.to_dict()
        else:
            response_dict = rsp.__dict__.copy()

        # Unwrap nested objects like SalamanderExternalPathInfoList
        if "id" in response_dict:
            response_dict["externalPathGroupId"] = response_dict.pop("id")

        if hasattr(rsp, "externalPaths"):
            external_paths = rsp.externalPaths
            if hasattr(external_paths, "data"):
                # Convert inner SalamanderExternalPathInfo to dicts
                response_dict["externalPaths"] = [
                    ep.__dict__ if hasattr(ep, "__dict__") else ep
                    for ep in external_paths.data
                ]
            else:
                response_dict["externalPaths"] = []

        # Add empty defaults for expected keys
        for missing_key in [
            "externalSerialNumber",
            "externalProductId",
            "externalParityGroups",
        ]:
            response_dict.setdefault(
                missing_key, "" if missing_key != "externalParityGroups" else []
            )

        logger.writeInfo(f"Normalized external path group dict={response_dict}")

        extracted_data = PathGroupInfoExtractor(self.serial).extract([response_dict])
        return extracted_data

    @log_entry_exit
    def validate_external_path_spec(self, spec: ExternalPathGroupSpec):
        if spec is None or spec.external_path_group_id is None:
            raise ValueError(
                VSPSExternalPathGroupValidateMsg.EXT_PATH_GROUP_ID_REQD.value
            )
        if not spec.external_fc_paths and not spec.external_iscsi_target_paths:
            raise ValueError(VSPSExternalPathGroupValidateMsg.PATHS_REQD.value)


class PathGroupInfoExtractor:
    def __init__(self, storage_serial_number):
        self.storage_serial_number = storage_serial_number
        self.common_properties = {
            "externalPathGroupId": str,
            "externalPaths": list,
            "externalSerialNumber": str,
            "externalProductId": str,
            "externalParityGroups": list,
        }

    # def process_list(self, response_key):
    #     new_items = []

    #     if response_key is None:
    #         return []

    #     for item in response_key:
    #         new_dict = {}
    #         for key, value in item.items():
    #             key = camel_to_snake_case(key)
    #             value_type = type(value)
    #             if value_type == list:
    #                 value = self.process_list(value)
    #             if value is None:
    #                 default_value = get_default_value(value_type)
    #                 value = default_value
    #             new_dict[key] = value
    #         new_items.append(new_dict)
    #     return new_items

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []

        for item in response_key:
            if not isinstance(item, dict):
                if hasattr(item, "__dict__"):
                    item = item.__dict__
                else:
                    continue  # skip if not dict-like

            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)

                if value_type == list:
                    value = self.process_list(value)
                elif hasattr(value, "__dict__"):
                    value = value.__dict__

                if value is None:
                    value_type = type(value) if value is not None else str
                    value = get_default_value(value_type)

                new_dict[key] = value

            new_items.append(new_dict)

        return new_items

    @log_entry_exit
    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            # new_dict["primary_storage_serial"] = self.storage_serial_number
            # new_dict["secondary_storage_serial"] = self.remote_serial_number
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                if value_type == list:
                    response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                # if cased_key in self.parameter_mapping.keys():
                #     cased_key = self.parameter_mapping[cased_key]
                if response_key is not None:
                    new_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
