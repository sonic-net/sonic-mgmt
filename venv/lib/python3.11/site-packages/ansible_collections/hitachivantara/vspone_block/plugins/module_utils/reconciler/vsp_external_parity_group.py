try:
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_external_volume_provisioner import (
        VSPExternalVolumeProvisioner,
    )
    from ..provisioner.vsp_external_parity_group_provisioner import (
        VSPExternalParityGroupProvisioner,
    )
    from ..message.vsp_external_parity_group_msgs import (
        VSPSExternalParityGroupValidateMsg,
    )
    from ..model.vsp_external_parity_group_models import (
        ExternalParityGroupFactSpec,
    )
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

except ImportError:
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from common.hv_constants import StateValue
    from provisioner.vsp_external_volume_provisioner import (
        VSPExternalVolumeProvisioner,
    )
    from provisioner.vsp_external_parity_group_provisioner import (
        VSPExternalParityGroupProvisioner,
    )
    from message.vsp_external_parity_group_msgs import (
        VSPSExternalParityGroupValidateMsg,
    )
    from model.vsp_external_parity_group_models import ExternalParityGroupFactSpec
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

logger = Log()


class VSPExternalParityGroupReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        if serial is None:
            self.serial = self.get_storage_serial_number()
        self.ext_vol_provisioner = VSPExternalVolumeProvisioner(
            self.connection_info, self.serial
        )
        self.provisioner = VSPExternalParityGroupProvisioner(
            self.connection_info, self.serial
        )

    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def external_parity_group_facts(self, spec: ExternalParityGroupFactSpec = None):
        if spec is None:
            rsp = self.ext_vol_provisioner.get_all_external_parity_groups()
            if rsp is None:
                rsp = []
            logger.writeDebug(f"external_parity_group_facts={rsp}")
            extracted_data = ExternalParityGroupInfoExtractor(self.serial).extract(
                rsp.data_to_list()
            )
            return extracted_data
        else:
            return self.get_one_external_parity_group_extracted(
                spec.external_parity_group
            )

    @log_entry_exit
    def get_one_external_parity_group_extracted(self, ext_parity_grp_id):
        rsp = self.get_one_external_parity_group(ext_parity_grp_id)
        return self.extract_one_external_parity_group(rsp)

    @log_entry_exit
    def get_one_external_parity_group(self, ext_parity_grp_id):
        rsp = self.provisioner.get_one_external_parity_group(ext_parity_grp_id)
        return rsp

    @log_entry_exit
    def extract_one_external_parity_group(self, ext_parity_grp_object):

        if ext_parity_grp_object is None:
            ext_parity_grp_object = []
        logger.writeDebug(f"get_one_external_parity_group={ext_parity_grp_object}")
        path_group_info = (
            self.provisioner.get_external_path_group_by_external_parity_group_id(
                ext_parity_grp_object.externalParityGroupId
            )
        )
        logger.writeDebug(
            f"get_one_external_parity_group:path_group_info={path_group_info}"
        )
        ext_parity_grp_object_dict = ext_parity_grp_object.to_dict()
        path_group_info_data_0 = path_group_info.get("data")[0]
        ext_parity_grp_object_dict["externalPathGroupId"] = path_group_info_data_0.get(
            "externalPathGroupId"
        )
        ext_parity_grp_object_dict["externalSerialNumber"] = path_group_info_data_0.get(
            "externalSerialNumber"
        )
        ext_parity_grp_object_dict["externalStorageProductId"] = (
            path_group_info_data_0.get("externalProductId")
        )
        extracted_data = ExternalParityGroupInfoExtractor(self.serial).extract(
            [ext_parity_grp_object_dict]
        )
        logger.writeDebug(
            f"get_one_external_parity_group:extracted_data={extracted_data}"
        )
        return extracted_data

    @log_entry_exit
    def external_parity_group_reconcile(self, state, spec):
        # reconcile the disk drive based on the desired state in the specification
        state = state.lower()
        msg = ""
        if state == StateValue.PRESENT:
            rsp = self.create_or_update_external_parity_group(spec)
            msg = "External parity group created successfully."
        elif state == StateValue.ASSIGN_EXTERNAL_PARITY_GROUP:
            rsp = self.assign_external_parity_group(spec)
            logger.writeDebug(
                f"external_pg_reconcile:ASSIGN_EXTERNAL_PARITY_GROUP={rsp}"
            )
            if self.connection_info.changed:
                msg = "Assigned external parity group to a CLPR successfully."
            else:
                msg = "External parity group is already assigned to the same CLPR."
        elif state == StateValue.CHANGE_MP_BLADE:
            rsp = self.change_mp_blade(spec)
            logger.writeDebug(f"external_pg_reconcile:CHANGE_MP_BLADE={rsp}")
            self.connection_info.changed = True
            msg = "Changed the MP blade assigned to an external parity group."
        elif state == StateValue.DISCONNECT:
            rsp = self.disconnect_from_a_volume_on_external_storage(spec)
            logger.writeDebug(f"external_pg_reconcile:DISCONNECT = {rsp} ")
            self.connection_info.changed = True
            msg = "Volume disconnected from the external parity group."
        elif state == StateValue.ABSENT:
            rsp = self.delete_external_parity_group(spec)
            logger.writeDebug(f"external_pg_reconcile:DELETE = {rsp} ")
            self.connection_info.changed = True
            msg = "External parity group deleted successfully."
            return None, msg
        response = self.get_one_external_parity_group_extracted(rsp)
        logger.writeDebug(f"external_pg_reconcile:response={response}")
        return response, msg

    @log_entry_exit
    def create_or_update_external_parity_group(self, spec):
        result = self.provisioner.create_external_parity_group(spec)
        self.connection_info.changed = True
        return result

    @log_entry_exit
    def delete_external_parity_group(self, spec):
        result = self.provisioner.delete_external_parity_group(spec)
        logger.writeDebug(f"delete_external_parity_group:delete_result = {result}")

    @log_entry_exit
    def disconnect_from_a_volume_on_external_storage(self, spec):
        result = self.provisioner.disconnect_from_a_volume_on_external_storage(spec)
        logger.writeDebug(f"disconnect_test_result:disconnect_result = {result}")
        # epg = self.get_one_external_parity_group(spec.external_parity_group_id)
        return result

    @log_entry_exit
    def assign_external_parity_group(self, spec):
        if spec.clpr_id is None:
            raise ValueError(VSPSExternalParityGroupValidateMsg.CLPR_ID_REQD.value)
        rsp = self.get_one_external_parity_group(spec.external_parity_group_id)
        if hasattr(rsp, "clprId") and rsp.clprId == spec.clpr_id:
            return rsp.externalParityGroupId
        else:
            self.connection_info.changed = True
            return self.provisioner.assign_external_parity_group(
                spec.external_parity_group_id, spec.clpr_id
            )

    @log_entry_exit
    def change_mp_blade(self, spec):
        if spec.mp_blade_id is None:
            raise ValueError(VSPSExternalParityGroupValidateMsg.MP_BLADE_ID_REQD.value)
        return self.provisioner.change_mp_blade(
            spec.external_parity_group_id, spec.mp_blade_id
        )


class ExternalParityGroupInfoExtractor:
    def __init__(self, storage_serial_number):
        self.storage_serial_number = storage_serial_number
        self.common_properties = {
            "externalParityGroupId": str,
            "usedCapacityRate": int,
            "availableVolumeCapacity": int,
            "spaces": list,
            # Not used fields
            "numOfLdevs": int,
            "emulationType": str,
            "clprId": int,
            "externalProductId": str,
            "availableVolumeCapacityInKB": int,
        }
        self.ext_storage_properties = {
            "externalPathGroupId": int,
            "externalSerialNumber": str,
            "externalStorageProductId": str,
        }
        self.parameter_mapping = {
            "available_volume_capacity": "available_volume_capacity_gb",
            "available_volume_capacity_in_kb": "available_volume_capacity_mb",
        }

    def fix_bad_camel_to_snake_conversion(self, key):
        new_key = key.replace("k_b", "kb")
        return new_key

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []

        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)
                # if value_type == list:
                #     value = self.process_list(value)
                if value is None:
                    default_value = get_default_value(value_type)
                    value = default_value
                new_dict[key] = value
            new_items.append(new_dict)
        return new_items

    @log_entry_exit
    def convert_kb_mb(self, kb):
        mb = kb / 1024
        return int(mb)

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
                if value_type == list:
                    response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if "k_b" in cased_key:
                    cased_key = self.fix_bad_camel_to_snake_conversion(cased_key)
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                if response_key is not None:
                    if cased_key == "available_volume_capacity_mb":
                        new_dict[cased_key] = self.convert_kb_mb(response_key)
                    else:
                        new_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            for key, value_type in self.ext_storage_properties.items():
                response_key = response.get(key)
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
