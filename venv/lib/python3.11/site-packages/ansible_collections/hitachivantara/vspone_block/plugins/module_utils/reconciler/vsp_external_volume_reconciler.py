try:
    from ..common.ansible_common import (
        log_entry_exit,
        get_default_value,
        camel_to_snake_case,
    )
    from ..common.hv_log import Log
    from ..provisioner.vsp_external_volume_provisioner import (
        VSPExternalVolumeProvisioner,
    )
    from ..provisioner.vsp_uvm_provisioner import VSPUvmProvisioner
    from ..model.vsp_external_volume_models import (
        ExternalVolumeSpec,
        ExternalVolumeFactSpec,
    )
    from ..common.hv_constants import StateValue
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..message.vsp_external_volume_msgs import VSPSExternalVolumeValidateMsg

except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        get_default_value,
        camel_to_snake_case,
    )
    from common.hv_log import Log
    from plugins.module_utils.provisioner.vsp_external_volume_provisioner import (
        VSPExternalVolumeProvisioner,
    )
    from provisioner.vsp_uvm_provisioner import VSPUvmProvisioner
    from model.vsp_external_volume_models import (
        ExternalVolumeSpec,
        ExternalVolumeFactSpec,
    )
    from common.hv_constants import StateValue
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from message.vsp_external_volume_msgs import VSPSExternalVolumeValidateMsg

logger = Log()


class VSPExternalVolumeReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        if serial is None:
            self.serial = self.get_storage_serial_number()
        self.provisioner = VSPExternalVolumeProvisioner(
            self.connection_info, self.serial
        )

    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def external_volume_reconcile(self, state: str, spec: ExternalVolumeSpec):
        #  reconcile based on the desired state in the specification
        state = state.lower()

        if state == StateValue.PRESENT:
            self.validate_create_spec(spec)
            return self.provisioner.create_external_volume_by_spec(spec)
        elif state == StateValue.DISCONNECT:
            test_result = self.disconnect_from_a_volume_on_external_storage(spec)
            logger.writeDebug(f"disconnect_test_result = {test_result} ")
            self.connection_info.changed = True
            return test_result, None
        elif state == StateValue.ABSENT:
            self.validate_delete_spec(spec)
            return self.provisioner.delete_external_volume_by_spec(spec)

    @log_entry_exit
    def disconnect_from_a_volume_on_external_storage(self, spec: ExternalVolumeSpec):
        self.validate_disconnect_spec(spec)
        logger.writeDebug(f"disconnect_test_result:spec = {spec} ")
        uvm_provisioner = VSPUvmProvisioner(self.connection_info)
        disconnect_result = (
            uvm_provisioner.disconnect_from_a_volume_on_external_storage(spec)
        )
        logger.writeDebug(
            f"disconnect_test_result:disconnect_result = {disconnect_result} "
        )
        epg = self.provisioner.get_one_external_parity_group(spec.external_parity_group)
        logger.writeDebug(
            f"disconnect_test_result:external_parity_group = {epg}  type={type(epg)}"
        )
        return epg

    @log_entry_exit
    def external_volume_facts(self, spec: ExternalVolumeFactSpec):
        rsp = self.provisioner.external_volume_facts(spec)
        if rsp is None:
            rsp = []
        return rsp

    @log_entry_exit
    def validate_create_spec(self, spec: ExternalVolumeSpec):
        if (
            spec is None
            # or spec.ldev_id is None
            or spec.external_storage_serial is None
            or spec.external_ldev_id is None
        ):
            raise ValueError(VSPSExternalVolumeValidateMsg.REQUIRED_FOR_CREATE.value)

    @log_entry_exit
    def validate_delete_spec(self, spec: ExternalVolumeSpec):
        if spec is None or spec.ldev_id is None:
            raise ValueError(
                VSPSExternalVolumeValidateMsg.LDEV_REQUIRED_FOR_DELETE.value
            )

    @log_entry_exit
    def validate_disconnect_spec(self, spec: ExternalVolumeSpec):
        if spec is None or spec.external_parity_group is None:
            raise ValueError(
                VSPSExternalVolumeValidateMsg.EXTERNAL_PARITY_GROUP_REQUIRED_FOR_DISCONNECT.value
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
            # numOfLdevs: int = None
            # emulationType: str = None
            # clprId: int = None
            # externalProductId: str = None
            # availableVolumeCapacityInKB: int = None
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
                if value_type == list:
                    value = self.process_list(value)
                if value is None:
                    default_value = get_default_value(value_type)
                    value = default_value
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
