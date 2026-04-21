from typing import Any

try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        get_default_value,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_true_copy_provisioner import VSPTrueCopyProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg, TrueCopyFailedMsg
    from ..model.vsp_true_copy_models import VSPTrueCopyPairInfoList
except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        get_default_value,
    )
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from provisioner.vsp_true_copy_provisioner import VSPTrueCopyProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg, TrueCopyFailedMsg
    from model.vsp_true_copy_models import VSPTrueCopyPairInfoList


logger = Log()


class VSPTrueCopyReconciler:
    def __init__(
        self, connection_info, serial=None, state=None, secondary_connection_info=None
    ):

        self.connection_info = connection_info
        self.storage_serial_number = serial
        self.secondary_connection_info = None
        self.provisioner = VSPTrueCopyProvisioner(connection_info, serial)
        if state:
            self.state = state
        if secondary_connection_info:
            self.secondary_connection_info = secondary_connection_info
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial_number()

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def delete_true_copy(self, spec):
        self.validate_tc_spec_for_ops(spec)
        try:
            pair_id, comment = self.provisioner.delete_true_copy_pair(spec)
            return pair_id, comment
        except Exception as e:
            logger.writeError("RC:delete_true_copy:exception={}", str(e))
            self.connection_info.changed = False
            comment = TrueCopyFailedMsg.DELETE_PAIR_FAILED.value + str(e)
            # return None, str(e)
            return None, comment

    @log_entry_exit
    def validate_tc_spec_for_ops_resize(self, spec: Any) -> None:
        self.validate_tc_spec_for_ops(spec)
        if spec.new_volume_size is None:
            raise ValueError(VSPTrueCopyValidateMsg.NEW_VOLUME_SIZE.value)

    @log_entry_exit
    def validate_tc_spec_for_ops(self, spec: Any) -> None:

        if spec.primary_volume_id:
            if spec.copy_group_name is None:
                raise ValueError(VSPTrueCopyValidateMsg.COPY_GROUP_NAME.value)

        if spec.copy_group_name:
            if spec.copy_pair_name is None and spec.primary_volume_id is None:
                raise ValueError(
                    VSPTrueCopyValidateMsg.PVOL_ID_OR_CP_NAME_NEEDED_WITH_CG_NAME.value
                )

    @log_entry_exit
    def resync_true_copy(self, spec):
        self.validate_tc_spec_for_ops(spec)
        return self.provisioner.resync_true_copy_pair(spec)

    @log_entry_exit
    def split_true_copy(self, spec):
        self.validate_tc_spec_for_ops(spec)
        return self.provisioner.split_true_copy_pair(spec)

    @log_entry_exit
    def swap_split_true_copy(self, spec):
        self.validate_tc_spec_for_ops(spec)
        return self.provisioner.swap_split_true_copy_pair(spec)

    @log_entry_exit
    def swap_resync_true_copy(self, spec):
        self.validate_tc_spec_for_ops(spec)
        return self.provisioner.swap_resync_true_copy_pair(spec)

    @log_entry_exit
    def resize_true_copy(self, spec):
        self.validate_tc_spec_for_ops_resize(spec)
        return self.provisioner.resize_true_copy_copy_pair(spec)

    @log_entry_exit
    def create_true_copy(self, spec):
        self.validate_create_spec(spec)

        return self.provisioner.create_true_copy(spec=spec)

    @log_entry_exit
    def validate_create_spec(self, spec: Any) -> None:

        if spec.primary_volume_id is None:
            raise ValueError(VSPTrueCopyValidateMsg.PRIMARY_VOLUME_ID.value)

        if (
            spec.secondary_pool_id is None
            and spec.provisioned_secondary_volume_id is None
        ):
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_POOL_ID.value)

        if (
            spec.secondary_hostgroup is not None
            and spec.secondary_hostgroups is not None
        ):
            raise ValueError(VSPTrueCopyValidateMsg.BOTH_HGS_ARE_SPECIFIED.value)

        if spec.secondary_hostgroup is not None and spec.secondary_hostgroups is None:
            spec.secondary_hostgroups = spec.secondary_hostgroup

        if (
            spec.secondary_hostgroups is None
            and spec.secondary_nvm_subsystem is None
            and spec.secondary_iscsi_targets is None
            and spec.provisioned_secondary_volume_id is None
        ):
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_OR_NVME.value)

        if self.secondary_connection_info is None:
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_CONNECTION_INFO.value)
        else:
            spec.secondary_connection_info = self.secondary_connection_info

        if spec.copy_group_name is None:
            raise ValueError(VSPTrueCopyValidateMsg.COPY_GROUP_NAME.value)
        if spec.copy_pair_name is None:
            raise ValueError(VSPTrueCopyValidateMsg.COPY_PAIR_NAME.value)

        if (
            spec.provisioned_secondary_volume_id
            and spec.begin_secondary_volume_id
            and spec.end_secondary_volume_id
        ):
            if (
                spec.provisioned_secondary_volume_id < spec.begin_secondary_volume_id
            ) or (spec.provisioned_secondary_volume_id > spec.end_secondary_volume_id):
                raise ValueError(
                    VSPTrueCopyValidateMsg.SECONDARY_VOLUME_ID_OUT_OF_RANGE.value
                )

    @log_entry_exit
    def reconcile_true_copy(self, spec: Any) -> Any:
        """
        Reconcile the TrueCopy based on the desired state in the specification.
        """
        state = self.state.lower()
        if self.secondary_connection_info is None:
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_CONNECTION_INFO.value)
        else:
            spec.secondary_connection_info = self.secondary_connection_info

        resp_data = None
        if state == StateValue.ABSENT:
            unused, comment = self.delete_true_copy(spec)
            # msg = "Truecopy pair {} has been deleted successfully.".format(result)
            return comment
        elif state == StateValue.PRESENT:
            resp_data = self.create_true_copy(spec=spec)
        elif state == StateValue.SPLIT:
            resp_data = self.split_true_copy(spec)
        elif state == StateValue.RE_SYNC:
            resp_data = self.resync_true_copy(spec)
        elif state == StateValue.SWAP_SPLIT:
            resp_data = self.swap_split_true_copy(spec)
        elif state == StateValue.SWAP_RESYNC:
            resp_data = self.swap_resync_true_copy(spec)
        elif state == StateValue.RESIZE or state == StateValue.EXPAND:
            resp_data = self.resize_true_copy(spec)

        if resp_data:
            logger.writeDebug("RC:resp_data={}  state={}", resp_data, state)
            if isinstance(resp_data, dict):
                return resp_data

            resp_in_dict = resp_data.to_dict()
            logger.writeDebug("RC:reconcile_true_copy:tc_pairs={}", resp_in_dict)

            remote_serial = spec.secondary_storage_serial_number
            return DirectTrueCopyInfoExtractor(
                self.storage_serial_number, remote_serial
            ).extract([resp_in_dict])

        else:
            return None

    @log_entry_exit
    def validate_tc_fact_spec(self, spec: Any) -> None:
        if self.secondary_connection_info is None:
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_CONNECTION_INFO.value)
        else:
            spec.secondary_connection_info = self.secondary_connection_info

    def get_true_copy_facts(self, spec=None):

        tc_pairs = self.provisioner.get_true_copy_facts(
            spec, self.storage_serial_number
        )
        logger.writeDebug("RC:get_true_copy_facts:tc_pairs={}", tc_pairs)

        if tc_pairs is None:
            return []
        else:
            remote_serial = spec.secondary_storage_serial_number
            extracted_data = DirectTrueCopyInfoExtractor(
                self.storage_serial_number, remote_serial
            ).extract(tc_pairs.data_to_list())
        return extracted_data

    @log_entry_exit
    def convert_primary_secondary_on_volume_type(self, pairs):
        items = []
        for item in pairs:
            if item.primaryOrSecondary == "S-VOL":
                tmp = item.ldevId
                tmp2 = item.serialNumber
                item.serialNumber = item.remoteSerialNumber
                item.ldevId = item.remoteLdevId
                item.remoteSerialNumber = tmp2
                item.remoteLdevId = tmp

            items.append(item)

        return VSPTrueCopyPairInfoList(data=items)


class DirectTrueCopyInfoExtractor:
    def __init__(self, serial, remote_serial=None):
        self.storage_serial_number = serial
        self.remote_serial_number = remote_serial
        self.common_properties = {
            "copyGroupName": str,
            "replicationType": str,
            "copyPairName": str,
            "fenceLevel": str,
            "pvolLdevId": int,
            "svolLdevId": int,
            "primaryVolumeIdHex": str,
            "pvolStatus": str,
            "svolStatus": str,
            "consistencyGroupId": int,
            "pvolStorageDeviceId": str,
            "svolStorageDeviceId": str,
            "copyProgressRate": int,
            "remoteMirrorCopyPairId": str,
            "secondaryVolumeIdHex": str,
        }

        self.parameter_mapping = {
            "pvol_ldev_id": "primary_volume_id",
            "svol_ldev_id": "secondary_volume_id",
        }

    def fix_bad_camel_to_snake_conversion(self, key):
        new_key = key.replace("v_s_m", "vsm")
        return new_key

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
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                if response_key is not None:
                    new_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            if new_dict.get("primary_volume_id_hex") == "":
                if (
                    new_dict.get("primary_volume_id") is not None
                    and new_dict.get("primary_volume_id") != ""
                ):
                    new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("primary_volume_id")
                    )
            if new_dict.get("secondary_volume_id_hex") == "":
                if (
                    new_dict.get("secondary_volume_id") is not None
                    and new_dict.get("secondary_volume_id") != ""
                ):
                    new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("secondary_volume_id")
                    )
            if new_dict["replication_type"] == "TC":
                new_dict.pop("replication_type", None)

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
            if cased_key in self.parameter_mapping.keys():
                cased_key = self.parameter_mapping[cased_key]
            if response_key is not None:
                new_dict[cased_key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[cased_key] = default_value

            if new_dict.get("primary_volume_id_hex") == "":
                if (
                    new_dict.get("primary_volume_id") is not None
                    and new_dict.get("primary_volume_id") != ""
                ):
                    new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("primary_volume_id")
                    )
            if new_dict.get("secondary_volume_id_hex") == "":
                if (
                    new_dict.get("secondary_volume_id") is not None
                    and new_dict.get("secondary_volume_id") != ""
                ):
                    new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("secondary_volume_id")
                    )

        return new_dict
