from typing import Any

try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        get_default_value,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue, ConnectionTypes
    from ..provisioner.vsp_hur_provisioner import VSPHurProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from .vsp_true_copy import DirectTrueCopyInfoExtractor
    from ..model.vsp_hur_models import VSPHurPairInfoList, VSPHurPairInfo
    from ..model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
    )
    from ..message.vsp_hur_msgs import VSPHurValidateMsg
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        get_default_value,
    )
    from common.hv_log import Log
    from common.hv_constants import StateValue, ConnectionTypes
    from provisioner.vsp_hur_provisioner import VSPHurProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from .vsp_true_copy import DirectTrueCopyInfoExtractor
    from model.vsp_hur_models import VSPHurPairInfoList, VSPHurPairInfo
    from model.vsp_copy_groups_models import DirectCopyPairInfo
    from message.vsp_hur_msgs import VSPHurValidateMsg
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg


logger = Log()


class VSPHurReconciler:
    def __init__(self, connection_info, serial, state, secondary_connection_info=None):

        self.logger = Log()
        self.connection_info = connection_info
        self.storage_serial_number = serial
        self.provisioner = VSPHurProvisioner(connection_info, serial)
        self.state = state
        self.secondary_connection_info = secondary_connection_info
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            if self.storage_serial_number is None:
                self.storage_serial_number = self.get_storage_serial_number()

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    # 20240808 hur operations reconciler
    @log_entry_exit
    def delete_hur(self, spec):
        return self.provisioner.delete_hur_pair(
            spec.primary_volume_id, spec.mirror_unit_id, spec
        )

    @log_entry_exit
    def resync_hur(self, spec):
        return self.provisioner.resync_hur_pair(
            spec.primary_volume_id, spec.mirror_unit_id, spec
        )

    @log_entry_exit
    def split_hur(self, spec):
        return self.provisioner.split_hur_pair(
            spec.primary_volume_id, spec.mirror_unit_id, spec
        )

    @log_entry_exit
    def swap_split_hur(self, spec):
        return self.provisioner.swap_split_hur_pair(spec.primary_volume_id, spec)

    @log_entry_exit
    def secondary_takeover_hur(self, spec):
        return self.provisioner.secondary_takeover_hur_pair(spec)

    @log_entry_exit
    def swap_resync_hur(self, spec):
        return self.provisioner.swap_resync_hur_pair(spec.primary_volume_id, spec)

    @log_entry_exit
    def create_hur(self, spec):
        self.validate_create_spec(spec)

        pvol = self.provisioner.get_volume_by_id(spec.primary_volume_id)
        logger.writeDebug("RC:create_hur:pvol={} ", pvol)
        if not pvol:
            raise ValueError(
                VSPTrueCopyValidateMsg.PRIMARY_VOLUME_ID_DOES_NOT_EXIST.value.format(
                    spec.primary_volume_id
                )
            )

        return self.provisioner.create_hur_pair(spec)

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
                    VSPHurValidateMsg.SECONDARY_VOLUME_ID_OUT_OF_RANGE.value
                )

    @log_entry_exit
    def validate_hur_spec_ctg(self, spec: Any) -> None:
        # sng20250125 this should be in validate_hur_module
        # but calls to validate_hur_module are bypassed in favor of the common validations
        # "HUR must be registered in a consistency group"
        if spec.consistency_group_id:
            if spec.allocate_new_consistency_group:
                raise ValueError(VSPHurValidateMsg.INVALID_CG_NEW.value)
        else:
            if spec.allocate_new_consistency_group is None:
                raise ValueError(VSPHurValidateMsg.INVALID_CTG_BOTH_NONE.value)
            else:
                if not spec.allocate_new_consistency_group:
                    # sng20250125 validate_hur_spec_ctg, default is auto-assign CTG
                    spec.allocate_new_consistency_group = True
                    # if we don't want the default then raise exception
                    # raise ValueError(VSPHurValidateMsg.INVALID_CTG_NONE.value)

    @log_entry_exit
    def validate_hur_spec_for_ops_resize(self, spec: Any) -> None:
        if spec.new_volume_size is None:
            raise ValueError(VSPHurValidateMsg.NEW_VOLUME_SIZE.value)

    @log_entry_exit
    def resize_hur_copy(self, spec):
        self.validate_hur_spec_for_ops_resize(spec)
        return self.provisioner.resize_hur_copy_pair(spec)

    @log_entry_exit
    def reconcile_hur(self, spec, secondary_connection_info: str) -> Any:
        """
        Reconcile the HUR based on the desired state in the specification.
        """
        spec.remote_connection_info = secondary_connection_info
        spec.secondary_storage_connection_info = secondary_connection_info
        spec.secondary_connection_info = secondary_connection_info
        comment = None
        state = self.state.lower()
        resp_data = None
        if state == StateValue.ABSENT:
            # 20240905 comment
            result = self.delete_hur(spec)
            return comment, result
        elif state == StateValue.PRESENT:
            resp_data = self.create_hur(spec)
            self.logger.writeDebug("RC:resp_data={}", resp_data)
        elif state == StateValue.SPLIT:
            resp_data = self.split_hur(spec)
        elif state == StateValue.RE_SYNC:
            resp_data = self.resync_hur(spec)
        elif state == StateValue.SWAP_SPLIT:
            resp_data = self.swap_split_hur(spec)
        elif state == StateValue.TAKEOVER:
            resp_data = self.secondary_takeover_hur(spec)
            return comment, resp_data
        elif state == StateValue.SWAP_RESYNC:
            resp_data = self.swap_resync_hur(spec)
        elif state == StateValue.RESIZE or state == StateValue.EXPAND:
            resp_data = self.resize_hur_copy(spec)

        # Match output with Gateway
        if isinstance(resp_data, str):
            self.logger.writeDebug("RC:resp_data={}", resp_data)
            raise ValueError(
                VSPHurValidateMsg.HUR_OPERATION_FAILED.value.format(resp_data)
            )
        updated_resp_data = update_response_data(self, resp_data)
        # for key, value in resp_data.items():
        #     new_key = key.replace("svol", "secondary_volume").replace("pvol", "primary_volume").replace("ldev_id", "id")
        #     updated_resp_data[new_key] = value

        # updated_resp_data["primary_volume_id_hex"] = volume_id_to_hex_format(
        #            updated_resp_data["primary_volume_id"]
        #         )
        # updated_resp_data["secondary_volume_id_hex"] = volume_id_to_hex_format(
        #            updated_resp_data["secondary_volume_id"]
        #         )
        # self.logger.writeDebug("resp_data={}", updated_resp_data)

        if updated_resp_data:

            # 20241218
            if isinstance(updated_resp_data, VSPHurPairInfo):
                extracted_data = HurInfoExtractor(self.storage_serial_number).extract(
                    VSPHurPairInfoList(data=[resp_data]).data_to_list()
                )
                return comment, extracted_data

            self.logger.writeDebug("resp_data={}", updated_resp_data)
            resp_in_dict = updated_resp_data
            self.logger.writeDebug("resp_in_dict={}", resp_in_dict)
            return comment, resp_in_dict
        else:
            return "Data is not available yet.", None

    #  for testing only
    @log_entry_exit
    def get_all_hurpairs(self):

        result = self.provisioner.get_all_hurpairs(self.storage_serial_number)

        result2 = HurInfoExtractor(self.storage_serial_number).extract(result)

        return result2

    @log_entry_exit
    # sng20241115 virtual vldevid lookup
    def get_other_attributes(self, spec, hur_pairs):

        if self.connection_info.connection_type != ConnectionTypes.DIRECT:
            return

        copy_group_list = self.provisioner.get_copy_group_list()
        logger.writeDebug("RC::copy_group_list={}", copy_group_list)
        logger.writeDebug("RC::hur_pairs={}", hur_pairs)

        # in case input is not a list
        if not isinstance(hur_pairs, list):
            hur_pairs = [hur_pairs]

        for hur_pair in hur_pairs:

            self.get_other_attributes_from_copy_group(copy_group_list, hur_pair)

            if hur_pair.get("muNumber"):
                logger.writeDebug("sng1104 muNumber={}", hur_pair["muNumber"])

            logger.writeDebug(
                "sng1104 localDeviceGroupName={}", hur_pair["localDeviceGroupName"]
            )
            logger.writeDebug(
                "sng1104 remoteDeviceGroupName={}", hur_pair["remoteDeviceGroupName"]
            )

        return

    def get_other_attributes_from_copy_group(self, cglist, hur_pair):
        if cglist is None:
            return
        cgname = hur_pair["copyGroupName"]

        logger.writeDebug("sng1104 392 cgname={}", cgname)
        logger.writeDebug("sng1104 392 hur_pair={}", hur_pair)

        for cg in cglist.data:
            if cgname == cg.copyGroupName:
                hur_pair["muNumber"] = cg.muNumber
                hur_pair["localDeviceGroupName"] = cg.localDeviceGroupName
                hur_pair["remoteDeviceGroupName"] = cg.remoteDeviceGroupName
                logger.writeDebug("sng1104 392 hur_pair={}", hur_pair)
                return

    @log_entry_exit
    def get_hur_facts(self, spec=None):

        if self.connection_info.connection_type == ConnectionTypes.DIRECT:

            spec.remote_connection_info = spec.secondary_connection_info
            spec.secondary_storage_connection_info = spec.secondary_connection_info
            # logger.writeDebug("RC:sng20241115  144 secondary_connection_info={}", spec.secondary_connection_info)
            tc_pairs = self.provisioner.hur_pair_facts_direct(spec)
            self.logger.writeDebug("RC:get_hur_facts:tc_pairs={}", tc_pairs)

            if isinstance(tc_pairs, DirectCopyPairInfo):
                tc_pairs = [tc_pairs.to_dict()]
            elif isinstance(tc_pairs, list):
                tc_pairs = self.objs_to_dict(tc_pairs)
            self.logger.writeDebug("RC:get_hur_facts:tc_pairs={}", tc_pairs)

            self.get_other_attributes(spec, tc_pairs)

            extracted_data = DirectHurCopyPairInfoExtractor(
                self.storage_serial_number
            ).extract(spec, tc_pairs)
            return extracted_data

        #  20240812 rec.get_hur_facts
        tc_pairs = self.provisioner.get_hur_facts_ext(
            pvol=spec.primary_volume_id,
            svol=spec.secondary_volume_id,
            mirror_unit_id=spec.mirror_unit_id,
        )
        self.logger.writeDebug("RC:get_hur_facts:tc_pairs={}", tc_pairs)
        if tc_pairs is None:
            return []
        else:
            if self.connection_info.connection_type == ConnectionTypes.DIRECT:
                tc_pairs = self.convert_primary_secondary_on_volume_type(tc_pairs.data)
                extracted_data = DirectTrueCopyInfoExtractor(
                    self.storage_serial_number
                ).extract(tc_pairs.data_to_list())
            else:
                extracted_data = HurInfoExtractor(self.storage_serial_number).extract(
                    tc_pairs.data_to_list()
                )

        return extracted_data

    # convert objs in the input to dict
    def objs_to_dict(self, objs):

        if not isinstance(objs, list):
            return objs

        items = []
        for obj in objs:
            if isinstance(obj, dict):
                items.append(obj)
                continue

            # DirectCopyPairInfo?
            obj = obj.to_dict()
            items.append(obj)
        return items

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

        return VSPHurPairInfoList(data=items)


class HurInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = int(serial)
        self.common_properties = {
            # "resourceId": str,
            "consistencyGroupId": int,
            # "copyPaceTrackSize": int,
            # "fenceLevel": str,
            "copyRate": int,
            "mirrorUnitId": int,
            # "pairName": str,
            "primaryJournalPoolId": int,
            "secondaryJournalPoolId": int,
            "primaryHexVolumeId": str,
            # "primaryVSMResourceGroupName": str,
            # "primaryVirtualHexVolumeId": str,
            # "primaryVirtualStorageId": str,
            # "primaryVirtualVolumeId": int,
            "primaryVolumeId": int,
            "primaryVolumeStorageId": int,
            "secondaryHexVolumeId": str,
            # "secondaryVSMResourceGroupName": str,
            # "secondaryVirtualStorageId": str,
            # "secondaryVirtualVolumeId": int,
            "secondaryVolumeId": int,
            "secondaryVolumeStorageId": int,
            "status": str,
            # "svolAccessMode": str,
            # "type": str,
            # "secondaryVirtualHexVolumeId": int,
            # "entitlementStatus": str,
            # "partnerId": str,
            # "subscriberId": str,
        }

        self.parameter_mapping = {
            "primary_volume_storage_id": "primary_storage_serial",
            "secondary_volume_storage_id": "secondary_storage_serial",
        }

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
                    if cased_key in self.parameter_mapping.keys():
                        cased_key = self.parameter_mapping[cased_key]
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value

            # new_dict["partner_id"] = "apiadmin"
            if new_dict.get("primary_volume_id_hex") == "":
                new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                    new_dict.get("primary_volume_id")
                )
            if new_dict.get("secondary_volume_id_hex") == "":
                new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
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
            if response_key is not None:
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                new_dict[cased_key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[cased_key] = default_value

        # new_dict["partner_id"] = "apiadmin"
        if new_dict.get("primary_volume_id_hex") == "":
            new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                new_dict.get("primary_volume_id")
            )
        if new_dict.get("secondary_volume_id_hex") == "":
            new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
                new_dict.get("secondary_volume_id")
            )

        return new_dict


class DirectHurCopyPairInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "consistencyGroupId": int,
            "pvolJournalId": int,
            "svolJournalId": int,
            "remoteMirrorCopyPairId": str,
            "pvolLdevId": int,
            "svolLdevId": int,
            "pvolStatus": str,
            "svolStatus": str,
            "copyGroupName": str,
            "copyPairName": str,
            "pvolStorageDeviceId": str,
            "svolStorageDeviceId": str,
            "muNumber": int,
            "primaryVolumeIdHex": str,
            "secondaryVolumeIdHex": str,
        }

        self.parameter_mapping = {
            "mu_number": "mirror_unit_id",
            "pvol_journal_id": "primary_journal_pool",
            "svol_journal_id": "secondary_journal_pool",
            "pvol_ldev_id": "primary_volume_id",
            "svol_ldev_id": "secondary_volume_id",
        }

    # sng20241126 get_serial_number_from_device_id
    @log_entry_exit
    def get_serial_number_from_device_id(self, storageDeviceId):

        # for 'pvolStorageDeviceId': 'A34000810045' -> 810045
        # for 'svolStorageDeviceId': 'A34000810050' -> 810050

        len2 = len(storageDeviceId)
        # supports up to 7 digits device id
        len1 = len2 - 8

        result = ""
        captureOn = False
        while len1 < len2:
            char = storageDeviceId[len1]
            if char != "0" or captureOn:
                captureOn = True
                result = result + char
            len1 = len1 + 1

        return result

    def fix_bad_camel_to_snake_conversion(self, key):
        new_key = key.replace("s_s_w_s", "ssws")
        return new_key

    @log_entry_exit
    def extract(self, spec, responses):
        new_items = []
        if responses is None:
            return new_items
        if isinstance(responses, dict):
            responses = [responses]

        for response in responses:
            new_dict = {
                # "primary_volume_storage_id": self.storage_serial_number,
                # "secondary_volume_storage_id": spec.secondary_storage_serial_number,
                "copy_rate": "",
                "mirror_unit_id": "",
            }
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                if response is None:
                    return new_items
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if "s_s_w_s" in cased_key:
                    cased_key = self.fix_bad_camel_to_snake_conversion(cased_key)
                if response_key is not None:
                    if cased_key in self.parameter_mapping.keys():
                        cased_key = self.parameter_mapping[cased_key]
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            if new_dict.get("primary_volume_id_hex") == "":
                new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                    new_dict.get("primary_volume_id")
                )
                # new_dict["primary_virtual_volume_id"] = ""
                # new_dict["primary_virtual_hex_volume_id"] = ""
            if new_dict.get("secondary_volume_id_hex") == "":
                new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
                    new_dict.get("secondary_volume_id")
                )

            if response.get("pvolStorageDeviceId"):
                logger.writeDebug("sngz={}", response.get("pvolStorageDeviceId"))
                new_dict["primary_volume_storage_id"] = (
                    self.get_serial_number_from_device_id(
                        response.get("pvolStorageDeviceId")
                    )
                )

            if response.get("svolStorageDeviceId"):
                new_dict["secondary_volume_storage_id"] = (
                    self.get_serial_number_from_device_id(
                        response.get("svolStorageDeviceId")
                    )
                )

                # new_dict["secondary_virtual_hex_volume_id"] = ""
                # new_dict["secondary_virtual_volume_id"] = ""
            if new_dict.get("mu_number"):
                new_dict.pop("mu_number")
            if new_dict.get("pvol_virtual_ldev_id"):
                new_dict.pop("pvol_virtual_ldev_id")
            if new_dict.get("svol_virtual_ldev_id"):
                new_dict.pop("svol_virtual_ldev_id")
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
            if "s_s_w_s" in cased_key:
                cased_key = self.fix_bad_camel_to_snake_conversion(cased_key)
            if response_key is not None:
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                new_dict[cased_key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[cased_key] = default_value

        # if new_dict.get("primary_volume_id_hex") == "" :
        #     new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(new_dict.get("primary_volume_id"))
        # if new_dict.get("secondary_volume_id_hex") == "" :
        #     new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(new_dict.get("secondary_volume_id"))

        return new_dict


def update_response_data(self, resp_data):
    updated_resp_data = {}

    # sng20250125 UCA-2466 'VSPHurPairInfo' object has no attribute 'items'
    self.logger.writeDebug("572 type resp_data={}", type(resp_data))
    self.logger.writeDebug("resp_data={}", resp_data)

    if resp_data is None:
        return updated_resp_data

    # Key replacement as per the given instructions
    for key, value in resp_data.items():
        new_key = (
            key.replace("svol", "secondary_volume")
            .replace("pvol", "primary_volume")
            .replace("ldev_id", "id")
            .replace("mirror_unit_number", "mirror_unit_id")
            .replace("primary_volume_journal_id", "primary_journal_pool_id")
            .replace("primary_volume_storage_serial_number", "primary_storage_serial")
            .replace(
                "secondary_volume_storage_serial_number", "secondary_storage_serial"
            )
            .replace("secondary_volume_journal_id", "secondary_journal_pool_id")
        )

        updated_resp_data[new_key] = value

    # Convert volume IDs to hex format
    updated_resp_data["primary_volume_id_hex"] = volume_id_to_hex_format(
        updated_resp_data["primary_volume_id"]
    )
    updated_resp_data["secondary_volume_id_hex"] = volume_id_to_hex_format(
        updated_resp_data["secondary_volume_id"]
    )

    # Log the updated response data
    self.logger.writeDebug("resp_data={}", updated_resp_data)

    return updated_resp_data
