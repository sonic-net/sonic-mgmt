from typing import Any

try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        convert_block_capacity,
        get_default_value,
    )
    from ..common.hv_log import Log
    from ..provisioner.vsp_gad_pair_provisioner import GADPairProvisioner
    from ..provisioner.vsp_volume_prov import VSPVolumeProvisioner
    from ..provisioner.vsp_resource_group_provisioner import VSPResourceGroupProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..model.vsp_gad_pairs_models import VspGadPairSpec
    from ..common.hv_constants import StateValue
    from ..message.vsp_gad_pair_msgs import GADPairValidateMSG
    from ..model.vsp_resource_group_models import (
        VSPResourceGroupFactSpec,
    )
    from ..model.vsp_gad_pairs_models import (
        VspGadPairsInfo,
        VspGadPairInfo,
    )
    from ..model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
    )
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from ..common.uaig_utils import UAIGResourceID

except ImportError:
    from message.vsp_gad_pair_msgs import GADPairValidateMSG
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        volume_id_to_hex_format,
        convert_block_capacity,
        get_default_value,
    )
    from common.hv_log import Log
    from provisioner.vsp_gad_pair_provisioner import GADPairProvisioner
    from provisioner.vsp_volume_prov import VSPVolumeProvisioner
    from provisioner.vsp_resource_group_provisioner import VSPResourceGroupProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from model.vsp_gad_pairs_models import VspGadPairSpec
    from common.hv_constants import StateValue
    from model.vsp_resource_group_models import (
        VSPResourceGroupFactSpec,
    )
    from model.vsp_gad_pairs_models import (
        VspGadPairsInfo,
        VspGadPairInfo,
    )
    from model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
    )
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from common.uaig_utils import UAIGResourceID

logger = Log()


# sng20241126 get_serial_number_from_device_id
def get_serial_number_from_device_id(storageDeviceId):

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


class VSPGadPairReconciler:

    def __init__(self, connection_info, secondary_connection_info=None, serial=None):
        self.connection_info = connection_info
        self.secondary_connection_info = secondary_connection_info
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial_number()
        self.serial = self.storage_serial_number
        self.provisioner = GADPairProvisioner(self.connection_info, self.serial)
        self.provisioner_volume = VSPVolumeProvisioner(
            self.connection_info, self.serial
        )
        self.provisioner_rg = VSPResourceGroupProvisioner(
            self.connection_info, self.serial
        )

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def gad_pair_reconcile_direct(
        self, state: str, spec: VspGadPairSpec, secondary_connection_info: str
    ) -> Any:
        state = state.lower()
        if self.secondary_connection_info is None:
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_CONNECTION_INFO.value)
        else:
            spec.secondary_connection_info = self.secondary_connection_info

        self.provisioner_for_secondary_storage = GADPairProvisioner(
            self.secondary_connection_info,
            self.provisioner.get_secondary_serial_direct(spec),
        )
        resp_data = None
        if state == StateValue.SPLIT:
            resp_data = self.split_gad_pair(spec, None)
        elif state == StateValue.RE_SYNC:
            resp_data = self.resync_gad_pair(spec, None)
        elif state == StateValue.SWAP_SPLIT:
            resp_data = self.swap_split_gad_pair(spec, None)
        elif state == StateValue.SWAP_RESYNC:
            resp_data = self.swap_resync_gad_pair(spec, None)
        elif state == StateValue.RESIZE or state == StateValue.EXPAND:
            resp_data = self.resize_gad_pair(spec, None)
        else:
            return

        if resp_data:
            logger.writeDebug("RC:resp_data={}  state={}", resp_data, state)

            if isinstance(resp_data, str):
                # sng20241126 str message to display
                return resp_data

            resp_in_dict = resp_data.to_dict()

            if state == StateValue.RESIZE or state == StateValue.EXPAND:
                # Show pvol and svol size in case of resize.
                pvolData = self.provisioner.get_volume_by_id(resp_in_dict["pvolLdevId"])
                resp_in_dict["primaryVolumeSize"] = convert_block_capacity(
                    pvolData.blockCapacity
                )
                svolData = self.provisioner_for_secondary_storage.get_volume_by_id(
                    resp_in_dict["svolLdevId"]
                )
                resp_in_dict["secondaryVolumeSize"] = convert_block_capacity(
                    svolData.blockCapacity
                )

            logger.writeDebug("RC:77:tc_pairs={}", resp_in_dict)
            # resp_in_dict["serialNumber"] = self.storage_serial_number
            # resp_in_dict["remoteSerialNumber"] = spec.secondary_storage_serial_number
            spec.secondary_storage_serial_number = (
                self.provisioner.get_secondary_serial_direct(spec)
            )
            pairs = [resp_in_dict]

            if state == StateValue.SWAP_SPLIT:
                self.connection_info.changed = True
                # sng20241123 you have do swap spit from the secondary storage,
                # but the pair is not swap yet, so we have to swap to show the fact correctly
                self.get_other_attributes(spec, pairs, True, True)
            else:
                # get pvol svol details
                self.get_other_attributes(spec, pairs)

            return DirectGADCopyPairInfoExtractor(self.storage_serial_number).extract(
                spec, pairs
            )
        else:
            return None

    @log_entry_exit
    # reconcile_gad_pair
    def gad_pair_reconcile(
        self, state: str, spec: VspGadPairSpec, secondary_connection_info: str
    ):

        #  reconcile the storage pool based on the desired state in the specification

        spec.remote_connection_info = secondary_connection_info
        spec.secondary_storage_connection_info = secondary_connection_info
        spec.secondary_connection_info = secondary_connection_info

        # sng20241114 - TODO
        spec.is_svol_readwriteable = False
        logger.writeDebug("sng20241114 copy_pair_name={}", spec.copy_pair_name)

        if state in [
            StateValue.SPLIT,
            StateValue.RE_SYNC,
            StateValue.SWAP_SPLIT,
            StateValue.SWAP_RESYNC,
            StateValue.RESIZE,
            StateValue.EXPAND,
        ]:
            self.validate_gad_spec_for_ops(spec)
            return self.gad_pair_reconcile_direct(
                state, spec, secondary_connection_info
            )

        pair = None
        #  see if we can find the pair with copy group name and copy pair name
        if spec.copy_group_name and spec.copy_pair_name:
            pair = self.provisioner.get_gad_pair_by_copy_group_and_copy_pair_name(spec)

        if pair is None:
            if spec.primary_volume_id is None:
                raise ValueError(VSPTrueCopyValidateMsg.PRIMARY_VOLUME_ID.value)

            if spec.primary_volume_id:
                # sng20241218 - swap here for now until operator rework is done
                if state in [StateValue.SWAP_SPLIT, StateValue.SWAP_RESYNC]:
                    pair = self.provisioner.get_gad_pair_by_svol_id(
                        spec, spec.primary_volume_id
                    )
                elif state != StateValue.PRESENT:
                    pair = self.provisioner.get_gad_pair_by_pvol_id(
                        spec, spec.primary_volume_id
                    )
                logger.writeDebug("RC:206:pair={}", pair)

        rec_methods = {
            StateValue.ABSENT: self.delete_gad_pair,
            StateValue.SPLIT: self.split_gad_pair,
            StateValue.RE_SYNC: self.resync_gad_pair,
            StateValue.SWAP_SPLIT: self.swap_split_gad_pair,
            StateValue.SWAP_RESYNC: self.swap_resync_gad_pair,
            StateValue.RESIZE: self.resize_gad_pair,
            StateValue.EXPAND: self.resize_gad_pair,
        }
        #  sng1104 - GAD Operations, invoke rec_methods
        if pair and rec_methods.get(state):

            logger.writeDebug("RC:227:pair={}", pair)
            response = rec_methods.get(state)(spec, pair)
            logger.writeDebug("RC:rec_methods:response={}", response)

            if response is None:
                # operation completed, fetch the pair again
                pairs = []
                pair = self.provisioner.get_gad_pair_by_pvol_id(
                    spec, spec.primary_volume_id
                )
                logger.writeDebug("RC:get_gad_pair_by_pvol_id:pair={}", pair)
                pairs.append(pair)
                self.get_other_attributes(spec, pairs)
                pair = DirectGADCopyPairInfoExtractor(
                    self.storage_serial_number
                ).extract(spec, pairs)
                return pair

            if isinstance(response, VspGadPairInfo):
                if state == StateValue.SWAP_SPLIT:
                    # fix for uca 2525
                    # with the operator fix of uca-2282 we should not have to get it again
                    # don't expect the pair to be swap yet even though the input is swapped
                    pair = response
                    logger.writeDebug("RC:240:pair={}", pair)
                    return self.addDetails_swap_split(pair.to_dict())
                else:
                    pair = self.provisioner.get_gad_pair_by_pvol_id(
                        spec, spec.primary_volume_id
                    )
                    logger.writeDebug("RC:240:pair={}", pair)
                    return self.addDetails(pair.to_dict(), spec.primary_volume_id)

            if isinstance(response, dict):
                pair = response
                logger.writeDebug("RC:gad_pair_reconcile:pair1={}", pair)
                self.get_other_attributes(spec, pair)
                if state == StateValue.RESIZE or state == StateValue.EXPAND:
                    return pair
                pair = DirectGADCopyPairInfoExtractor(
                    self.storage_serial_number
                ).extract(spec, pair)
                return pair

            if isinstance(response, DirectCopyPairInfo):
                pair = response
                logger.writeDebug("RC:gad_pair_reconcile:pair1={}", pair)
                self.get_other_attributes(spec, pair)
                pair = DirectGADCopyPairInfoExtractor(
                    self.storage_serial_number
                ).extract(spec, pair.to_dict())
                return pair

            return response.to_dict() if not isinstance(response, str) else response
        elif not pair and rec_methods.get(state):
            return "Gad pair not present"
        else:

            self.validate_create_spec(spec)

            pvol = self.provisioner.get_volume_by_id(spec.primary_volume_id)
            if pvol.emulationType.upper() == "NOT DEFINED":
                raise ValueError(
                    VSPTrueCopyValidateMsg.PRIMARY_VOLUME_ID_DOES_NOT_EXIST.value.format(
                        spec.primary_volume_id
                    )
                )

            if not pair:
                pair = self.create_update_gad_pair(spec, pair, pvol)
                if (
                    spec.secondary_nvm_subsystem is not None
                    or spec.secondary_iscsi_targets is not None
                ):
                    pair = self.provisioner.get_gad_pair_by_pvol_id(
                        spec, spec.primary_volume_id
                    )
                    logger.writeDebug("RC:206:pair={}", pair)
            logger.writeDebug("RC:270:pair={}", pair)

            if isinstance(pair, dict):
                logger.writeDebug("RC:gad_pair_reconcile:pair1={}", pair)
                self.get_other_attributes(spec, pair)

                pair = DirectGADCopyPairInfoExtractor(
                    self.storage_serial_number
                ).extract(spec, pair)
                logger.writeDebug("RC:gad_pair_reconcile:pair2={}", pair)
                return pair

            if isinstance(pair, VspGadPairInfo):
                logger.writeDebug("RC: 379 primaryVolumeId ={}", pair.primaryVolumeId)
                # for gateway only
                return self.addDetails(pair.to_dict(), pair.primaryVolumeId)

            return pair.camel_to_snake_dict() if pair else None

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
            spec.secondary_hostgroups is None
            and spec.secondary_nvm_subsystem is None
            and spec.secondary_iscsi_targets is None
            and spec.provisioned_secondary_volume_id is None
            and spec.provisioned_secondary_volume_id is None
        ):
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_OR_NVME.value)

        if self.secondary_connection_info is None:
            raise ValueError(VSPTrueCopyValidateMsg.SECONDARY_CONNECTION_INFO.value)
        else:
            spec.secondary_connection_info = self.secondary_connection_info
            spec.remote_connection_info = self.secondary_connection_info

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

        if spec.quorum_disk_id is None:
            raise ValueError(GADPairValidateMSG.QUORUM_DISK_ID.value)

    @log_entry_exit
    def create_update_gad_pair(self, spec, pair, pvol):
        if pair:
            return pair
        return self.provisioner.create_gad_pair(spec, pvol)

    @log_entry_exit
    def delete_gad_pair(self, spec, pair):
        rsp = self.provisioner.delete_gad_pair(spec, pair)

        if rsp == GADPairValidateMSG.DELETE_GAD_FAIL_SPLIT_DIRECT.value:
            pair = self.provisioner.split_gad_pair(spec, pair)
            rsp = self.provisioner.delete_gad_pair(spec, pair)

        return rsp

    @log_entry_exit
    def split_gad_pair(self, spec, pair):
        self.validate_gad_spec_for_ops(spec)
        return self.provisioner.split_gad_pair(spec, pair)

    @log_entry_exit
    def validate_gad_spec_for_ops(self, spec: Any) -> None:
        # due to swap operations, primary_volume_id is not required,
        # but copy_pair_name is a must
        if spec.copy_pair_name is None:
            raise ValueError(VSPTrueCopyValidateMsg.COPY_PAIR_NAME.value)

    @log_entry_exit
    def resync_gad_pair(self, spec, pair):
        return self.provisioner.resync_gad_pair(spec, pair)

    @log_entry_exit
    def swap_split_gad_pair(self, spec, pair):
        self.validate_gad_spec_for_ops(spec)
        return self.provisioner.swap_split_gad_pair(spec, pair)

    @log_entry_exit
    def swap_resync_gad_pair(self, spec, pair):
        self.validate_gad_spec_for_ops(spec)
        return self.provisioner.swap_resync_gad_pair(spec, pair)

    @log_entry_exit
    def resize_gad_pair(self, spec, pair):
        self.validate_gad_spec_for_ops(spec)
        return self.provisioner.resize_gad_pair(spec)

    def get_gad_copypairs(self, pairs):
        gad_pairs = []
        for pair in pairs:
            logger.writeDebug("RC:get_copypair_one:pair={}", pair)
            copyPairs = pair.get("copyPairs", None)
            if copyPairs is None:
                continue

            for copyPair in copyPairs:
                if (
                    copyPair["replicationType"] == "GAD"
                    and copyPair["svolStatus"] != "SMPL"
                    and copyPair.pvolStatus != "SMPL"
                ):
                    gad_pairs.append(copyPair)

        return gad_pairs

    # sng1104 - filter the copy group copy pairs by GAD
    def get_gad_from_copygroups(self, cgs):
        logger.writeDebug("RC:get_gad_from_copygroups:pair={}", cgs)
        gad_pairs = []
        for cg in cgs:
            logger.writeDebug("RC:cg={}", cg)
            if cg is None:
                continue
            copyPairs = cg.copyPairs
            if copyPairs is None:
                continue

            for copyPair in copyPairs:
                if (
                    copyPair.replicationType == "GAD"
                    and copyPair.svolStatus != "SMPL"
                    and copyPair.pvolStatus != "SMPL"
                ):
                    gad_pairs.append(copyPair.to_dict())

        return gad_pairs

    #  sng20241115 rec.gad_pair_facts
    def gad_pair_facts(self, spec=None):

        # logger.writeDebug("RC:sng20241115 secondary_connection_info={}", spec.secondary_connection_info)
        tc_pairs = self.provisioner.gad_pair_facts(spec)
        logger.writeDebug("RC:224 pairs={}", tc_pairs)
        if tc_pairs:
            spec.secondary_storage_serial_number
            if hasattr(tc_pairs, "data"):
                # VspGadPairsInfo class
                cglistdict = tc_pairs.data
            else:
                cglistdict = tc_pairs.data_to_list()

            cglistdict = self.objs_to_dict(cglistdict)

            doMore = False
            # logger.writeDebug("RC: 299 spec ={}", spec)
            if spec.copy_group_name and spec.copy_pair_name:
                doMore = True
            logger.writeDebug("RC: 299 doMore ={}", doMore)
            self.get_other_attributes(spec, cglistdict, doMore)

            # logger.writeDebug("RC:cglistdict={}", cglistdict)
            extracted_data = DirectGADCopyPairInfoExtractor(
                self.storage_serial_number
            ).extract(spec, cglistdict)

        else:
            extracted_data = {}
        return extracted_data

    # for gateway only
    def addDetails(self, pair: dict, secondaryVolumeId):
        storage_id = UAIGResourceID().storage_resourceId(self.serial)
        ldev_resource_id = UAIGResourceID().ldev_resourceId(
            self.serial, pair["primary_volume_id"]
        )
        logger.writeDebug("RC: 393 pair ={}", pair)
        logger.writeDebug("RC: 393 secondaryVolumeId ={}", secondaryVolumeId)
        logger.writeDebug("RC: 393 self.serial ={}", self.serial)
        logger.writeDebug("RC: 393 storage_id ={}", storage_id)
        logger.writeDebug("RC: 393 ldev_resource_id ={}", ldev_resource_id)

        vol = self.provisioner_volume.get_volume_by_ldev_uaig(
            storage_id, ldev_resource_id
        )
        logger.writeDebug("RC: 393 vol ={}", vol)
        logger.writeDebug("RC: 393 isAluaEnabled ={}", vol.isALUA)
        pair["is_alua_enabled"] = vol.isALUA

        # sng20250116 get svol_status
        svol_status = ""
        provisioner_remote = GADPairProvisioner(
            self.connection_info, pair["secondary_volume_storage_id"]
        )
        remote_pair = provisioner_remote.get_gad_pair_by_svol_id_gw(
            pair["secondary_volume_id"]
        )
        logger.writeDebug("RC: 393 remote_pair ={}", remote_pair)
        if remote_pair:
            svol_status = remote_pair.status
        else:
            remote_pair = provisioner_remote.get_gad_pair_by_id(
                pair["secondary_volume_id"]
            )
            logger.writeDebug("RC: 393 remote_pair ={}", remote_pair)
            if remote_pair:
                svol_status = remote_pair.status
        pair["primary_volume_status"] = pair["status"]
        pair["secondary_volume_status"] = svol_status
        logger.writeDebug("RC: 475 remote_pair ={}", remote_pair)
        logger.writeDebug("RC: 475 svol_status ={}", svol_status)
        logger.writeDebug("RC: 475 secondaryVolumeId ={}", pair["secondary_volume_id"])
        logger.writeDebug(
            "RC: 475 secondaryVolumeStorageId ={}", pair["secondary_volume_storage_id"]
        )

        input_spec = VSPResourceGroupFactSpec()
        # we get RG number from the porcleain
        # we want to show the RG name
        input_spec.id = int(pair["primary_vsm_resource_group_name"])
        logger.writeDebug("RC: 393 input_spec.id ={}", input_spec.id)

        if input_spec.id == 0:
            pair["primary_vsm_resource_group_name"] = "meta_resource"
        else:
            rgs = self.provisioner_rg.get_resource_groups(None, False)
            if rgs:
                for rg in rgs.data_to_list():
                    # given input_spec.id, it is taking it as a start index
                    logger.writeDebug("RC: 393 rg ={}", rg)
                    if rg["id"] == input_spec.id:
                        pair["primary_vsm_resource_group_name"] = rg["name"]
                        break

        input_spec.id = int(pair["secondary_vsm_resource_group_name"])
        if input_spec.id == 0:
            pair["secondary_vsm_resource_group_name"] = "meta_resource"
        else:
            # sng20250115 - get_resource_groups for remote storage
            provisioner_rg = VSPResourceGroupProvisioner(
                self.connection_info, pair["secondary_volume_storage_id"]
            )
            rgs = provisioner_rg.get_resource_groups(None, False)
            if rgs:
                for rg in rgs.data_to_list():
                    logger.writeDebug("RC: 393 rg ={}", rg)
                    if str(rg["id"]) == str(input_spec.id):
                        pair["secondary_vsm_resource_group_name"] = rg["name"]
                        break

        if pair["secondary_virtual_hex_volume_id"] is None:
            pair["secondary_virtual_hex_volume_id"] = ""
        # if pair["partner_id"] is None:
        #     pair["partner_id"] = ""
        # if pair["subscriber_id"] is None:
        #     pair["subscriber_id"] = ""
        if pair["status"]:
            del pair["status"]

        return pair

    # for gateway only
    # pair is not swapped
    # but the self.serial is the remote and
    # the primary_volume_id is the secondaryVolumeId
    def addDetails_swap_split(self, pair: dict):
        storage_id = UAIGResourceID().storage_resourceId(
            pair["primary_volume_storage_id"]
        )
        ldev_resource_id = UAIGResourceID().ldev_resourceId(
            pair["primary_volume_storage_id"], pair["primary_volume_id"]
        )
        logger.writeDebug("RC: 393 pair ={}", pair)
        logger.writeDebug(
            "RC: 393 primary_volume_storage_id ={}", pair["primary_volume_storage_id"]
        )
        logger.writeDebug("RC: 393 storage_id ={}", storage_id)
        logger.writeDebug("RC: 393 ldev_resource_id ={}", ldev_resource_id)

        provisioner_volume = VSPVolumeProvisioner(
            self.connection_info, pair["primary_volume_storage_id"]
        )
        vol = provisioner_volume.get_volume_by_ldev_uaig(storage_id, ldev_resource_id)
        logger.writeDebug("RC: 393 vol ={}", vol)
        logger.writeDebug("RC: 393 isAluaEnabled ={}", vol.isALUA)
        pair["is_alua_enabled"] = vol.isALUA

        # sng20250116 get svol_status
        svol_status = ""
        provisioner_remote = GADPairProvisioner(
            self.connection_info, pair["secondary_volume_storage_id"]
        )
        # sng20250129 - get_gad_pair_by_svol_id_gw
        remote_pair = provisioner_remote.get_gad_pair_by_svol_id_gw(
            pair["secondary_volume_id"]
        )
        logger.writeDebug("RC: 393 remote_pair ={}", remote_pair)
        if remote_pair:
            svol_status = remote_pair.status
        else:
            remote_pair = provisioner_remote.get_gad_pair_by_id(
                pair["secondary_volume_id"]
            )
            logger.writeDebug("RC: 393 remote_pair ={}", remote_pair)
            if remote_pair:
                svol_status = remote_pair.status
        pair["primary_volume_status"] = pair["status"]
        pair["secondary_volume_status"] = svol_status
        logger.writeDebug("RC: 475 remote_pair ={}", remote_pair)
        logger.writeDebug("RC: 475 svol_status ={}", svol_status)
        logger.writeDebug("RC: 475 secondaryVolumeId ={}", pair["secondary_volume_id"])
        logger.writeDebug(
            "RC: 475 secondaryVolumeStorageId ={}", pair["secondary_volume_storage_id"]
        )

        input_spec = VSPResourceGroupFactSpec()
        # we get RG number from the porcleain
        # we want to show the RG name
        input_spec.id = int(pair["primary_vsm_resource_group_name"])
        logger.writeDebug("RC: 393 input_spec.id ={}", input_spec.id)

        if input_spec.id == 0:
            pair["primary_vsm_resource_group_name"] = "meta_resource"
        else:
            rgs = self.provisioner_rg.get_resource_groups(None, False)
            if rgs:
                for rg in rgs.data_to_list():
                    # given input_spec.id, it is taking it as a start index
                    logger.writeDebug("RC: 393 rg ={}", rg)
                    if rg["id"] == input_spec.id:
                        pair["primary_vsm_resource_group_name"] = rg["name"]
                        break

        input_spec.id = int(pair["secondary_vsm_resource_group_name"])
        if input_spec.id == 0:
            pair["secondary_vsm_resource_group_name"] = "meta_resource"
        else:
            # sng20250115 - get_resource_groups for remote storage
            provisioner_rg = VSPResourceGroupProvisioner(
                self.connection_info, pair["secondary_volume_storage_id"]
            )
            rgs = provisioner_rg.get_resource_groups(None, False)
            if rgs:
                for rg in rgs.data_to_list():
                    logger.writeDebug("RC: 393 rg ={}", rg)
                    if str(rg["id"]) == str(input_spec.id):
                        pair["secondary_vsm_resource_group_name"] = rg["name"]
                        break

        if pair["secondary_virtual_hex_volume_id"] is None:
            pair["secondary_virtual_hex_volume_id"] = ""
        # if pair["partner_id"] is None:
        #     pair["partner_id"] = ""
        # if pair["subscriber_id"] is None:
        #     pair["subscriber_id"] = ""
        if pair["status"]:
            del pair["status"]

        return pair

    # convert objs in the input to dict
    def objs_to_dict(self, objs):

        if not isinstance(objs, list):
            return objs

        items = []
        for obj in objs:
            if isinstance(obj, dict):
                items.append(obj)
                continue

            # DirectSpecificCopyGroupInfo?
            obj = obj.to_dict()
            items.append(obj)
        return items

    @log_entry_exit
    # sng20241115 virtual vldevid lookup
    # doSwap=true is only for swap-split
    def get_other_attributes(self, spec, gad_copy_pairs, doMore=True, doSwap=False):

        spec.secondary_storage_serial_number = (
            self.provisioner.get_secondary_serial_direct(spec)
        )
        copy_group_list = self.provisioner.get_copy_group_list()
        logger.writeDebug("RC::copy_group_list={}", copy_group_list)
        logger.writeDebug("RC::gad_copy_pairs={}", gad_copy_pairs)

        #  in case input is not a list
        if not isinstance(gad_copy_pairs, list):
            gad_copy_pairs = [gad_copy_pairs]

        for gad_copy_pair in gad_copy_pairs:

            self.get_other_attributes_from_copy_group(
                copy_group_list, gad_copy_pair, doSwap
            )
            if gad_copy_pair.get("muNumber"):
                logger.writeDebug("sng1104 muNumber={}", gad_copy_pair["muNumber"])
            logger.writeDebug(
                "sng1104 localDeviceGroupName={}", gad_copy_pair["localDeviceGroupName"]
            )
            logger.writeDebug(
                "sng1104 remoteDeviceGroupName={}",
                gad_copy_pair["remoteDeviceGroupName"],
            )

            gad_copy_pair["isAluaEnabled"] = False
            gad_copy_pair["primaryVirtualVolumeId"] = -1
            gad_copy_pair["secondaryVirtualVolumeId"] = -1

            if not doMore:
                continue

            # sng20241126 swap as needed
            primary_volume_storage_id = get_serial_number_from_device_id(
                gad_copy_pair.get("pvolStorageDeviceId")
            )
            secondary_volume_storage_id = get_serial_number_from_device_id(
                gad_copy_pair.get("svolStorageDeviceId")
            )
            if spec.secondary_storage_serial_number is not None:
                serial_str = str(spec.secondary_storage_serial_number).strip()
                if serial_str[0].isalpha():
                    serial_str = get_serial_number_from_device_id(serial_str)
                if int(serial_str) == int(primary_volume_storage_id):
                    doSwap = True

            logger.writeDebug("sng1104 doSwap={}", doSwap)
            logger.writeDebug(
                "sng1104 primary_volume_storage_id={}", primary_volume_storage_id
            )
            logger.writeDebug(
                "sng1104 secondary_volume_storage_id={}", secondary_volume_storage_id
            )
            logger.writeDebug(
                "sng1104 secondary_storage_serial_number={}",
                spec.secondary_storage_serial_number,
            )

            pvol = gad_copy_pair["pvolLdevId"]
            svol = gad_copy_pair["svolLdevId"]
            spec.secondary_storage_connection_info = self.secondary_connection_info

            if doSwap:
                vol = self.provisioner.get_vol_remote(spec, pvol)
                rg = self.provisioner.get_resource_group_by_id_remote(
                    spec, vol.resourceGroupId
                )
                vsms = self.provisioner.get_vsm_all_remote(spec)
            else:
                vol = self.provisioner.get_volume_by_id(pvol)
                rg = self.provisioner.get_resource_group_by_id(vol.resourceGroupId)
                vsms = self.provisioner.get_vsm_all()

            # sng20241127 get_vsm_info for facts
            virtualStorageDeviceId, virtualSerialNumber = self.get_vsm_info(
                vsms, vol.resourceGroupId
            )

            if vol.virtualLdevId:
                gad_copy_pair["primaryVirtualVolumeId"] = vol.virtualLdevId
            if vol.isAluaEnabled:
                gad_copy_pair["isAluaEnabled"] = vol.isAluaEnabled

            gad_copy_pair["primaryVSMResourceGroupName"] = rg.resourceGroupName
            # gad_copy_pair["primaryVirtualStorageId"] = rg.virtualStorageId
            gad_copy_pair["primaryVirtualStorageDeviceId"] = virtualStorageDeviceId
            gad_copy_pair["primaryVirtualSerialNumber"] = virtualSerialNumber

            logger.writeDebug("sng1104 pvol={}", vol)
            logger.writeDebug("sng1104 pvolVirtualLdevId={}", vol.virtualLdevId)
            logger.writeDebug("sng1104 rg={}", rg)
            logger.writeDebug("sng1104 resourceGroupName={}", rg.resourceGroupName)
            logger.writeDebug("sng1104 virtualStorageId={}", rg.virtualStorageId)
            logger.writeDebug(
                "sng1104 virtualStorageDeviceId={}", virtualStorageDeviceId
            )
            logger.writeDebug("sng1104 virtualSerialNumber={}", virtualSerialNumber)

            if doSwap:
                vol = self.provisioner.get_volume_by_id(svol)
                logger.writeDebug("sng1104 svol={}", svol)
                logger.writeDebug("sng1104 vol={}", vol)
                logger.writeDebug("sng1104 vol.resourceGroupId={}", vol.resourceGroupId)
                rg = self.provisioner.get_resource_group_by_id(vol.resourceGroupId)
                vsms = self.provisioner.get_vsm_all()
            else:
                vol = self.provisioner.get_vol_remote(spec, svol)
                rg = self.provisioner.get_resource_group_by_id_remote(
                    spec, vol.resourceGroupId
                )
                vsms = self.provisioner.get_vsm_all_remote(spec)

            virtualStorageDeviceId, virtualSerialNumber = self.get_vsm_info(
                vsms, vol.resourceGroupId
            )

            if vol.virtualLdevId:
                gad_copy_pair["secondaryVirtualVolumeId"] = vol.virtualLdevId
            gad_copy_pair["secondaryVSMResourceGroupName"] = rg.resourceGroupName
            # gad_copy_pair["SecondaryVirtualStorageId"] = rg.virtualStorageId
            gad_copy_pair["secondaryVirtualStorageDeviceId"] = virtualStorageDeviceId
            gad_copy_pair["secondaryVirtualSerialNumber"] = virtualSerialNumber

            logger.writeDebug("sng1104 svol={}", vol)
            logger.writeDebug("sng1104 svolVirtualLdevId={}", vol.virtualLdevId)
            logger.writeDebug("sng1104 rg={}", rg)
            logger.writeDebug("sng1104 resourceGroupName={}", rg.resourceGroupName)
            # logger.writeDebug("sng1104 virtualStorageId={}", rg.virtualStorageId)
            logger.writeDebug(
                "sng1104 virtualStorageDeviceId={}", virtualStorageDeviceId
            )
            logger.writeDebug("sng1104 virtualSerialNumber={}", virtualSerialNumber)

        return

    def get_vsm_info(self, vsms, resourceGroupId):
        # VirtualStorageMachineInfoList
        for vsm in vsms.data:
            for rgid in vsm.resourceGroupIds:
                if rgid == resourceGroupId:
                    return vsm.virtualStorageDeviceId, vsm.virtualSerialNumber

    def get_other_attributes_from_copy_group(self, cglist, gad_copy_pair, doSwap):
        if cglist is None:
            return
        cgname = gad_copy_pair["copyGroupName"]

        logger.writeDebug("sng1104 392 cgname={}", cgname)
        logger.writeDebug("sng1104 392 gad_copy_pair={}", gad_copy_pair)

        for cg in cglist.data:
            if cgname == cg.copyGroupName:
                gad_copy_pair["muNumber"] = cg.muNumber

                if doSwap:

                    # sng20241123 the copy group from swap-split,
                    logger.writeDebug("sng1104 392 cg={}", cg)
                    # do swap
                    gad_copy_pair["localDeviceGroupName"] = cg.remoteDeviceGroupName
                    gad_copy_pair["remoteDeviceGroupName"] = cg.localDeviceGroupName

                else:
                    gad_copy_pair["localDeviceGroupName"] = cg.localDeviceGroupName
                    gad_copy_pair["remoteDeviceGroupName"] = cg.remoteDeviceGroupName

                logger.writeDebug("sng1104 392 gad_copy_pair={}", gad_copy_pair)
                return

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

        return VspGadPairsInfo(data=items)


class DirectGADInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            # "replicationType": str,
            "ldevId": int,
            # ?
            "primaryHexVolumeId": str,
            "remoteSerialNumber": str,
            # "remoteStorageTypeId": str,
            "remoteLdevId": int,
            # "primaryOrSecondary": str,
            # ?
            "secondaryHexVolumeId": str,
            "muNumber": int,
            "status": str,
            # ?
            "serialNumber": str,
            "isSSWS": bool,
            # "entitlementStatus": str,
            # "partnerId": str,
            # "subscriberId": str,
        }

        self.parameter_mapping = {
            "ldev_id": "primary_volume_id",
            "remote_ldev_id": "secondary_volume_id",
            "mu_number": "mirror_unit_id",
            "remote_serial_number": "secondary_storage_serial",
            "serial_number": "primary_storage_serial",
            # "remote_storage_type_id": "secondary_storage_type_id",
        }

    def fix_bad_camel_to_snake_conversion(self, key):
        new_key = key.replace("s_s_w_s", "ssws")
        return new_key

    @log_entry_exit
    def extract(self, responses):
        new_items = []
        for response in responses:
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
            new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                new_dict.get("primary_volume_id")
            )
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

        new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
            new_dict.get("primary_volume_id")
        )
        new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
            new_dict.get("secondary_volume_id")
        )

        return new_dict


class DirectGADCopyPairInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "consistencyGroupId": int,
            "pvolLdevId": int,
            "svolLdevId": int,
            "pvolStatus": str,
            "svolStatus": str,
            "copyGroupName": str,
            "copyPairName": str,
            "localDeviceGroupName": str,
            "remoteDeviceGroupName": str,
            "primaryVSMResourceGroupName": str,
            "primaryVirtualSerialNumber": int,
            # "primaryVirtualStorageDeviceId": str,
            "primaryVirtualVolumeId": int,
            "secondaryVSMResourceGroupName": str,
            "secondaryVirtualSerialNumber": int,
            #  "secondaryVirtualStorageDeviceId": str,
            "secondaryVirtualVolumeId": int,
            "pvolVirtualLdevId": int,
            "svolVirtualLdevId": int,
            "muNumber": int,
            "remoteMirrorCopyPairId": str,
            # "entitlementStatus": str,
            # "partnerId": str,
            # "subscriberId": str,
            "isAluaEnabled": bool,
            "quorumDiskId": int,
            "primaryVolumeIdHex": str,
            "secondaryVolumeIdHex": str,
        }

        self.parameter_mapping = {
            "pvol_virtual_ldev_id": "primary_virtual_volume_id",
            "svol_virtual_ldev_id": "secondary_virtual_volume_id",
            "mu_number": "mirror_unit_id",
            "pvol_status": "primary_volume_status",
            "svol_status": "secondary_volume_status",
            "pvol_ldev_id": "primary_volume_id",
            "svol_ldev_id": "secondary_volume_id",
            # "pvol_status": "status",
            # "copy_pair_name": "pair_name",
        }

    def fix_bad_camel_to_snake_conversion(self, key):
        new_key = key.replace("s_s_w_s", "ssws")
        new_key = key.replace("v_s_m", "vsm")
        return new_key

    @log_entry_exit
    def extract(self, spec, responses):
        new_items = []
        if responses is None:
            return new_items
        if isinstance(responses, dict):
            responses = [responses]

        for response in responses:
            if response is None:
                continue

            new_dict = {
                "primary_volume_storage_id": self.storage_serial_number,
                "secondary_volume_storage_id": spec.secondary_storage_serial_number,
                "copy_pace_track_size": "",
                "copy_rate": "",
                "mirror_unit_id": "",
                "consistency_group_id": "",  # in case we get None in the input data
                "primary_vsm_resource_group_name": "",
                "secondary_vsm_resource_group_name": "",
            }

            if response.get("pvolStorageDeviceId"):
                new_dict["primary_volume_storage_id"] = (
                    get_serial_number_from_device_id(
                        response.get("pvolStorageDeviceId")
                    )
                )
            if response.get("svolStorageDeviceId"):
                new_dict["secondary_volume_storage_id"] = (
                    get_serial_number_from_device_id(
                        response.get("svolStorageDeviceId")
                    )
                )

            if response.get("primaryVolumeSize"):
                new_dict["primary_volume_size"] = response.get("primaryVolumeSize")
            if response.get("secondaryVolumeSize"):
                new_dict["secondary_volume_size"] = response.get("secondaryVolumeSize")

            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                if response is None:
                    return new_items
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                cased_key = self.fix_bad_camel_to_snake_conversion(cased_key)
                if response_key is not None and response_key != "":
                    if cased_key in self.parameter_mapping.keys():
                        cased_key = self.parameter_mapping[cased_key]
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
                new_dict.get("primary_volume_id")
            )
            new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
                new_dict.get("secondary_volume_id")
            )
            # new_dict["secondary_virtual_hex_volume_id"] = ""
            # new_dict["secondary_virtual_volume_id"] = ""
            if new_dict.get("mu_number"):
                new_dict.pop("mu_number")
            if new_dict.get("pvol_virtual_ldev_id"):
                new_dict.pop("pvol_virtual_ldev_id")
            if new_dict.get("svol_virtual_ldev_id"):
                new_dict.pop("svol_virtual_ldev_id")
            if new_dict.get("copy_rate"):
                new_dict.pop("copy_rate")
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
            cased_key = self.fix_bad_camel_to_snake_conversion(cased_key)
            if response_key is not None:
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                new_dict[cased_key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[cased_key] = default_value

        new_dict["primary_volume_id_hex"] = volume_id_to_hex_format(
            new_dict.get("primary_volume_id")
        )
        new_dict["secondary_volume_id_hex"] = volume_id_to_hex_format(
            new_dict.get("secondary_volume_id")
        )
        if new_dict.get("copy_rate"):
            new_dict.pop("copy_rate")

        return new_dict
