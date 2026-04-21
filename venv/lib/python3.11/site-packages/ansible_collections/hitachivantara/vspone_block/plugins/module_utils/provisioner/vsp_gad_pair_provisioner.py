try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..message.vsp_gad_pair_msgs import GADPairValidateMSG
    from ..provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from ..common.hv_constants import CommonConstants
    from ..common.vsp_constants import PairStatus, DEFAULT_NAME_PREFIX
    from ..provisioner.vsp_host_group_provisioner import VSPHostGroupProvisioner
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from ..message.vsp_gad_pair_msgs import GADFailedMsg
    from ..common.hv_constants import ConnectionTypes
    from ..common.hv_log import Log
    from ..model.vsp_resource_group_models import VSPResourceGroupSpec
    from ..model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
        DirectSpecificCopyGroupInfo,
        DirectSpecificCopyGroupInfoList,
    )
    from ..model.vsp_gad_pairs_models import (
        HostgroupSpec,
        VspGadPairsInfo,
    )
    from ..common.ansible_common import (
        log_entry_exit,
        convert_decimal_size_to_bytes,
    )
    from .vsp_remote_replication_helper import RemoteReplicationHelperForSVol

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from message.vsp_gad_pair_msgs import GADPairValidateMSG
    from provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from common.hv_constants import CommonConstants
    from common.vsp_constants import PairStatus, DEFAULT_NAME_PREFIX
    from provisioner.vsp_host_group_provisioner import VSPHostGroupProvisioner
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from message.vsp_gad_pair_msgs import GADFailedMsg
    from common.hv_constants import ConnectionTypes
    from common.hv_log import Log
    from model.vsp_resource_group_models import VSPResourceGroupSpec
    from model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
        DirectSpecificCopyGroupInfo,
        DirectSpecificCopyGroupInfoList,
    )
    from model.vsp_gad_pairs_models import (
        HostgroupSpec,
        VspGadPairsInfo,
    )
    from common.ansible_common import (
        log_entry_exit,
        convert_decimal_size_to_bytes,
    )
    from .vsp_remote_replication_helper import RemoteReplicationHelperForSVol

logger = Log()


class GADPairProvisioner:

    def __init__(self, connection_info, serial):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_GAD_PAIR
        )
        self.vol_gw = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )
        self.rg_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_RESOURCE_GROUP
        )
        self.cg_gw = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_COPY_GROUPS
        )
        self.storage_prov = VSPStorageSystemProvisioner(connection_info)
        self.connection_info = connection_info
        self.connection_type = connection_info.connection_type
        self.serial = serial

        self.gateway.set_storage_serial_number(serial)

    @log_entry_exit
    def get_resource_group_by_id_remote(self, spec, resourceGroupId):
        secondary_storage_connection_info = spec.secondary_storage_connection_info
        secondary_storage_connection_info.connection_type = ConnectionTypes.DIRECT
        if spec.secondary_storage_serial_number is None:
            spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(
                spec
            )
        rr_prov = GadHelperForSvol(
            secondary_storage_connection_info, spec.secondary_storage_serial_number
        )
        vol = rr_prov.get_resource_group_by_id(resourceGroupId)
        return vol

    @log_entry_exit
    def get_vsm_all(self):
        return self.rg_gateway.get_vsm_all()

    @log_entry_exit
    def get_secondary_serial_direct(self, spec):
        return self.gateway.get_secondary_serial(spec)

    @log_entry_exit
    def get_vsm_all_remote(self, spec):
        secondary_storage_connection_info = spec.secondary_storage_connection_info
        secondary_storage_connection_info.connection_type = ConnectionTypes.DIRECT
        if spec.secondary_storage_serial_number is None:
            spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(
                spec
            )
        rr_prov = GadHelperForSvol(
            secondary_storage_connection_info, spec.secondary_storage_serial_number
        )
        vsms = rr_prov.get_vsm_all()
        return vsms

    @log_entry_exit
    def get_vol_remote(self, spec, ldev):
        secondary_storage_connection_info = spec.secondary_storage_connection_info
        secondary_storage_connection_info.connection_type = ConnectionTypes.DIRECT
        if spec.secondary_storage_serial_number is None:
            spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(
                spec
            )
        rr_prov = GadHelperForSvol(
            secondary_storage_connection_info, spec.secondary_storage_serial_number
        )
        vol = rr_prov.get_volume_by_id(ldev)
        return vol

    @log_entry_exit
    def create_gad_pair(self, spec, pvol):

        #  auto config the is_new_group_creation
        copy_group = self.cg_gw.get_copy_group_by_name(spec)
        logger.writeDebug(f"copy_group result: {copy_group}")
        if copy_group is None:
            spec.is_new_group_creation = True
        else:
            spec.is_new_group_creation = False
            spec.muNumber = copy_group.muNumber

        # pvol = self.get_volume_by_id(spec.primary_volume_id)
        # if pvol is None:
        #     err_msg = (
        #         GADFailedMsg.PAIR_CREATION_FAILED.value
        #         + VSPTrueCopyValidateMsg.NO_PRIMARY_VOLUME_FOUND.value.format(
        #             spec.primary_volume_id
        #         )
        #     )
        #     logger.writeError(err_msg)
        #     raise ValueError(err_msg)

        # sng20241127 - pvol set_alua_mode
        if spec.set_alua_mode:
            self.vol_gw.change_volume_settings(
                spec.primary_volume_id, None, spec.set_alua_mode
            )

        # # verify the pvol isAluaEnabled
        # pvol = self.get_volume_by_id(spec.primary_volume_id)
        logger.writeDebug("PROV:813:pvol.isAluaEnabled = {}", pvol.isAluaEnabled)

        secondary_storage_connection_info = spec.secondary_storage_connection_info
        secondary_storage_connection_info.connection_type = ConnectionTypes.DIRECT
        if spec.secondary_storage_serial_number is None:
            spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(
                spec
            )
        rr_prov = GadHelperForSvol(
            secondary_storage_connection_info, spec.secondary_storage_serial_number
        )
        secondary_vol_id = None
        try:
            if spec.secondary_nvm_subsystem is not None:
                secondary_vol_id = rr_prov.get_secondary_volume_id_when_nvme(pvol, spec)
            elif spec.secondary_iscsi_targets is not None:
                secondary_vol_id = rr_prov.get_secondary_volume_id_when_iscsi_target(
                    pvol, spec
                )
            else:
                secondary_vol_id = rr_prov.get_secondary_volume_id(pvol, spec)
            spec.secondary_volume_id = secondary_vol_id
            result = self.gateway.create_gad_pair(spec)
            logger.writeDebug(f"create_gad_pair result: {result}")
            pair = self.cg_gw.get_one_copy_pair_by_id(
                result, spec.secondary_connection_info
            )
            self.connection_info.changed = True
            return pair
        except Exception as ex:
            # if the GAD creation fails, delete the secondary volume
            err_msg = GADFailedMsg.PAIR_CREATION_FAILED.value + str(ex)
            try:
                if secondary_vol_id:
                    if spec.secondary_nvm_subsystem is not None:
                        rr_prov.delete_volume_when_nvme(
                            secondary_vol_id,
                            pvol.nvmSubsystemId,
                            spec.secondary_nvm_subsystem,
                            pvol.namespaceId,
                        )
                    else:
                        if spec.provisioned_secondary_volume_id is None:
                            rr_prov.delete_volume(secondary_vol_id)
            except Exception as del_err:
                err_msg = err_msg + str(del_err)
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def validate_hg_details(self, spec):
        hg_prov = VSPHostGroupProvisioner(self.connection_info)

        def assign_hgs(hgs, input_hgs):
            hg_objects = []
            input_hgs_copy = input_hgs[:]
            for input_hg in input_hgs_copy:
                for hg in hgs.data:
                    if hg.hostGroupName == input_hg.name and hg.port == input_hg.port:
                        input_hgs.remove(input_hg)
                        hg_spec = HostgroupSpec(
                            id=hg.hostGroupId,
                            name=hg.hostGroupName,
                            port=hg.port,
                            resource_group_id=hg.resourceGroupId,
                        )
                        if input_hg.enable_preferred_path:
                            hg_spec.enable_preferred_path = (
                                input_hg.enable_preferred_path
                            )
                        hg_objects.append(hg_spec)
                        break
            return hg_objects

        if spec.primary_hostgroups:
            hgs = hg_prov.get_all_host_groups(spec.primary_storage_serial_number)
            hg_real = assign_hgs(hgs, spec.primary_hostgroups)
            if len(spec.primary_hostgroups) > 0:
                names = [hg.name for hg in spec.primary_hostgroups]
                err_msg = GADPairValidateMSG.PRIMARY_HG_NOT_FOUND.value.format(names)
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            spec.primary_hostgroups = hg_real

        if spec.secondary_hostgroups:
            if spec.secondary_storage_serial_number is None:
                spec.secondary_storage_serial_number = (
                    self.gateway.get_secondary_serial(spec)
                )
            hgs = hg_prov.get_all_host_groups(spec.secondary_storage_serial_number)
            real_sec_hg = assign_hgs(hgs, spec.secondary_hostgroups)
            if len(spec.secondary_hostgroups) > 0:
                names = [hg.name for hg in spec.secondary_hostgroups]
                err_msg = GADPairValidateMSG.SEC_HG_NOT_FOUND.value.format(names)
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            spec.secondary_hostgroups = real_sec_hg

    def get_copypair_dict_one(self, pairs, volume_id):
        logger.writeDebug("PROV::pairs={}", pairs)
        for pair in pairs:
            logger.writeDebug("PROV::pair={}", pair)
            copyPairs = pair.get("copyPairs", None)
            if copyPairs and len(copyPairs) > 0:
                for copyPair in copyPairs:
                    if copyPair["pvolLdevId"] == volume_id:
                        # just return the first one for now
                        logger.writeDebug("PROV::copyPair={}", copyPair)
                        return copyPair

    def get_copypair_one(self, pairs, volume_id):
        logger.writeDebug("PROV::pairs={}", pairs)
        logger.writeDebug("PROV::volume_id={}", volume_id)
        if pairs is None:
            return

        if isinstance(pairs, list):
            for copyPair in pairs:
                # expect DirectCopyPairInfo here
                if copyPair.pvolLdevId == volume_id:
                    # just return the first one for now
                    return copyPair.to_dict()

        if isinstance(pairs, DirectSpecificCopyGroupInfo):
            copyPairs = pairs.copyPairs
            if copyPairs and len(copyPairs) > 0:
                for copyPair in copyPairs:
                    if copyPair.pvolLdevId == volume_id:
                        # just return the first one for now
                        logger.writeDebug("PROV::copyPair={}", copyPair)
                        return copyPair.to_dict()

    def get_copypair_one_data(self, pairs, volume_id):
        logger.writeDebug("PROV::pairs={}", pairs)
        if pairs is None:
            return
        for pair in pairs.data:
            logger.writeDebug("PROV::pair={}", pair)
            copyPairs = pair.copyPairs
            if copyPairs and len(copyPairs) > 0:
                for copyPair in copyPairs:
                    if copyPair.pvolLdevId == volume_id:
                        # just return the first one for now
                        logger.writeDebug("PROV::copyPair={}", copyPair)
                        return copyPair.to_dict()

    @log_entry_exit
    def get_copy_group_list(self):
        return self.cg_gw.get_copy_group_list()

    @log_entry_exit
    def get_gad_pair_by_pvol_id(self, spec, volume_id):
        logger.writeDebug("PROV:215 self.connection_type={}", self.connection_type)
        if self.connection_type == "direct":
            #  sng1104 - use copy group, get_all_copy_pairs_by_copygroup_name
            # pairs = self.cg_gw.get_all_copy_pairs_by_copygroup_name(spec)
            pairs = self.cg_gw.get_all_copy_pairs(spec)
            return self.get_copypair_one(pairs, volume_id)
        else:
            pairs = self.get_all_gad_pairs(spec)
            for pair in pairs.data:
                if pair.primaryVolumeId == volume_id:
                    return pair

    @log_entry_exit
    def get_gad_pair_by_svol_id(self, spec, volume_id):
        logger.writeDebug("PROV:215 self.connection_type={}", self.connection_type)
        if self.connection_type == "direct":
            return
        else:
            pairs = self.get_all_gad_pairs(spec)
            for pair in pairs.data:
                logger.writeDebug("PROV:215 pair={}", pair)
                if int(pair.secondaryVolumeId) == int(volume_id):
                    return pair

    @log_entry_exit
    def get_all_gad_pairs(self, spec):
        # DIRECT should use gad_pair_facts cg_gw
        pairs = self.gateway.get_all_gad_pairs(spec)
        return pairs

    @log_entry_exit
    def get_gad_pair_by_id(self, gad_pair_id):

        #  don't expect DIRECT to call this one, it goes thru CG

        # TODO - spec is not needed for gateway, clean up the gateway layer later
        spec = None
        pairs = self.get_all_gad_pairs(spec)
        for pair in pairs.data:
            if self.connection_type == "direct":
                if pair.ldevId == gad_pair_id:
                    return pair
            else:
                if (pair.resourceId == gad_pair_id) or (
                    pair.primaryVolumeId == gad_pair_id
                ):
                    return pair

    @log_entry_exit
    def get_gad_pair_by_svol_id_gw(self, gad_pair_id):

        #  don't expect DIRECT to call this one, it goes thru CG

        # TODO - spec is not needed for gateway, clean up the gateway layer later
        spec = None
        pairs = self.get_all_gad_pairs(spec)
        for pair in pairs.data:
            if self.connection_type == "direct":
                if pair.ldevId == gad_pair_id:
                    return pair
            else:
                if (pair.resourceId == gad_pair_id) or (
                    pair.secondaryVolumeId == gad_pair_id
                ):
                    return pair

    @log_entry_exit
    def delete_gad_pair(self, spec, gad_pair):
        logger.writeDebug(f"PROV:gad_pair:gad_pair: {gad_pair}")

        if isinstance(gad_pair, DirectCopyPairInfo):
            # after the auto split, the input "pair" is a DirectCopyPairInfo obj
            if gad_pair.pvolStatus == PairStatus.PSUS:
                self.gateway.delete_gad_pair(spec, gad_pair.remoteMirrorCopyPairId)
                # pvol = self.get_volume_by_id(gad_pair.pvolLdevId)
                if spec.should_delete_svol is True:
                    spec.secondary_volume_id = gad_pair.svolLdevId
                    if spec.secondary_storage_serial_number is None:
                        spec.secondary_storage_serial_number = (
                            self.gateway.get_secondary_serial(spec)
                        )
                    rr_prov = GadHelperForSvol(
                        spec.secondary_storage_connection_info,
                        spec.secondary_storage_serial_number,
                    )
                    rr_prov.delete_volume_and_all_mappings(spec.secondary_volume_id)
            else:
                return GADPairValidateMSG.DELETE_GAD_FAIL_SPLIT_DIRECT.value
        else:
            if gad_pair["pvolStatus"] == PairStatus.PSUS:
                self.gateway.delete_gad_pair(spec, gad_pair["remoteMirrorCopyPairId"])
                if spec.should_delete_svol is True:
                    spec.secondary_volume_id = gad_pair["svolLdevId"]
                    if spec.secondary_storage_serial_number is None:
                        spec.secondary_storage_serial_number = (
                            self.gateway.get_secondary_serial(spec)
                        )
                    rr_prov = GadHelperForSvol(
                        spec.secondary_storage_connection_info,
                        spec.secondary_storage_serial_number,
                    )
                    rr_prov.delete_volume_and_all_mappings(spec.secondary_volume_id)
            else:
                return GADPairValidateMSG.DELETE_GAD_FAIL_SPLIT_DIRECT.value

        self.connection_info.changed = True
        return GADPairValidateMSG.DELETE_GAD_PAIR_SUCCESS.value

    @log_entry_exit
    def swap_resync_gad_pair(self, spec=None, gad_pair=None):
        spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(spec)
        swap_pair_id = self.gateway.swap_resync_gad_pair(spec)
        pair_id = swap_pair_id
        #  don't swap for GAD
        # pair_id = self.gateway.get_pair_id_from_swap_pair_id(swap_pair_id, spec.secondary_connection_info)
        # logger.writeDebug(f"PV: swap_pair_id = {swap_pair_id} pair_id = {pair_id}")
        pair = self.cg_gw.get_one_copy_pair_by_id(
            pair_id, spec.secondary_connection_info
        )

        #  sng20241123 make the call so the copy group is save to global
        #  we need it for get_other_attributes()
        cg = self.cg_gw.get_copy_group_by_name(spec)
        logger.writeDebug(f"PV: 362 cg = {cg}")

        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def get_gad_pair_by_copy_group_and_copy_pair_name(self, spec):
        return self.cg_gw.get_gad_pair_by_copy_group_and_copy_pair_name(spec)

    @log_entry_exit
    def swap_split_gad_pair(self, spec=None, gad_pair=None):
        spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(spec)
        tc = self.cg_gw.get_gad_pair_by_copy_group_and_copy_pair_name(spec)
        logger.writeDebug(f"PV: 362 tc = {tc}")

        if tc is None:
            return "GAD pair is not found"

        # sng20241126 swap_split_gad_pair consistencyGroupId check
        if tc.consistencyGroupId is not None:
            if isinstance(tc.consistencyGroupId, int) and tc.consistencyGroupId != "-1":
                return GADPairValidateMSG.NO_SWAP_SPLIT_WITH_CTG.value
            if tc.consistencyGroupId != "-1" and tc.consistencyGroupId != "":
                return GADPairValidateMSG.NO_SWAP_SPLIT_WITH_CTG.value

        swap_pair_id = self.gateway.swap_split_gad_pair(spec)
        pair_id = swap_pair_id
        #  don't swap for GAD
        # pair_id = self.gateway.get_pair_id_from_swap_pair_id(swap_pair_id, spec.secondary_connection_info)

        pair = self.cg_gw.get_one_copy_pair_by_id(
            pair_id, spec.secondary_connection_info
        )
        logger.writeDebug(f"PV: 362 pair = {pair}")
        #  here the pair is DirectCopyPairInfo with
        #   remoteMirrorCopyPairId='A34000810050,test_GAD2,test_GAD2S_,test_GAD2P_,test_GAD_pair1'

        #  sng20241123 make the call so the copy group is save to global
        #  we need it for get_other_attributes()
        cg = self.cg_gw.get_copy_group_by_name(spec)
        logger.writeDebug(f"PV: 362 cg = {cg}")

        self.connection_info.changed = True
        return pair

    #  sng20241115 split_gad_pair
    @log_entry_exit
    def split_gad_pair(self, spec=None, gad_pair=None):

        #  connection_type is DIRECT

        # common code is checking it?
        # if gad_pair["pvolStatus"] == PairStatus.PSUS:
        #     # already in split state
        #     return gad_pair

        # tc = None
        # if spec.primary_volume_id:
        #     primary_volume_id = spec.primary_volume_id
        #     tc = self.get_gad_for_primary_vol_id(spec, primary_volume_id)
        #     if tc is None:
        #         raise ValueError(GADPairValidateMSG.NO_PAIR_FOR_PRIMARY_VOLUME_ID.value.format(primary_volume_id))
        #     if tc.pvolStatus == 'PSUE' :
        #         return tc

        spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(spec)

        tc = gad_pair
        if tc is None:
            tc = self.cg_gw.get_gad_pair_by_copy_group_and_copy_pair_name(spec)
            if tc is None:
                err_msg = (
                    GADFailedMsg.PAIR_SPLIT_FAILED.value
                    + GADPairValidateMSG.NO_GAD_PAIR_FOUND_FOR_INPUTS.value
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)
        logger.writeDebug(f"PV:: 331 tc=  {tc}")
        if isinstance(tc, dict):
            # from
            pvolStatus = tc["pvolStatus"]
            svolStatus = tc["svolStatus"]
            remoteMirrorCopyPairId = tc["remoteMirrorCopyPairId"]
            sss = remoteMirrorCopyPairId.split(",")
            spec.local_device_group_name = sss[2]
            spec.remote_device_group_name = sss[3]
            spec.copy_pair_name = sss[4]
        else:
            pvolStatus = tc.pvolStatus
            svolStatus = tc.svolStatus

        if pvolStatus == PairStatus.PSUS:
            # already in split state
            return tc

        if tc is not None and svolStatus == "SSWS":
            swap_pair_id = self.gateway.swap_split_gad_pair(spec, "PSUS")
            pair_id = self.gateway.get_pair_id_from_swap_pair_id(
                swap_pair_id, spec.secondary_connection_info
            )
            logger.writeDebug(f"PV: swap_pair_id = {swap_pair_id} pair_id = {pair_id}")
            pair = self.cg_gw.get_one_copy_pair_by_id(
                pair_id, spec.secondary_connection_info
            )
            self.connection_info.changed = True
            return pair
        else:
            pair_id = self.gateway.split_gad_pair(spec)
            logger.writeDebug(f"PV:: pair_id=  {pair_id}")
            pair = self.cg_gw.get_one_copy_pair_by_id(
                pair_id, spec.secondary_connection_info
            )
            self.connection_info.changed = True
            return pair

    @log_entry_exit
    def get_gad_for_primary_vol_id(self, spec, primary_vol_id):
        all_tc_pairs = self.get_all_gad_pairs_direct(spec=spec)
        logger.writeDebug(
            f"PV:: get_gad_for_primary_vol_id all_tc_pairs=  {all_tc_pairs}"
        )

        #  sng20241115 isinstance DirectCopyPairInfo
        if isinstance(all_tc_pairs, DirectCopyPairInfo):
            tc = all_tc_pairs
            if tc.pvolLdevId == primary_vol_id:
                return tc

        for tc in all_tc_pairs.data:
            if hasattr(tc, "ldevId"):
                if tc.ldevId == primary_vol_id:
                    return tc
            if hasattr(tc, "primaryVolumeId"):
                if tc.primaryVolumeId == primary_vol_id:
                    return tc

        return None

    #  sng20241115 resync_gad_pair
    @log_entry_exit
    def resync_gad_pair(self, spec=None, gad_pair=None):
        #  connection_type is DIRECT

        # common code is checking it?
        # if gad_pair["pvolStatus"] == PairStatus.PAIR:
        #     # already in resync state
        #     return gad_pair

        # tc = None
        # if spec.primary_volume_id:
        #     primary_volume_id = spec.primary_volume_id
        #     tc = self.get_gad_for_primary_vol_id(spec, primary_volume_id)
        #     if tc is None:
        #         raise ValueError(GADPairValidateMSG.NO_PAIR_FOR_PRIMARY_VOLUME_ID.value.format(primary_volume_id))
        #     logger.writeDebug(f"PROV:resync_gad_pair:tc : {tc}")
        #     if tc.pvolStatus == 'PAIR' :
        #         #  sng20241115 resync_gad_pair already in PAIR, tc is a CG
        #         return tc

        spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(spec)
        tc = self.cg_gw.get_gad_pair_by_copy_group_and_copy_pair_name(spec)
        if tc is None:
            err_msg = (
                GADFailedMsg.PAIR_RESYNC_FAILED.value
                + GADPairValidateMSG.NO_GAD_PAIR_FOUND_FOR_INPUTS.value
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if tc.pvolStatus == PairStatus.PAIR:
            # already in pair state
            return tc

        pair_id = self.gateway.resync_gad_pair(spec)
        logger.writeDebug(f"PV: pair_id=  {pair_id}")
        pair = self.cg_gw.get_one_copy_pair_by_id(
            pair_id, spec.secondary_connection_info
        )
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def is_resize_needed(self, volume_data, spec):
        size_in_bytes = convert_decimal_size_to_bytes(spec.new_volume_size)
        if volume_data.blockCapacity > size_in_bytes:
            logger.writeDebug(
                "PV:resize_true_copy_copy_pair: Shrink/reduce volume size is not supported."
            )
            return False

        expand_val = size_in_bytes - (
            volume_data.blockCapacity if volume_data.blockCapacity else 0
        )
        if expand_val > 0:
            return True
        return False

    @log_entry_exit
    def resize_gad_pair(self, spec=None):
        pair_id = None
        if spec.copy_group_name and spec.copy_pair_name:
            tc = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            logger.writeDebug(f"PV:resize_gad_pair: tc=  {tc}")
            if tc is not None and len(tc) > 0:
                pvol_id = tc[0].pvolLdevId
                svol_id = tc[0].svolLdevId
                pvol_data = self.vol_gw.get_volume_by_id(pvol_id)
                svol_data = self.vol_gw.get_volume_by_id(svol_id)
                resize_needed = self.is_resize_needed(pvol_data, spec)
                if resize_needed is False:
                    err_msg = (
                        GADFailedMsg.PAIR_RESIZE_FAILED.value
                        + VSPTrueCopyValidateMsg.REDUCE_VOLUME_SIZE_NOT_SUPPORTED.value
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    pair_id = self.gateway.resize_gad_pair(tc[0], spec)
                    logger.writeDebug(
                        f"resize_true_copy_copy_pair: pair_id=  {pair_id}"
                    )
                    pair = self.cg_gw.get_one_copy_pair_by_id(
                        tc[0].remoteMirrorCopyPairId, spec.secondary_connection_info
                    )
                    self.connection_info.changed = True
                    return pair
            else:
                err_msg = (
                    GADFailedMsg.PAIR_RESIZE_FAILED.value
                    + GADPairValidateMSG.GAD_PAIR_NOT_FOUND.value.format(
                        spec.copy_pair_name
                    )
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

    @log_entry_exit
    def gad_pair_facts(self, gad_pair_facts_spec=None):
        # sng20241115 - prov.gad_pair_facts.direct
        spec = gad_pair_facts_spec
        # logger.writeDebug("sng20241115 get_all_gad_pairs_direct.secondary_connection_info ={}", spec.secondary_connection_info)

        tc_pairs = self.get_all_gad_pairs_direct(spec=spec)

        logger.writeDebug(f"PV:: pairs=  {tc_pairs}")
        if tc_pairs is None:
            return tc_pairs
        if spec is None:
            return tc_pairs
        else:
            ret_tc_pairs = self.apply_filters(tc_pairs, spec)
            return VspGadPairsInfo(data=ret_tc_pairs)

    # sng20241115 - prov.get_all_gad_pairs_direct
    @log_entry_exit
    def get_all_gad_pairs_direct(self, serial=None, spec=None):
        if serial is None:
            serial = self.serial
        if spec is None:
            ret_list = self.gateway.get_all_gad_pairs(serial)
            logger.writeDebug(
                f"PROV:get_all_gad_pairs_direct:ret_list= {ret_list} serial = {serial}"
            )
            return ret_list
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            # First we check if there is a copy group name present in the spec
            spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(
                spec
            )

            if (
                spec.copy_group_name
                and spec.copy_pair_name
                and spec.local_device_group_name
                and spec.remote_device_group_name
            ):
                return self.cg_gw.get_remote_copy_pair_by_id(spec)

            if spec.copy_group_name and spec.copy_pair_name:
                return self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(
                    spec
                )

            if spec.copy_group_name:
                return self.cg_gw.get_remote_pairs_for_a_copy_group(spec)

            if spec.primary_volume_id:
                return self.cg_gw.get_remote_pairs_by_pvol(spec)

            if spec.secondary_volume_id:
                return self.cg_gw.get_remote_pairs_by_svol(spec)

            # ret_list = self.cg_gw.get_all_copy_pairs(spec)
            ret_list = self.cg_gw.get_all_remote_pairs_from_copy_groups(spec)
            return ret_list
            # return DirectCopyPairInfoList(data=ret_list)

    @log_entry_exit
    def apply_filters(self, tc_pairs, spec):
        pairs = self.get_gad_copypairs(tc_pairs)

        result = pairs
        if not spec.primary_volume_id and not spec.secondary_volume_id:
            return result

        if pairs and spec.primary_volume_id:
            result = []
            for pair in pairs:
                logger.writeDebug("sng20241115 pair={}", pair)
                if pair.pvolLdevId != spec.primary_volume_id:
                    continue
                result.append(pair)
            return result

        if pairs and spec.secondary_volume_id:
            result = []
            for pair in pairs:
                logger.writeDebug("sng20241115 pair={}", pair)
                if pair.svolLdevId != spec.secondary_volume_id:
                    continue
                result.append(pair)
            return result

        return result

    @log_entry_exit
    def apply_filter_pvol(self, tc_pairs, primary_vol_id):

        if not isinstance(tc_pairs, list):
            tc_pairs = [tc_pairs]

        ret_val = []
        for tc in tc_pairs:
            logger.writeDebug("sng20241115 pair={}", tc)
            tc = self.get_gad_pair_by_pvol_new(
                self.get_gad_copypairs(tc), primary_vol_id
            )
            # if tc.ldevId == primary_vol_id or tc.remoteLdevId == primary_vol_id:
            if tc:
                ret_val.append(tc)
        return ret_val

    # sng20241115 pair: DirectSpecificCopyGroupInfo or list
    @log_entry_exit
    def get_gad_copypairs(self, pair):

        logger.writeDebug("sng20241115 :pair={}", pair)

        if isinstance(pair, list):
            return self.get_gad_copypairs_from_list(pair)
        if isinstance(pair, DirectSpecificCopyGroupInfoList):
            return self.get_gad_copypairs_from_list(pair.data_to_list())

        gad_pairs = []

        if isinstance(pair, DirectCopyPairInfo):
            if (
                pair.replicationType == "GAD"
                and pair.svolStatus != "SMPL"
                # commented by ansible sanity test
                # and copyPair.pvolStatus != "SMPL"
            ):
                gad_pairs.append(pair)
                return gad_pairs

        copyPairs = pair.copyPairs
        if copyPairs is None:
            return

        for copyPair in copyPairs:
            # sng20241115 change replicationType here to use other types for testing
            if (
                copyPair.replicationType == "GAD"
                and copyPair.svolStatus != "SMPL"
                and copyPair.pvolStatus != "SMPL"
            ):
                gad_pairs.append(copyPair)

        return gad_pairs

    @log_entry_exit
    def get_gad_copypairs_from_list(self, cgList):

        gad_pairs = []

        logger.writeDebug("sng20241115 :cg={}", cgList)
        if isinstance(cgList, dict):
            return self.get_gad_copypairs_from_dict(cgList, gad_pairs)

        for cg in cgList:
            if cg is None:
                continue

            logger.writeDebug("sng20241115 :cg={}", cg)

            if isinstance(cg, dict):
                gad_pairs = self.get_gad_copypairs_from_dict(cg, gad_pairs)
                continue

            copyPairs = None
            #  handle cg class object if needed
            if isinstance(cg, DirectCopyPairInfo):
                copyPairs = [cg]
            elif hasattr(cg, "copyPairs"):
                copyPairs = cg.copyPairs

            logger.writeDebug("sng20241115 :copyPairs={}", cg)
            if copyPairs is None:
                continue

            for copyPair in copyPairs:
                if (
                    copyPair.replicationType == "GAD"
                    and copyPair.svolStatus != "SMPL"
                    and copyPair.pvolStatus != "SMPL"
                ):
                    gad_pairs.append(copyPair)

        return gad_pairs

    @log_entry_exit
    def get_gad_copypairs_from_dict(self, cgs, gad_pairs):

        if cgs is None:
            return gad_pairs
        if not isinstance(cgs, dict):
            return gad_pairs

        # cgs is a dict, the element of the dict can some time be an array

        for cg in cgs:

            if cg is None:
                continue

            logger.writeDebug("sng20241115 :cg={}", cg)

            if isinstance(cg, str):
                # this element of the dict is not an array,
                # we can now get the copyPairs from the cgs dict
                copyPairs = cgs["copyPairs"]

                if isinstance(copyPairs, dict):
                    for copyPair in copyPairs:
                        if (
                            copyPair["replicationType"] == "GAD"
                            and copyPair["svolStatus"] != "SMPL"
                            and copyPair.pvolStatus != "SMPL"
                        ):
                            gad_pairs.append(copyPair)
                else:
                    # handle copyPair class objects
                    for copyPair in copyPairs:
                        if isinstance(copyPair, dict):
                            if (
                                copyPair["replicationType"] == "GAD"
                                and copyPair["svolStatus"] != "SMPL"
                                and copyPair.pvolStatus != "SMPL"
                            ):
                                gad_pairs.append(copyPair)
                        else:
                            if (
                                copyPair.replicationType == "GAD"
                                and copyPair.svolStatus != "SMPL"
                                and copyPair.pvolStatus != "SMPL"
                            ):
                                gad_pairs.append(copyPair)

                return gad_pairs

            #  cg is a list of dict
            items = cg
            if not isinstance(cg, list):
                return gad_pairs

            for cg in items:

                copyPairs = cg["copy_pairs"]
                if copyPairs is None:
                    continue

                for copyPair in copyPairs:
                    if (
                        copyPair.replicationType == "GAD"
                        and copyPair.svolStatus != "SMPL"
                        and copyPair.pvolStatus != "SMPL"
                    ):
                        gad_pairs.append(copyPair)

        return gad_pairs

    # sng20241115 pairs: []DirectCopyPairInfo
    def get_gad_pair_by_pvol_new(self, copyPairs, volume_id):
        logger.writeDebug("sng20241115 :copyPairs={}", copyPairs)
        if copyPairs is None:
            return
        if not isinstance(copyPairs, list):
            copyPairs = [copyPairs]
        for copyPair in copyPairs:
            if isinstance(copyPair, dict):
                if copyPair["pvolLdevId"] == volume_id:
                    # just return the first one for now
                    logger.writeDebug("sng20241115 found copyPair={}", copyPair)
                    return copyPair
            else:
                if copyPair.pvolLdevId == volume_id:
                    # just return the first one for now
                    logger.writeDebug("sng20241115 found copyPair={}", copyPair)
                    return copyPair

    @log_entry_exit
    def apply_filter_svol(self, tc_pairs, secondary_vol_id):
        ret_val = []

        for tc in tc_pairs:
            if tc.remoteLdevId == secondary_vol_id or tc.ldevId == secondary_vol_id:
                ret_val.append(tc)
        return ret_val

    @log_entry_exit
    def gad_pair_facts_v1(self, gad_pair_facts_spec):
        # sng1104 - GET FACTS, formatting is in the reconciler layer
        # do pegasus switch here
        # invalid code , commented by ansible sanity test
        # if False:
        #     # faster but missing some info and not for pegasus
        #     pairs = self.gateway.get_all_gad_pairs(gad_pair_facts_spec)
        # else:
        #     # pegasus has to use copy group, slower
        pairs = self.cg_gw.get_all_copy_pairs(gad_pair_facts_spec)
        return pairs

    @log_entry_exit
    def get_secondary_storage_system_serial(self, serial_number):
        system = self.storage_prov.get_storage_ucp_system(serial_number)
        if not system:
            err_msg = GADPairValidateMSG.SECONDARY_SYSTEM_NT_FOUND.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        elif system.ucpSystems[0] == CommonConstants.UCP_SERIAL:
            pass
            # raise ValueError(GADPairValidateMSG.SECONDARy_SYSTEM_CANNOT_BE_SAME.value)
        return system.ucpSystems[0]

    @log_entry_exit
    def check_ucp_system(self, serial):
        serial, resource_id = self.storage_prov.check_ucp_system(serial)
        self.serial = serial
        self.gateway.resource_id = resource_id
        self.gateway.serial = serial
        return serial

    @log_entry_exit
    def check_storage_in_ucpsystem(self) -> bool:
        return self.gateway.check_storage_in_ucpsystem()

    @log_entry_exit
    def get_resource_group_by_id(self, resourceGroupId):
        return self.rg_gateway.get_resource_group_by_id(resourceGroupId)

    @log_entry_exit
    def get_volume_by_id(self, primary_volume_id):

        volume = self.vol_gw.get_volume_by_id(primary_volume_id)
        # return vol_gw.get_volume_by_id(device_id, primary_volume_id)
        logger.writeDebug(f"PROV:get_volume_by_id:volume: {volume}")

        return volume


class GadHelperForSvol(RemoteReplicationHelperForSVol):
    def __init__(self, connection_info, serial):
        super().__init__(connection_info, serial)
        self.rg_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_RESOURCE_GROUP
        )

    @log_entry_exit
    def get_resource_group_by_id(self, resourceGroupId):
        return self.rg_gateway.get_resource_group_by_id(resourceGroupId)

    @log_entry_exit
    def get_vsm_all(self):
        return self.rg_gateway.get_vsm_all()

    @log_entry_exit
    def get_volume_by_id(self, id):
        vol = self.vol_gateway.get_volume_by_id(id)
        return vol

    @log_entry_exit
    def delete_volume(self, secondary_vol_id, volume=None):
        if volume is None:
            volume = self.vol_gateway.get_volume_by_id(secondary_vol_id)

        self.delete_lun_path(volume)
        self.move_volume_back_to_meta(volume)
        self.delete_actual_volume(secondary_vol_id, volume)

    @log_entry_exit
    def delete_volume_when_nvme(
        self, secondary_vol_id, nvm_id, nvmsubsystem, namespace_id, volume=None
    ):
        if volume is None:
            volume = self.vol_gateway.get_volume_by_id(secondary_vol_id)
        if nvm_id is None:
            nvm_id = volume.nvmSubsystemId
        if namespace_id is None:
            namespace_id = volume.namespaceId

        self.delete_ns_path_and_namespace(nvm_id, nvmsubsystem, namespace_id)
        self.move_volume_back_to_meta(volume)
        self.delete_actual_volume(secondary_vol_id, volume)

    @log_entry_exit
    def get_secondary_volume_id(self, vol_info, spec):
        logger.writeDebug("PROV:813:primary_volume = {}", vol_info)

        # Fail early, save time
        # Before creating the secondary volume check if secondary hostgroups exist
        host_groups = self.get_secondary_hostgroups(spec.secondary_hostgroups)
        if host_groups is None and spec.provisioned_secondary_volume_id is None:
            err_msg = GADPairValidateMSG.NO_REMOTE_HGS_FOUND.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if spec.provisioned_secondary_volume_id:
            svol_id = spec.provisioned_secondary_volume_id
            sec_vol_info = self.vol_gateway.get_volume_by_id(svol_id)
            hgs_prov_svol = self.get_hgs_for_provisioned_svol(sec_vol_info)
            logger.writeDebug(
                "PROV:get_secondary_volume_id:hgs_prov_svol = {}", hgs_prov_svol
            )
            host_groups = self.find_hgs_to_add_for_provisioned_svol(
                host_groups, hgs_prov_svol
            )
            logger.writeDebug(
                "PROV:get_secondary_volume_id:host_groups = {}", host_groups
            )
        else:
            svol_id = self.select_secondary_volume_id(vol_info.ldevId, spec)

        sec_vol_spec = self.construct_svol_spec(svol_id, vol_info, spec)

        sec_vol_name = None
        if spec.provisioned_secondary_volume_id:
            sec_vol_id = spec.provisioned_secondary_volume_id
        else:
            sec_vol_id = self.vol_gateway.create_volume(sec_vol_spec)
            # the name change is done in the update_volume method
            if vol_info.label is not None and vol_info.label != "":
                sec_vol_name = vol_info.label
            else:
                sec_vol_name = f"{DEFAULT_NAME_PREFIX}-{vol_info.ldevId}"

            logger.writeDebug("PROV:1221:sec_vol_name = {}", sec_vol_name)

        # sng20241127 - set svol label/name and set_alua_mode
        set_alua_mode = None
        if spec.set_alua_mode:
            set_alua_mode = spec.set_alua_mode

        if not spec.provisioned_secondary_volume_id:
            try:
                self.vol_gateway.change_volume_settings(
                    sec_vol_id, sec_vol_name, set_alua_mode
                )
            except Exception as ex:
                err_msg = GADFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
                logger.writeError(err_msg)
                # if setting the volume name fails, delete the secondary volume
                self.delete_volume(sec_vol_id)
                raise ValueError(err_msg)
        else:
            self.vol_gateway.change_volume_settings(sec_vol_id, None, set_alua_mode)

        try:
            # verify the svol set label and set_alua_mode
            sec_vol_info = self.vol_gateway.get_volume_by_id(sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol_id = {}", sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol = {}", sec_vol_info)
            logger.writeDebug(
                "PROV:813:sec_vol isAluaEnabled= {}", sec_vol_info.isAluaEnabled
            )
            if sec_vol_info.virtualLdevId is None:
                self.vol_gateway.unassign_vldev(sec_vol_id, sec_vol_id)
            elif (
                sec_vol_info.virtualLdevId != 65534
                and sec_vol_info.virtualLdevId != 65535
            ):
                self.vol_gateway.unassign_vldev(sec_vol_id, sec_vol_info.virtualLdevId)

            # self.vol_gateway.assign_vldev(sec_vol_id, sec_vol_id)
            logger.writeDebug(
                "PROV:get_secondary_volume_id:sec_vol_id = {}", sec_vol_id
            )
            logger.writeDebug(
                "PROV:get_secondary_volume_id:sec_vol_spec = {}", sec_vol_spec
            )
            logger.writeDebug(
                "PROV:get_secondary_volume_id:sec_vol_info= {}", sec_vol_info
            )

            # Can't blindly remove the ldev from the resource group, it could be
            # already attached to some hostgroups
            hg_resource_id = None
            if host_groups and len(host_groups) > 0:
                logger.writeDebug(
                    "PROV:get_secondary_volume_id:host_groups= {}", host_groups
                )
                hg_resource_id = host_groups[0].resourceGroupId
            else:
                if spec.provisioned_secondary_volume_id:
                    logger.writeDebug(
                        "PROV:get_secondary_volume_id:hgs_prov_svol= {}", hgs_prov_svol
                    )
                    if hgs_prov_svol and len(hgs_prov_svol):
                        hg_resource_id = hgs_prov_svol[0].resourceGroupId

            # if the secondary volume RG does not match with HG RG throw error
            if hg_resource_id:
                if (
                    sec_vol_info.resourceGroupId != 0
                    and sec_vol_info.resourceGroupId != hg_resource_id
                ):
                    err_msg = (
                        GADFailedMsg.SEC_VOLUME_OPERATION_FAILED.value
                        + GADPairValidateMSG.RG_DID_NOT_MATCH.value
                    )
                    raise ValueError(err_msg)
            else:
                # if there is a lun path you can't change RG ID
                if sec_vol_info.resourceGroupId != 0 and sec_vol_info.numOfPorts == 0:
                    rm_resource_spec = VSPResourceGroupSpec()
                    rm_resource_spec.ldevs = [int(sec_vol_id)]
                    self.rg_gateway.remove_resource(
                        sec_vol_info.resourceGroupId, rm_resource_spec
                    )
            if hg_resource_id:
                add_resource_spec = VSPResourceGroupSpec()
                add_resource_spec.ldevs = [int(sec_vol_id)]
                resourceGroupId = hg_resource_id
                logger.writeDebug(
                    "PROV:get_secondary_volume_id:resourceGroupId = {}", resourceGroupId
                )
                if resourceGroupId != 0:
                    self.rg_gateway.add_resource(resourceGroupId, add_resource_spec)

                #  sng1104 - TODO enable_preferred_path goes here if needed?
                # hg_info = self.parse_hostgroup(host_group)
                # logger.writeDebug("PROV:get_secondary_volume_id:hg_info = {}", hg_info)

                #  sng1104 - on the 2nd storage, find the hg.RG, move ldev to RG

            # GAD reserved
            if sec_vol_info.virtualLdevId != 65535:
                self.vol_gateway.assign_vldev(sec_vol_id, 65535)
            vol_info = self.vol_gateway.get_volume_by_id(sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol_id 1397 = {}", sec_vol_id)

            if host_groups is not None and len(host_groups) > 0:
                lun_ids = self.find_lun_ids_from_spec(
                    host_groups, spec.secondary_hostgroups
                )
                self.add_luns_to_host_groups(sec_vol_id, host_groups, lun_ids)

        except Exception as ex:
            err_msg = GADFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
            logger.writeError(err_msg)
            if not spec.provisioned_secondary_volume_id:
                # if attaching the volume to the host group fails, delete the secondary volume
                try:
                    self.delete_volume(sec_vol_id)
                except Exception as e:
                    logger.writeError(err_msg)
            else:
                # if attaching the volume to the host group fails, detach them
                logger.writeDebug("PROV:062725:host_groups = {}", host_groups)
                self.dettach_hostgroups(sec_vol_id, host_groups)

            raise Exception(err_msg)
        return sec_vol_id

    @log_entry_exit
    def get_secondary_volume_id_when_nvme(self, vol_info, spec):

        logger.writeDebug("PROV:813:primary_volume = {}", vol_info)
        # capture namespace ID
        pvolNameSpaceId = vol_info.namespaceId
        pvolNvmSubsystemId = vol_info.nvmSubsystemId
        self.validate_virtual_ldev_id(vol_info)
        self.validate_namespace_id(vol_info)

        # Fail early, save time
        # Before creating the secondary volume check if secondary hostgroup exists
        # host_group = self.get_secondary_hostgroup(spec.secondary_hostgroups)
        logger.writeDebug("PROV: nvmesubsystem spec = {}", spec.secondary_nvm_subsystem)
        nvme_subsystem = self.get_nvmesubsystem_by_name(spec.secondary_nvm_subsystem)
        if nvme_subsystem is None:
            err_msg = VSPTrueCopyValidateMsg.NO_REMOTE_NVME_FOUND.value.format(
                spec.secondary_nvm_subsystem.name
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if int(nvme_subsystem.nvmSubsystemId) != int(pvolNvmSubsystemId):
            err_msg = VSPTrueCopyValidateMsg.NVMSUBSYSTEM_DIFFER.value.format(
                nvme_subsystem.nvmSubsystemId, pvolNvmSubsystemId
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if spec.provisioned_secondary_volume_id:
            svol_id = spec.provisioned_secondary_volume_id
        else:
            svol_id = self.select_secondary_volume_id(vol_info.ldevId, spec)

        sec_vol_spec = self.construct_svol_spec(svol_id, vol_info, spec)

        sec_vol_id = self.vol_gateway.create_volume(sec_vol_spec)
        sec_vol_name = None
        # per UCA-2281
        if vol_info.label is not None and vol_info.label != "":
            sec_vol_name = vol_info.label
        else:
            sec_vol_name = f"{DEFAULT_NAME_PREFIX}-{vol_info.ldevId}"

        # the name change is done in the update_volume method
        logger.writeDebug("PROV:1221:sec_vol_name = {}", sec_vol_name)

        # sng20241127 - set svol label/name and set_alua_mode
        set_alua_mode = None
        if spec.set_alua_mode:
            set_alua_mode = spec.set_alua_mode

        try:
            logger.writeDebug("PROV:813:sec_vol_name = {}", sec_vol_name)
            logger.writeDebug("PROV:813:set_alua_mode = {}", set_alua_mode)
            self.vol_gateway.change_volume_settings(
                sec_vol_id, sec_vol_name, set_alua_mode
            )

            # verify the svol set label and set_alua_mode
            vol_info = self.vol_gateway.get_volume_by_id(sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol_id = {}", sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol = {}", vol_info)
            logger.writeDebug(
                "PROV:813:sec_vol isAluaEnabled= {}", vol_info.isAluaEnabled
            )

            logger.writeDebug(
                "PROV:813:sec_vol virtualLdevId= {}", vol_info.virtualLdevId
            )

            if (vol_info.virtualLdevId != 65535) and (vol_info.virtualLdevId != 65534):
                logger.writeDebug(
                    "PROV: = unassigning vldev for sec_vol_id : {} having vldev {}",
                    sec_vol_id,
                    vol_info.virtualLdevId,
                )
                self.vol_gateway.unassign_vldev(sec_vol_id, sec_vol_id)

            logger.writeDebug(
                "PROV:get_secondary_volume_id:sec_vol_id = {}", sec_vol_id
            )

            #  sng1104 - TODO enable_preferred_path goes here if needed?
            # hg_info = self.parse_hostgroup(host_group)
            # logger.writeDebug("PROV:get_secondary_volume_id:hg_info = {}", hg_info)

            #  sng1104 - on the 2nd storage, find the hg.RG, move lun to RG
            add_resource_spec = VSPResourceGroupSpec()
            add_resource_spec.ldevs = [int(sec_vol_id)]
            resourceGroupId = nvme_subsystem.resourceGroupId
            logger.writeDebug(
                "PROV:secondary_volume :vol_info.resourceGroupId = {}",
                vol_info.resourceGroupId,
            )
            logger.writeDebug(
                "PROV:get_secondary_volume_id:resourceGroupId = {}", resourceGroupId
            )
            if vol_info.resourceGroupId != resourceGroupId:
                self.rg_gateway.add_resource(resourceGroupId, add_resource_spec)

            # GAD reserved
            if vol_info.virtualLdevId != 65535:
                self.vol_gateway.assign_vldev(sec_vol_id, 65535)
            self.create_namespace_for_svol(
                nvme_subsystem.nvmSubsystemId, sec_vol_id, pvolNameSpaceId
            )
            # ns_id = ns_id.split(",")[-1]
            self.create_namespace_paths(
                nvme_subsystem.nvmSubsystemId,
                pvolNameSpaceId,
                spec.secondary_nvm_subsystem,
            )
        except Exception as ex:
            err_msg = GADFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
            logger.writeError(err_msg)
            # if setting the volume name fails, delete the secondary volume
            # if attaching the volume to the host group fails, delete the secondary volume
            self.delete_volume_when_nvme(
                sec_vol_id,
                nvme_subsystem.nvmSubsystemId,
                spec.secondary_nvm_subsystem,
                pvolNameSpaceId,
            )
            raise Exception(err_msg)
        return sec_vol_id

    @log_entry_exit
    def validate_virtual_ldev_id(self, vol_info):
        if vol_info.virtualLdevId == 65535 or vol_info.virtualLdevId == 65534:
            err_msg = VSPTrueCopyValidateMsg.PVOL_VLDEV_MISSING.value.format(
                vol_info.ldevId
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def get_secondary_volume_id_when_iscsi_target(self, vol_info, spec):
        logger.writeDebug("PROV:813:primary_volume = {}", vol_info)
        self.validate_virtual_ldev_id(vol_info)
        self.validate_for_iscsi(vol_info)

        # Fail early, save time
        # Before creating the secondary volume check if secondary hostgroup exists
        iscsi_targets = self.get_secondary_hostgroups(
            spec.secondary_iscsi_targets, True
        )
        if iscsi_targets is None and spec.provisioned_secondary_volume_id is None:
            err_msg = GADPairValidateMSG.NO_REMOTE_ISCSI_FOUND.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if spec.provisioned_secondary_volume_id:
            svol_id = spec.provisioned_secondary_volume_id
            sec_vol_info = self.vol_gateway.get_volume_by_id(svol_id)
            hgs_prov_svol = self.get_hgs_for_provisioned_svol(sec_vol_info)
            logger.writeDebug(
                "PROV:get_secondary_volume_id:hgs_prov_svol = {}", hgs_prov_svol
            )
            iscsi_targets = self.find_hgs_to_add_for_provisioned_svol(
                iscsi_targets, hgs_prov_svol
            )
            logger.writeDebug(
                "PROV:get_secondary_volume_id:host_groups = {}", iscsi_targets
            )
        else:
            svol_id = self.select_secondary_volume_id(vol_info.ldevId, spec)

        sec_vol_spec = self.construct_svol_spec(svol_id, vol_info, spec)

        sec_vol_name = None
        if spec.provisioned_secondary_volume_id:
            sec_vol_id = spec.provisioned_secondary_volume_id
        else:
            sec_vol_id = self.vol_gateway.create_volume(sec_vol_spec)
            # the name change is done in the update_volume method
            if vol_info.label is not None and vol_info.label != "":
                sec_vol_name = vol_info.label
            else:
                sec_vol_name = f"{DEFAULT_NAME_PREFIX}-{vol_info.ldevId}"

            logger.writeDebug("PROV:1221:sec_vol_name = {}", sec_vol_name)

        # sng20241127 - set svol label/name and set_alua_mode
        set_alua_mode = None
        if spec.set_alua_mode:
            set_alua_mode = spec.set_alua_mode

        if not spec.provisioned_secondary_volume_id:
            try:
                self.vol_gateway.change_volume_settings(
                    sec_vol_id, sec_vol_name, set_alua_mode
                )
            except Exception as ex:
                err_msg = GADFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
                logger.writeError(err_msg)
                # if setting the volume name fails, delete the secondary volume
                self.delete_volume(sec_vol_id)
                raise ValueError(err_msg)
        else:
            self.vol_gateway.change_volume_settings(sec_vol_id, None, set_alua_mode)

        try:
            # verify the svol set label and set_alua_mode
            vol_info = self.vol_gateway.get_volume_by_id(sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol_id = {}", sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol = {}", vol_info)
            logger.writeDebug(
                "PROV:813:sec_vol isAluaEnabled= {}", vol_info.isAluaEnabled
            )
            if vol_info.virtualLdevId is None:
                self.vol_gateway.unassign_vldev(sec_vol_id, sec_vol_id)
            elif vol_info.virtualLdevId != 65534 and vol_info.virtualLdevId != 65535:
                self.vol_gateway.unassign_vldev(sec_vol_id, vol_info.virtualLdevId)

            self.vol_gateway.unassign_vldev(sec_vol_id, sec_vol_id)
            logger.writeDebug(
                "PROV:get_secondary_volume_id:sec_vol_id = {}", sec_vol_id
            )
            logger.writeDebug(
                "PROV:get_secondary_volume_id:sec_vol_spec = {}", sec_vol_spec
            )

            if vol_info.resourceGroupId != 0:

                add_resource_spec = VSPResourceGroupSpec()
                add_resource_spec.ldevs = [int(sec_vol_id)]
                self.rg_gateway.remove_resource(
                    vol_info.resourceGroupId, add_resource_spec
                )
                # self.rg_gateway.add_resource(0, add_resource_spec)
            #  sng1104 - TODO enable_preferred_path goes here if needed?
            # hg_info = self.parse_hostgroup(host_group)
            # logger.writeDebug("PROV:get_secondary_volume_id:hg_info = {}", hg_info)

            #  sng1104 - on the 2nd storage, find the hg.RG, move lun to RG
            add_resource_spec = VSPResourceGroupSpec()
            add_resource_spec.ldevs = [int(sec_vol_id)]
            resourceGroupId = iscsi_targets[0].resourceGroupId
            logger.writeDebug(
                "PROV:get_secondary_volume_id:resourceGroupId = {}", resourceGroupId
            )

            self.rg_gateway.add_resource(resourceGroupId, add_resource_spec)

            # GAD reserved
            if vol_info.virtualLdevId != 65535:
                self.vol_gateway.assign_vldev(sec_vol_id, 65535)
            vol_info = self.vol_gateway.get_volume_by_id(sec_vol_id)
            logger.writeDebug("PROV:813:sec_vol_id 1397 = {}", sec_vol_id)

            if iscsi_targets is not None and len(iscsi_targets) > 0:
                lun_ids = self.find_lun_ids_from_spec(
                    iscsi_targets, spec.secondary_iscsi_targets, is_iscsi=True
                )
                self.add_luns_to_iscsi_targets(sec_vol_id, iscsi_targets, lun_ids)

        except Exception as ex:
            err_msg = GADFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
            logger.writeError(err_msg)
            if not spec.provisioned_secondary_volume_id:
                # if attaching the volume to the host group fails, delete the secondary volume
                try:
                    self.delete_volume(sec_vol_id)
                except Exception as e:
                    logger.writeError(err_msg)
            else:
                # if attaching the volume to the host group fails, detach them
                self.dettach_iscsi_targets(sec_vol_id, iscsi_targets)

            raise Exception(err_msg)
        return sec_vol_id

    @log_entry_exit
    def delete_volume_and_all_mappings(self, secondary_volume_id):
        logger.writeDebug(
            f"delete_svol_force: secondary_volume_id: {secondary_volume_id}"
        )
        volume = self.vol_gateway.get_volume_by_id(secondary_volume_id)
        if volume.namespaceId is not None:
            self.delete_volume_when_nvme(secondary_volume_id, None, None, None, volume)
        else:
            self.delete_volume(secondary_volume_id, volume)

    @log_entry_exit
    def move_volume_back_to_meta(self, volume_info):
        logger.writeDebug(f"move_volume_back_to_meta: volume_info: {volume_info}")
        if volume_info.virtualLdevId is None:
            self.vol_gateway.unassign_vldev(volume_info.ldevId, volume_info.ldevId)
        if volume_info.virtualLdevId == 65535 or volume_info.virtualLdevId == 65534:
            self.vol_gateway.unassign_vldev(
                volume_info.ldevId, volume_info.virtualLdevId
            )

        logger.writeDebug("PROV:move_volume_back_to_meta:sec_vol_id = {}", volume_info)

        if volume_info.resourceGroupId != 0:
            add_resource_spec = VSPResourceGroupSpec()
            add_resource_spec.ldevs = [int(volume_info.ldevId)]
            self.rg_gateway.remove_resource(
                volume_info.resourceGroupId, add_resource_spec
            )
        # assign back vldev
        self.vol_gateway.assign_vldev(volume_info.ldevId, volume_info.ldevId)
