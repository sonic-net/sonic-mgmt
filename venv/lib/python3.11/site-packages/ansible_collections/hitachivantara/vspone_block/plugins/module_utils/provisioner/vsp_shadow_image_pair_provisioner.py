import time

try:
    from ..common.ansible_common import (
        log_entry_exit,
        get_size_from_byte_format_capacity,
        dicts_to_dataclass_list,
    )
    from ..common.hv_constants import ConnectionTypes
    from ..common.hv_log import Log
    from ..common.vsp_constants import DEFAULT_NAME_PREFIX
    from ..model.vsp_shadow_image_pair_models import (
        VSPShadowImagePairsInfo,
        VSPShadowImagePairInfo,
    )
    from ..common.vsp_constants import VolumePayloadConst, PairStatus
    from .vsp_volume_prov import VSPVolumeProvisioner
    from .vsp_nvme_provisioner import VSPNvmeProvisioner
    from .vsp_host_group_provisioner import VSPHostGroupProvisioner
    from ..message.vsp_shadow_image_pair_msgs import VSPShadowImagePairValidateMsg
    from ..model.vsp_volume_models import CreateVolumeSpec, VSPVolumeInfo
    from ..model.vsp_host_group_models import VSPHostGroupInfo
    from ..message.vsp_lun_msgs import VSPVolValidationMsg
    from ..gateway.vsp_shadow_image_pair_gateway import VSPShadowImagePairDirectGateway

except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        get_size_from_byte_format_capacity,
        dicts_to_dataclass_list,
    )
    from common.hv_constants import ConnectionTypes
    from common.hv_log import Log
    from common.vsp_constants import DEFAULT_NAME_PREFIX
    from model.vsp_shadow_image_pair_models import (
        VSPShadowImagePairsInfo,
        VSPShadowImagePairInfo,
    )
    from .vsp_volume_prov import VSPVolumeProvisioner
    from .vsp_nvme_provisioner import VSPNvmeProvisioner
    from .vsp_host_group_provisioner import VSPHostGroupProvisioner
    from common.vsp_constants import VolumePayloadConst, PairStatus
    from message.vsp_shadow_image_pair_msgs import VSPShadowImagePairValidateMsg
    from model.vsp_volume_models import CreateVolumeSpec, VSPVolumeInfo
    from model.vsp_host_group_models import VSPHostGroupInfo
    from message.vsp_lun_msgs import VSPVolValidationMsg

logger = Log()


class VSPShadowImagePairProvisioner:

    def __init__(self, connection_info):

        self.gateway = VSPShadowImagePairDirectGateway(connection_info)
        self.connection_info = connection_info
        self.vol_provisioner = VSPVolumeProvisioner(connection_info)
        self.hg_prov = VSPHostGroupProvisioner(self.connection_info)
        self.nvme_provisioner = VSPNvmeProvisioner(self.connection_info)

    @log_entry_exit
    def get_all_shadow_image_pairs(self, serial, pvol, refresh=None):
        if pvol is not None:
            shadow_image_pairs = self.get_shadow_image_pair_by_pvol_and_svol(
                serial, pvol
            )
        else:
            shadow_image_pairs = self.gateway.get_all_shadow_image_pairs(
                serial, refresh
            )
            shadow_image_pairs = shadow_image_pairs.data_to_list()

        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            shadow_image_pairs = self.fill_additional_info_for_si_pairs(
                shadow_image_pairs
            )

        return shadow_image_pairs

    @log_entry_exit
    def host_group_for_ldev_id(self, ldev_id):
        volume = self.vol_provisioner.get_volume_by_ldev(ldev_id)
        logger.writeDebug(
            "PROV:20250324 volume = {}",
            volume,
        )

        if volume:
            return volume.ports

    @log_entry_exit
    def fill_host_group_info_for_one_si_pair(self, shadow_image_pair):
        logger.writeDebug(f"20250324 shadow_image_pair= {shadow_image_pair}")
        if isinstance(shadow_image_pair, dict):
            pvol = shadow_image_pair["primaryVolumeId"]
            svol = shadow_image_pair["secondaryVolumeId"]
            if pvol:
                shadow_image_pair["pvolHostGroups"] = self.host_group_for_ldev_id(pvol)
            if svol:
                shadow_image_pair["svolHostGroups"] = self.host_group_for_ldev_id(svol)
        else:
            pvol = shadow_image_pair.primaryVolumeId
            svol = shadow_image_pair.secondaryVolumeId
            if pvol:
                shadow_image_pair.pvolHostGroups = self.host_group_for_ldev_id(pvol)
            if svol:
                shadow_image_pair.svolHostGroups = self.host_group_for_ldev_id(svol)

        return shadow_image_pair

    @log_entry_exit
    def fill_additional_info_for_si_pairs(self, shadow_image_pairs):
        logger.writeDebug(f"20250324 shadow_image_pairs= {shadow_image_pairs}")
        new_shadow_image_pairs = []
        for si in shadow_image_pairs:
            new_si_pair = self.fill_nvm_subsystem_info_for_one_si_pair(si)
            new_si_pair = self.fill_host_group_info_for_one_si_pair(new_si_pair)
            new_shadow_image_pairs.append(new_si_pair)
        return new_shadow_image_pairs

    @log_entry_exit
    def fill_nvm_subsystem_info_for_one_si_pair(self, shadow_image_pair):
        logger.writeDebug(
            f"fill_nvm_subsystem_info_for_one_si_pair:shadow_image_pair= {shadow_image_pair}"
        )
        if isinstance(shadow_image_pair, dict):
            pvol = shadow_image_pair["primaryVolumeId"]
            svol = shadow_image_pair["secondaryVolumeId"]
            shadow_image_pair["pvolNvmSubsystemName"] = (
                self.nvm_subsystem_name_for_ldev_id(pvol)
            )
            shadow_image_pair["svolNvmSubsystemName"] = (
                self.nvm_subsystem_name_for_ldev_id(svol)
            )
        else:
            pvol = shadow_image_pair.primaryVolumeId
            svol = shadow_image_pair.secondaryVolumeId
            shadow_image_pair.pvolNvmSubsystemName = (
                self.nvm_subsystem_name_for_ldev_id(pvol)
            )
            shadow_image_pair.svolNvmSubsystemName = (
                self.nvm_subsystem_name_for_ldev_id(svol)
            )

        return shadow_image_pair

    @log_entry_exit
    def nvm_subsystem_name_for_ldev_id(self, ldev_id):
        volume = self.vol_provisioner.get_volume_by_ldev(ldev_id)
        if volume.nvmSubsystemId:
            nvm_subsystem_name = self.get_nvm_subsystem_name(volume)
            logger.writeDebug(
                "PROV:nvm_subsystem_name_for_ldev_id:nvm_subsystem_name = {}",
                nvm_subsystem_name,
            )
            return nvm_subsystem_name
        else:
            return None

    @log_entry_exit
    def get_nvm_subsystem_name(self, volume):
        nvm_provisioner = VSPNvmeProvisioner(self.connection_info)
        nvm_ss = nvm_provisioner.get_nvme_subsystem_by_id(volume.nvmSubsystemId)
        logger.writeDebug("PROV:get_nvm_subsystem_info:nvm_subsystem = {}", nvm_ss)

        return nvm_ss.nvmSubsystemName

    @log_entry_exit
    def create_secondary_volume(self, pvol, svol_pool_id, svol_id=None):
        sec_vol_spec = CreateVolumeSpec()
        sec_vol_spec.pool_id = svol_pool_id
        sec_vol_spec.size = get_size_from_byte_format_capacity(pvol.byteFormatCapacity)
        sec_vol_spec.capacity_saving = pvol.dataReductionMode
        if pvol.dataReductionMode != VolumePayloadConst.DISABLED:
            sec_vol_spec.is_compression_acceleration_enabled = (
                pvol.isCompressionAccelerationEnabled
            )
        if svol_id is not None:
            sec_vol_spec.ldev_id = svol_id
        if pvol.label is not None and pvol.label != "":
            sec_vol_name = pvol.label
        else:
            sec_vol_name = f"{DEFAULT_NAME_PREFIX}-{pvol.ldevId}"
        sec_vol_spec.name = sec_vol_name

        sec_vol_id = self.vol_provisioner.create_volume(sec_vol_spec)
        return sec_vol_id

    @log_entry_exit
    def create_shadow_image_pair(self, serial, createShadowImagePairSpec):

        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            #  20240820 for direct only
            pvol = self.vol_provisioner.get_volume_by_ldev(
                createShadowImagePairSpec.pvol
            )
            if pvol.emulationType == VolumePayloadConst.NOT_DEFINED:
                err_msg = VSPShadowImagePairValidateMsg.PVOL_NOT_FOUND.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)

            if createShadowImagePairSpec.svol is None:
                if createShadowImagePairSpec.secondary_pool_id is None:
                    err_msg = VSPShadowImagePairValidateMsg.SVOL_POOL_ID_NEEDED.value
                    raise ValueError(err_msg)
                svol_pool_id = createShadowImagePairSpec.secondary_pool_id
                svol_id = self.create_secondary_volume(pvol, svol_pool_id)
                createShadowImagePairSpec.svol = svol_id
                if pvol.nvmSubsystemId:
                    ns_id = self.create_name_space_for_svol(
                        pvol.nvmSubsystemId, svol_id
                    )

                if pvol.ports is not None and len(pvol.ports) > 0:
                    hg_info = pvol.ports[0]
                    hg = VSPHostGroupInfo(
                        port=hg_info["portId"], hostGroupId=hg_info["hostGroupNumber"]
                    )
                    self.hg_prov.add_luns_to_host_group(hg, luns=[svol_id])
                    svol = self.vol_provisioner.get_volume_by_ldev(svol_id)
                    if svol.ports:
                        hg_info = svol.ports[0]
            else:
                svol = self.vol_provisioner.get_volume_by_ldev(
                    createShadowImagePairSpec.svol
                )
                if svol.emulationType == VolumePayloadConst.NOT_DEFINED:
                    # err_msg = VSPShadowImagePairValidateMsg.SVOL_NOT_FOUND.value
                    # logger.writeError(err_msg)
                    # raise ValueError(err_msg)
                    if createShadowImagePairSpec.secondary_pool_id is None:
                        err_msg = (
                            VSPShadowImagePairValidateMsg.SVOL_POOL_ID_NEEDED.value
                        )
                        raise ValueError(err_msg)
                    svol_pool_id = createShadowImagePairSpec.secondary_pool_id
                    svol_id = self.create_secondary_volume(
                        pvol, svol_pool_id, createShadowImagePairSpec.svol
                    )
                    createShadowImagePairSpec.svol = svol_id
                    if pvol.nvmSubsystemId:
                        ns_id = self.create_name_space_for_svol(
                            pvol.nvmSubsystemId, svol_id
                        )

                    if pvol.ports is not None and len(pvol.ports) > 0:
                        hg_info = pvol.ports[0]
                        hg = VSPHostGroupInfo(
                            port=hg_info["portId"],
                            hostGroupId=hg_info["hostGroupNumber"],
                        )
                        self.hg_prov.add_luns_to_host_group(hg, luns=[svol_id])
                        svol = self.vol_provisioner.get_volume_by_ldev(svol_id)
                        if svol.ports:
                            hg_info = svol.ports[0]
                elif pvol.byteFormatCapacity != svol.byteFormatCapacity:
                    err_msg = (
                        VSPShadowImagePairValidateMsg.PVOL_SVOL_SIZE_MISMATCH.value
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
            logger.writeDebug(
                f"PV:create_shadow_image_pair:spec= {createShadowImagePairSpec}"
            )
            if createShadowImagePairSpec.is_data_reduction_force_copy is None:
                createShadowImagePairSpec.is_data_reduction_force_copy = (
                    True
                    if pvol.dataReductionMode
                    and pvol.dataReductionMode != VolumePayloadConst.DISABLED
                    else False
                )

        pairId = self.gateway.create_shadow_image_pair(
            serial, createShadowImagePairSpec
        )
        time.sleep(20)
        shadow_image_pair = self.gateway.get_shadow_image_pair_by_id(serial, pairId)
        shadow_image_pair = self.fill_nvm_subsystem_info_for_one_si_pair(
            shadow_image_pair
        )
        shadow_image_pair = self.fill_host_group_info_for_one_si_pair(shadow_image_pair)
        logger.writeDebug(
            "PROV::shadow_image_pair = {} type = {}",
            shadow_image_pair,
            type(shadow_image_pair),
        )
        if isinstance(shadow_image_pair, dict):
            return shadow_image_pair
        return shadow_image_pair.to_dict()

    @log_entry_exit
    def create_name_space_for_svol(self, nvm_subsystem_id, ldev_id):
        nvm_provisioner = VSPNvmeProvisioner(self.connection_info)
        return nvm_provisioner.create_namespace(nvm_subsystem_id, ldev_id)

    @log_entry_exit
    def get_shadow_image_pair_by_id(self, serial, pairId):

        return self.gateway.get_shadow_image_pair_by_id(serial, pairId)

    @log_entry_exit
    def get_shadow_image_pair_by_pvol_and_svol(self, serial, pvol, svol=None):
        shadow_image_pairs = None
        if pvol is None:
            shadow_image_pairs = self.gateway.get_all_shadow_image_pairs(serial)
        else:
            shadow_image_pairs = self.gateway.get_shadow_image_pair_by_pvol(
                serial, pvol
            )
        shadow_image_list = []
        shadow_image_pair = None
        for sip in shadow_image_pairs.data_to_list():
            if sip.get("primaryVolumeId") == pvol:
                shadow_image_list.append(sip)
            if svol is not None:
                if sip.get("secondaryVolumeId") == svol:
                    shadow_image_pair = sip
                    return shadow_image_pair

        if svol is not None:
            return None

        data = VSPShadowImagePairsInfo(
            dicts_to_dataclass_list(shadow_image_list, VSPShadowImagePairInfo)
        )
        return data.data_to_list()

    @log_entry_exit
    def get_shadow_image_pair_by_copy_pair_name(
        self, serial, copy_pair_name, copy_group_name
    ):
        shadow_image_pairs = None

        shadow_image_pairs = self.gateway.get_all_shadow_image_pairs(serial)

        shadow_image_list = []
        shadow_image_pair = None
        for sip in shadow_image_pairs.data_to_list():
            if sip.get("copyGroupName") == copy_group_name:
                shadow_image_list.append(sip)
            if copy_pair_name is not None:
                if sip.get("copyPairName") == copy_pair_name:
                    shadow_image_pair = sip
                    return shadow_image_pair

        if copy_pair_name is not None:
            if len(shadow_image_list) > 0:
                return shadow_image_list[0]
            else:
                return None

        data = VSPShadowImagePairsInfo(
            dicts_to_dataclass_list(shadow_image_list, VSPShadowImagePairInfo)
        )
        return data.data_to_list()

    @log_entry_exit
    def get_specific_cg_pair_by_pvol_svol(
        self,
        pvol,
        svol=None,
        cg_name=None,
        cp_name=None,
        pm_device_grp_name=None,
        sec_device_grp_name=None,
    ):

        return self.gateway.get_specific_cg_pair_by_pvol_svol(
            pvol, svol, cg_name, cp_name, pm_device_grp_name, sec_device_grp_name
        )

    @log_entry_exit
    def split_shadow_image_pair(self, serial, updateShadowImagePairSpec):
        unused = self.gateway.split_shadow_image_pair(serial, updateShadowImagePairSpec)
        return self.get_si_pair_with_latest_data(
            serial, updateShadowImagePairSpec.pair_id, PairStatus.PSUS
        )

    @log_entry_exit
    def resync_shadow_image_pair(self, serial, updateShadowImagePairSpec):
        unused = self.gateway.resync_shadow_image_pair(
            serial, updateShadowImagePairSpec
        )
        return self.get_si_pair_with_latest_data(
            serial, updateShadowImagePairSpec.pair_id, PairStatus.PAIR
        )

    @log_entry_exit
    def restore_shadow_image_pair(self, serial, updateShadowImagePairSpec):
        unused = self.gateway.restore_shadow_image_pair(
            serial, updateShadowImagePairSpec
        )

        return self.get_si_pair_with_latest_data(
            serial, updateShadowImagePairSpec.pair_id, PairStatus.PAIR
        )

    @log_entry_exit
    def migrate_shadow_image_pair(self, serial, updateShadowImagePairSpec):
        unused = self.gateway.migrate_shadow_image_pair(
            serial, updateShadowImagePairSpec
        )
        return self.get_si_pair_with_latest_data(
            serial, updateShadowImagePairSpec.pair_id, PairStatus.PSUS
        )

    @log_entry_exit
    def get_si_pair_with_latest_data(self, serial, pair_id, type):
        pair = None
        count = 0

        while count < 10:
            pair = self.gateway.get_shadow_image_pair_by_id(serial, pair_id)

            if (
                isinstance(pair, dict)
                and pair.get("status") == type
                or pair.status == type
            ):
                return pair.to_dict()
            time.sleep(10)
            count += 1
        return pair

    @log_entry_exit
    def delete_shadow_image_pair(self, serial, deleteShadowImagePairSpec):
        logger.writeDebug(
            "PROV:20250324 deleteShadowImagePairSpec = {}", deleteShadowImagePairSpec
        )
        unused = self.gateway.delete_shadow_image_pair(
            serial, deleteShadowImagePairSpec
        )
        if deleteShadowImagePairSpec.should_delete_svol:
            secondary_volume_id = deleteShadowImagePairSpec.secondary_volume_id
            self.delete_svol_force(secondary_volume_id)
        return "Shadow image pair is deleted."

    @log_entry_exit
    def delete_svol_force(self, secondary_volume_id):
        logger.writeDebug(f"20250324 secondary_volume_id: {secondary_volume_id}")
        if secondary_volume_id is None:
            return
        volume = self.vol_provisioner.get_volume_by_ldev(secondary_volume_id)
        ports = volume.ports
        if ports:
            for port in ports:
                # unpresent the svol from the host group
                self.vol_provisioner.delete_lun_path(port)
        self.delete_host_ns_path_for_ldev(volume.ldevId)
        self.delete_ldev_from_nvme_subsystem(volume.ldevId)
        self.delete_volume(volume)

    @log_entry_exit
    def delete_volume(self, volume: VSPVolumeInfo):
        ldev_id = volume.ldevId

        force_execute = (
            True
            if volume.dataReductionMode
            and volume.dataReductionMode.lower() != VolumePayloadConst.DISABLED
            else None
        )
        try:
            self.vol_provisioner.delete_volume(ldev_id, force_execute)
            self.connection_info.changed = True
        except Exception as e:
            logger.writeError(f"An error occurred in delete_volume: {str(e)}")
            raise ValueError(VSPVolValidationMsg.VOLUME_HAS_PATH.value)

    @log_entry_exit
    def delete_host_ns_path_for_ldev(self, ldev_id):
        try:
            nvms = self.nvme_provisioner.get_nvme_subsystems_by_namespace()

            for nvm in nvms.data:
                ldev_paths = self.find_ldevs_in_paths(nvm.nvmSubsystemId, ldev_id)
                if ldev_paths and len(ldev_paths) > 0:
                    # self.nvme_provisioner.delete_host_namespace_path(ldev_found.nvmSubsystemId, ldev_found.hostNqn, int(ldev_found.namespaceId))
                    for x in ldev_paths:
                        self.nvme_provisioner.delete_host_namespace_path_by_id(
                            x.namespacePathId
                        )
        except Exception as e:
            if "The API is not supported for the specified storage system" in str(e):
                logger.writeError(
                    "The API is not supported for the specified storage system"
                )
            else:
                raise e

    @log_entry_exit
    def find_ldevs_in_paths(self, nvm_subsystem_id, ldev_id):
        ldevs = []
        paths = self.nvme_provisioner.get_namespace_paths(nvm_subsystem_id)
        for path in paths.data:
            logger.writeDebug(
                f"RC:find_ldevs_in_paths:path.ldevId={path.ldevId} ldev_id={ldev_id}"
            )
            if str(path.ldevId) == str(ldev_id):
                ldevs.append(path)
        return ldevs

    @log_entry_exit
    def delete_ldev_from_nvme_subsystem(self, ldev_id):
        try:
            nvms = self.nvme_provisioner.get_nvme_subsystems_by_namespace()

            for nvm in nvms.data:
                ldevs = self.find_ldevs_in_nvm_subsystem(nvm.nvmSubsystemId, ldev_id)
                if ldevs and len(ldevs) > 0:
                    for x in ldevs:
                        self.nvme_provisioner.delete_namespace(
                            x.nvmSubsystemId, x.namespaceId
                        )
        except Exception as e:
            if "The API is not supported for the specified storage system" in str(e):
                logger.writeError(
                    "The API is not supported for the specified storage system"
                )
            else:
                raise e

    @log_entry_exit
    def find_ldevs_in_nvm_subsystem(self, nvm_subsystem_id, ldev_id):
        ldevs = []
        namespaces = self.nvme_provisioner.get_namespaces(nvm_subsystem_id)
        for ns in namespaces.data:
            if ns.ldevId == ldev_id:
                ldevs.append(ns)
        return ldevs

    @log_entry_exit
    def delete_svol_force_2(self, secondary_volume_id):
        logger.writeDebug(f"20250324 secondary_volume_id: {secondary_volume_id}")
        # unpresent the svol from the host group
        svol = self.vol_provisioner.get_volume_by_ldev(secondary_volume_id)
        if svol.ports is not None and len(svol.ports) > 0:
            hg_provisioner = VSPHostGroupProvisioner(self.connection_info)
            for hg_info in svol.ports:
                hg = hg_provisioner.get_one_host_group(
                    hg_info["portId"], hg_info["hostGroupName"]
                ).data
                logger.writeDebug(f"20250324 hg_info: {hg_info}")
                logger.writeDebug(f"20250324 hg: {hg}")
                hg_provisioner.delete_luns_from_host_group(
                    hg, luns=[secondary_volume_id]
                )
        # delete the svol
        self.vol_provisioner.delete_volume(secondary_volume_id, False)
