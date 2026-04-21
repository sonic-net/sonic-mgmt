import time

try:
    from ..common.ansible_common import (
        convert_block_capacity,
        log_entry_exit,
        camel_to_snake_case,
        snake_to_camel_case,
        get_response_key,
        get_default_value,
        volume_id_to_hex_format,
        convert_decimal_size_to_bytes,
        convert_to_mb,
    )
    from ..common.uaig_utils import camel_to_snake_case_dict
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..common.vsp_constants import VolumePayloadConst, DEFAULT_NAME_PREFIX
    from ..model.common_base_models import ConnectionInfo
    from ..model.vsp_volume_models import (
        CreateVolumeSpec,
        VolumeFactSpec,
        VSPVolumeInfo,
        VSPVolumesInfo,
        VSPVolumeSnapshotInfo,
        VSPVolumePortInfo,
        VSPVolumeNvmSubsystenInfo,
    )
    from ..provisioner.vsp_volume_prov import VSPVolumeProvisioner
    from ..provisioner.vsp_nvme_provisioner import VSPNvmeProvisioner
    from ..provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from ..provisioner.vsp_snapshot_provisioner import VSPHtiSnapshotProvisioner
    from ..message.vsp_lun_msgs import VSPVolValidationMsg
    from ..provisioner.vsp_host_group_provisioner import VSPHostGroupProvisioner
except ImportError:
    from common.ansible_common import (
        convert_block_capacity,
        log_entry_exit,
        camel_to_snake_case,
        snake_to_camel_case,
        get_response_key,
        get_default_value,
        volume_id_to_hex_format,
        convert_decimal_size_to_bytes,
        convert_to_mb,
    )
    from common.uaig_utils import camel_to_snake_case_dict
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from common.vsp_constants import VolumePayloadConst, DEFAULT_NAME_PREFIX
    from model.common_base_models import ConnectionInfo
    from model.vsp_volume_models import (
        CreateVolumeSpec,
        VolumeFactSpec,
        VSPVolumeInfo,
        VSPVolumesInfo,
        VSPVolumeSnapshotInfo,
        VSPVolumePortInfo,
        VSPVolumeNvmSubsystenInfo,
    )
    from provisioner.vsp_volume_prov import VSPVolumeProvisioner
    from provisioner.vsp_nvme_provisioner import VSPNvmeProvisioner
    from provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from provisioner.vsp_snapshot_provisioner import VSPHtiSnapshotProvisioner
    from message.vsp_lun_msgs import VSPVolValidationMsg
    from provisioner.vsp_host_group_provisioner import VSPHostGroupProvisioner


logger = Log()


class VSPVolumeSubstates:
    """
    Enum class for VSP Volume Substates
    """

    ADD_HOST_NQN = "add_host_nqn"
    REMOVE_HOST_NQN = "remove_host_nqn"


class VSPVolumeReconciler:
    """_summary_"""

    def __init__(self, connection_info: ConnectionInfo, serial: str):
        self.connection_info = connection_info
        self.serial = serial
        self.provisioner = VSPVolumeProvisioner(self.connection_info)
        self.port_prov = VSPStoragePortProvisioner(self.connection_info)
        self.nvme_provisioner = VSPNvmeProvisioner(self.connection_info, self.serial)
        self.hg_prov = VSPHostGroupProvisioner(self.connection_info)
        self.snapshots = None

    @log_entry_exit
    def volume_reconcile(self, state: str, spec: CreateVolumeSpec):
        """Reconciler for volume management"""

        if state == StateValue.PRESENT:

            if (
                spec.ldev_id is None
                and spec.name is None
                and spec.nvm_subsystem_name
                and spec.state is not None
                and spec.state == VSPVolumeSubstates.REMOVE_HOST_NQN
            ):
                # ldev_id and name not present in the spec, but nvm_subsystem_name present
                self.update_nvm_subsystem(spec)
                return "NVM subsystem updated successfully."

            volume = None
            new_vol = False
            if spec.ldev_id:
                volume = self.provisioner.get_volume_by_ldev(spec.ldev_id)
                logger.writeDebug("RC:sng20241205 volume={}", volume)

            if not volume or volume.emulationType == VolumePayloadConst.NOT_DEFINED:
                spec.ldev_id = self.create_volume(spec)
                if spec.name:
                    self.update_volume_name(spec.ldev_id, spec.name)
                else:
                    self.update_volume_name(spec.ldev_id, None)

                volume = self.provisioner.get_volume_by_ldev(spec.ldev_id)
                new_vol = True

            self.update_volume(volume, spec, new_vol)

            # Check if the ldev is a command device
            if volume.attributes and "CMD" in volume.attributes:
                self.provisioner.fill_cmd_device_info(volume)

            additional_change = False
            if spec.should_shred_volume_enable:
                unused = self.provisioner.shredding_volume(
                    spec.ldev_id, spec.should_shred_volume_enable
                )
                logger.writeInfo("RC:volume_reconcile:shredding_volume finished")

            if spec.qos_settings:
                self.provisioner.change_qos_settings(spec.ldev_id, spec.qos_settings)
                logger.writeInfo("RC:volume_reconcile:qos_settings finished")
                self.connection_info.changed = True
                additional_change = True

            if spec.mp_blade_id is not None and spec.mp_blade_id != volume.mpBladeId:
                self.provisioner.change_mp_blade(spec.ldev_id, spec.mp_blade_id)
                self.connection_info.changed = True
                additional_change = True

            if spec.clpr_id is not None and spec.clpr_id != volume.clprId:
                self.provisioner.assign_ldev_to_clpr(spec.ldev_id, spec.clpr_id)
                self.connection_info.changed = True
                additional_change = True

            if spec.should_reclaim_zero_pages:
                self.provisioner.reclaim_zero_pages(spec.ldev_id)
                logger.writeInfo("RC:volume_reconcile:reclaim_zero_pages finished")
                self.connection_info.changed = True
                additional_change = True

            # Keep this logic always at the end of the volume creation
            if spec.should_format_volume:
                if volume.status.upper() != VolumePayloadConst.BLOCK:
                    logger.writeDebug(
                        "RC:volume_reconcile:formatting volume as it is not in BLOCK state"
                    )
                    self.provisioner.change_volume_status(spec.ldev_id, True)

                force_format = (
                    True
                    if volume.dataReductionMode
                    and volume.dataReductionMode.lower() != VolumePayloadConst.DISABLED
                    else False
                )
                try:
                    self.provisioner.format_volume(
                        spec.ldev_id,
                        force_format=force_format,
                        format_type=spec.format_type,
                    )
                except Exception as e:
                    if "Timeout Error!" in str(e):
                        spec.is_task_timeout = True
                    else:
                        self.provisioner.change_volume_status(spec.ldev_id, False)
                        raise e

                logger.writeInfo("RC:volume_reconcile:format volume finished")
                self.connection_info.changed = True

            if additional_change:
                volume = self.provisioner.get_volume_by_ldev(spec.ldev_id)

            if new_vol:
                if spec and hasattr(spec, "comment") is not None:
                    spec.comment = "Volume created successfully."
            create_qos_settings = True if spec.qos_settings else False
            return self.get_volume_detail_info(
                volume, create_qos_setting=create_qos_settings
            )

        elif state == StateValue.ASSIGN_VIRTUAL_LDEV:
            if spec.ldev_id is None and spec.vldev_id is None:
                raise ValueError(VSPVolValidationMsg.BOTH_LDEV_VLDEV_ID_REQD.value)
            volume = self.provisioner.get_volume_by_ldev(spec.ldev_id)
            logger.writeDebug("RC:volume_reconcile:state=absent:volume={}", volume)
            changed = self.provisioner.change_volume_settings_vldev(spec, volume)
            self.connection_info.changed = changed
            return self.get_volume_detail_info(volume)

        elif state == StateValue.ABSENT:
            volume = self.provisioner.get_volume_by_ldev(spec.ldev_id)
            logger.writeDebug("RC:volume_reconcile:state=absent:volume={}", volume)
            if not volume or volume.emulationType == VolumePayloadConst.NOT_DEFINED:
                return None
            if spec.force is not None and spec.force is True:
                self.delete_volume_force(volume)
            else:
                if volume.numOfPorts and volume.numOfPorts > 0:
                    raise ValueError(VSPVolValidationMsg.PATH_EXIST.value)
                if spec.should_shred_volume_enable:
                    unused = self.provisioner.shredding_volume(
                        spec.ldev_id, spec.should_shred_volume_enable
                    )
                    logger.writeInfo("RC:volume_reconcile:shredding_volume finished")
                self.delete_volume(volume)

    @log_entry_exit
    def update_nvm_subsystem(self, spec):
        found = self.does_nvme_subsystem_exist(spec.nvm_subsystem_name)
        if not found:
            raise ValueError(
                VSPVolValidationMsg.NVM_SUBSYSTEM_DOES_NOT_EXIST.value.format(
                    spec.nvm_subsystem_name
                )
            )
        else:
            logger.writeDebug("RC:process_update_nvme:nvm_system={}", found)
            self.process_update_nvme(found, spec)

    @log_entry_exit
    def update_volume(
        self, volume_data: VSPVolumeInfo, spec: CreateVolumeSpec, new_vol: bool
    ):

        if new_vol:
            spec.name = None
            spec.capacity_saving = None
        # sng20241205 VLDEVID_META_RSRC
        logger.writeDebug("RC: sng20241205 volume_data={}", volume_data)
        logger.writeDebug("RC: sng20241205 spec.vldev_id={}", spec.vldev_id)
        # if spec.vldev_id and volume_data.resourceGroupId == 0:
        #     raise ValueError(VSPVolValidationMsg.VLDEVID_META_RSRC.value)
        if volume_data.parityGroupIds and spec.tiering_policy:
            raise ValueError(VSPVolValidationMsg.BOTH_PARITY_GRP_TIERING.value)

        self.validate_tiering_policy(spec)

        found = False
        if spec.nvm_subsystem_name:
            found = self.does_nvme_subsystem_exist(spec.nvm_subsystem_name)
            if not found:
                raise ValueError(
                    VSPVolValidationMsg.NVM_SUBSYSTEM_DOES_NOT_EXIST.value.format(
                        spec.nvm_subsystem_name
                    )
                )
            else:
                logger.writeDebug("RC:process_update_nvme:nvm_system={}", found)

        # Expand the size if its required
        if spec.size:
            # if "." in spec.size:
            #     raise ValueError(VSPVolValidationMsg.SIZE_INT_REQUIRED.value)

            # size_in_bytes = convert_to_bytes(spec.size)
            size_in_bytes = convert_decimal_size_to_bytes(spec.size)
            expand_val = size_in_bytes - (
                volume_data.blockCapacity if volume_data.blockCapacity else 0
            )
            if expand_val > 0:
                enhanced_expansion = (
                    True
                    if volume_data.isDataReductionShareEnabled is not None
                    else False
                )
                self.provisioner.expand_volume_capacity(
                    volume_data.ldevId, expand_val, enhanced_expansion
                )
                self.connection_info.changed = True
            elif expand_val < 0:
                raise ValueError(VSPVolValidationMsg.VALID_SIZE.value)
        if (
            spec.capacity_saving is not None
            and spec.capacity_saving == volume_data.dataReductionMode
        ):
            spec.capacity_saving = None
        if spec.name is not None and spec.name == volume_data.label:
            spec.name = None

        # update the volume by comparing the existing details
        if (
            (spec.capacity_saving is not None)
            or (spec.name is not None)
            or spec.is_alua_enabled is not None
            or spec.is_relocation_enabled is not None
            or spec.data_reduction_process_mode is not None
            or spec.is_compression_acceleration_enabled is not None
            or spec.is_full_allocation_enabled is not None
        ):
            self.provisioner.change_volume_settings(
                volume_data.ldevId, spec.name, spec.capacity_saving, spec
            )

        # sng20241202 update change_volume_settings_tier
        self.provisioner.change_volume_settings_tier(spec, volume_data.ldevId)
        changed = self.provisioner.change_volume_settings_vldev(spec, volume_data)
        if changed:
            self.connection_info.changed = True

        if found:
            self.process_update_nvme(found, spec)
        logger.writeDebug("RC:update_volume:changed={}", self.connection_info.changed)
        return volume_data.ldevId

    @log_entry_exit
    def does_nvme_subsystem_exist(self, nvm_subsystem_name):
        ret_value = self.nvme_provisioner.get_nvme_subsystem_by_name(nvm_subsystem_name)
        if ret_value:
            return ret_value
        else:
            return False

    @log_entry_exit
    def process_create_nvme(self, nvme_subsystem, spec):
        # if spec.state is None or empty during create, we will try to
        # add host NQNs, based on the information provided in the spec.
        if (
            spec.state is None
            or spec.state == ""
            or spec.state.lower() == VSPVolumeSubstates.ADD_HOST_NQN
        ):
            if spec.host_nqns is not None and len(spec.host_nqns) > 0:
                logger.writeDebug("RC:host_nqns={}", spec.host_nqns)
                host_nqns_to_register = self.get_host_nqns_to_register(
                    nvme_subsystem.nvmSubsystemId, spec.host_nqns
                )
                logger.writeDebug("RC:host_nqns_to_register={}", host_nqns_to_register)
                self.register_host_nqns(
                    nvme_subsystem.nvmSubsystemId, host_nqns_to_register
                )
                ldev_found = self.is_ldev_present(
                    nvme_subsystem.nvmSubsystemId, spec.ldev_id
                )
                logger.writeDebug("RC:process_create_nvme={}", ldev_found)
                if not ldev_found:
                    # add ldev to the nvme name space
                    object_id = self.create_namespace_for_ldev(
                        nvme_subsystem.nvmSubsystemId, spec.ldev_id
                    )
                    namespace_id = object_id.split(",")[-1]
                    logger.writeDebug("RC:namespace_id={}", namespace_id)
                else:
                    namespace_id = ldev_found.namespaceId
                    logger.writeDebug("RC:ldev_found={}", ldev_found)

                self.set_host_namespace_paths(
                    nvme_subsystem.nvmSubsystemId, spec.host_nqns, namespace_id
                )
            else:
                ldev_found = self.is_ldev_present(
                    nvme_subsystem.nvmSubsystemId, spec.ldev_id
                )
                logger.writeDebug("RC:process_create_nvme={}", ldev_found)
                if not ldev_found:
                    # add ldev to the nvme name space
                    object_id = self.create_namespace_for_ldev(
                        nvme_subsystem.nvmSubsystemId, spec.ldev_id
                    )
                    namespace_id = object_id.split(",")[-1]
                    logger.writeDebug("RC:namespace_id={}", namespace_id)
                else:
                    namespace_id = ldev_found.namespaceId
                    logger.writeDebug("RC:ldev_found={}", ldev_found)

    @log_entry_exit
    def set_host_namespace_paths(self, nvme_subsystem_id, hpst_nqns, namespace_id):
        for h in hpst_nqns:
            try:
                self.nvme_provisioner.set_host_namespace_path(
                    nvme_subsystem_id, h, namespace_id
                )
                self.connection_info.changed = True
            except Exception as e:
                logger.writeException(e)
                logger.writeDebug(
                    "RC:set_host_namespace_paths:nvme_subsystem_id={} host_nqn = {} namespace_id = {}",
                    nvme_subsystem_id,
                    h,
                    namespace_id,
                )

    @log_entry_exit
    def create_namespace_for_ldev(self, nvme_subsystem_id, ldev_id):
        ret_value = self.nvme_provisioner.create_namespace(nvme_subsystem_id, ldev_id)
        self.connection_info.changed = True
        logger.writeDebug("RC:create_namespace_for_ldev={}", ret_value)

        return ret_value

    @log_entry_exit
    def is_ldev_present(self, nvme_subsystem_id, ldev_id):
        ret_list = self.nvme_provisioner.get_namespaces(nvme_subsystem_id)
        logger.writeDebug("RC:is_ldev_present={}", ret_list)
        for x in ret_list.data:
            if str(x.ldevId) == str(ldev_id):
                return x
        return False

    @log_entry_exit
    def register_host_nqns(self, nvme_subsystem_id, host_nqns):
        logger.writeDebug("RC:register_host_nqns={}", host_nqns)
        for x in host_nqns:
            self.nvme_provisioner.register_host_nqn(nvme_subsystem_id, x)
            self.connection_info.changed = True

    @log_entry_exit
    def get_host_nqns_to_register(self, nvme_subsystem_id, host_nqns):
        ret_list = self.nvme_provisioner.get_host_nqns(nvme_subsystem_id)
        host_nqn_dict = {}
        for host_nqn in ret_list.data:
            host_nqn_dict[host_nqn.hostNqn] = host_nqn

        result_list = []
        for x in host_nqns:
            if host_nqn_dict.get(x) is None:
                result_list.append(x)

        return result_list

    @log_entry_exit
    def process_update_nvme(self, nvme_subsystem, spec):

        # During update if spec.state is None, we just return
        if spec.state is None:
            return

        if spec.state.lower() == VSPVolumeSubstates.REMOVE_HOST_NQN:
            if spec.ldev_id is None:
                self.process_remove_host_nqns(nvme_subsystem, spec.host_nqns)
            else:
                self.remove_hqn_from_exiting_vol(
                    nvme_subsystem, spec.host_nqns, spec.ldev_id
                )
        elif spec.state.lower() == VSPVolumeSubstates.ADD_HOST_NQN:
            if spec.ldev_id is None:
                return
            else:
                self.process_add_host_nqns(nvme_subsystem, spec.host_nqns, spec.ldev_id)
        else:
            return

    @log_entry_exit
    def process_add_host_nqns(self, nvme_subsystem, host_nqns, ldev_id):
        logger.writeDebug("RC:process_add_host_nqns:nvme_system={}", nvme_subsystem)
        if host_nqns is not None and len(host_nqns) > 0:
            host_nqns_to_register = self.get_host_nqns_to_register(
                nvme_subsystem.nvmSubsystemId, host_nqns
            )
            logger.writeDebug(
                "RC:process_add_host_nqns:host_nqns_to_register={}",
                host_nqns_to_register,
            )
            self.register_host_nqns(
                nvme_subsystem.nvmSubsystemId, host_nqns_to_register
            )
            ldev_found = self.is_ldev_present(nvme_subsystem.nvmSubsystemId, ldev_id)
            logger.writeDebug(
                "RC:process_add_host_nqns:ldev_found={} ldev_id = {} ldev type = {}",
                ldev_found,
                ldev_id,
                type(ldev_id),
            )
            if not ldev_found:
                # add ldev to the nvme name space
                object_id = self.create_namespace_for_ldev(
                    nvme_subsystem.nvmSubsystemId, ldev_id
                )
                namespace_id = object_id.split(",")[-1]
                logger.writeDebug("RC:namespace_id={}", namespace_id)
            else:
                namespace_id = ldev_found.namespaceId
                logger.writeDebug("RC:ldev_found={}", ldev_found)

            self.set_host_namespace_paths(
                nvme_subsystem.nvmSubsystemId, host_nqns, namespace_id
            )
        else:
            # If host_nqns is empty just create the namespace for ldev_id
            ldev_found = self.is_ldev_present(nvme_subsystem.nvmSubsystemId, ldev_id)
            logger.writeDebug("RC:process_create_nvme={}", ldev_found)
            if not ldev_found:
                # add ldev to the nvme name space
                object_id = self.create_namespace_for_ldev(
                    nvme_subsystem.nvmSubsystemId, ldev_id
                )
                namespace_id = object_id.split(",")[-1]
                logger.writeDebug("RC:namespace_id={}", namespace_id)
            else:
                namespace_id = ldev_found.namespaceId
                logger.writeDebug("RC:ldev_found={}", ldev_found)

    @log_entry_exit
    def remove_hqn_from_nvm_subsystem(self, nvm, host_nqn):
        host_nqns = self.find_host_nqn_in_nvm_subsystem(nvm.nvmSubsystemId, host_nqn)
        if host_nqns and len(host_nqns) > 0:
            for x in host_nqns:
                self.nvme_provisioner.delete_host_nqn_by_id(x.hostNqnId)

    @log_entry_exit
    def remove_hqn_from_exiting_vol(self, nvme_subsystem, host_nqns, ldev_id):
        logger.writeDebug(
            "RC:remove_hqn_from_exiting_vol:nvme_system={}", nvme_subsystem
        )
        ldev_found = self.is_ldev_present(nvme_subsystem.nvmSubsystemId, ldev_id)
        if not ldev_found:
            raise ValueError(
                VSPVolValidationMsg.LDEV_NOT_FOUND_IN_NVM.value.format(
                    ldev_id, nvme_subsystem.nvmSubsystemName
                )
            )
        else:
            host_nqns_to_remove = self.get_host_nqns_to_remove(
                nvme_subsystem.nvmSubsystemId, host_nqns
            )
            logger.writeDebug(
                "RC:remove_hqn_from_exiting_vol:host_nqns_to_remove={}",
                host_nqns_to_remove,
            )
            ldev_paths = self.find_ldevs_in_paths(
                nvme_subsystem.nvmSubsystemId, ldev_id
            )
            logger.writeDebug(
                "RC:remove_hqn_from_exiting_vol:ldev_paths={}", ldev_paths
            )
            if ldev_paths and len(ldev_paths) > 0:
                for x in ldev_paths:
                    logger.writeDebug("RC:remove_hqn_from_exiting_vol:x={}", x)
                    if x.hostNqn in host_nqns_to_remove:
                        self.nvme_provisioner.delete_host_namespace_path_by_id(
                            x.namespacePathId
                        )
                        logger.writeDebug("RC:remove_hqn_from_exiting_vol:x={}", x)
                        paths = self.find_host_nqn_in_paths(
                            nvme_subsystem.nvmSubsystemId, x.hostNqn
                        )
                        logger.writeDebug(
                            "RC:remove_hqn_from_exiting_vol:paths={}", paths
                        )
                        if len(paths) == 0:
                            logger.writeDebug(
                                "RC:remove_hqn_from_exiting_vol:remove_hqn_from_nvm_subsystem"
                            )
                            self.remove_hqn_from_nvm_subsystem(
                                nvme_subsystem, x.hostNqn
                            )

    @log_entry_exit
    def process_remove_host_nqns(self, nvme_subsystem, host_nqns):

        host_nqns_to_remove = self.get_host_nqns_to_remove(
            nvme_subsystem.nvmSubsystemId, host_nqns
        )
        logger.writeDebug(
            "RC:process_remove_host_nqn:host_nqns_to_remove={}", host_nqns_to_remove
        )
        if len(host_nqns_to_remove) > 0:
            self.delete_host_nqns_from_nvme_subsystem(host_nqns_to_remove)
            self.connection_info.changed = True

    @log_entry_exit
    def get_host_nqns_to_remove(self, nvme_subsystem_id, host_nqns):
        ret_list = self.nvme_provisioner.get_host_nqns(nvme_subsystem_id)
        host_nqn_dict = {}
        for host_nqn in ret_list.data:
            host_nqn_dict[host_nqn.hostNqn] = host_nqn

        result_list = []
        for x in host_nqns:
            if host_nqn_dict.get(x):
                result_list.append(x)

        return result_list

    # sng20241202 validate_tiering_policy
    def validate_tiering_policy(self, spec):

        tier_level_for_new_page_allocation = spec.tier_level_for_new_page_allocation
        if tier_level_for_new_page_allocation:
            if (
                tier_level_for_new_page_allocation.lower() != "high"
                and tier_level_for_new_page_allocation.lower() != "middle"
                and tier_level_for_new_page_allocation.lower() != "low"
            ):
                raise Exception(
                    "tier_level_for_new_page_allocation must be High, Middle or Low"
                )

        tiering_policy = spec.tiering_policy
        if tiering_policy is None:
            return

        if not spec.is_relocation_enabled:
            raise ValueError(
                "If tiering_policy is specified then is_relocation_enabled must be true."
            )

        tier_level = tiering_policy.get("tier_level", None)
        if not tier_level:
            raise ValueError(
                "If tiering_policy is specified then tier_level must be specified."
            )

        if tier_level < 0 or tier_level > 31:
            raise ValueError("Specify a value from 0 to 31 for tier_level.")

        tier1AllocationRateMin = tiering_policy.get("tier1_allocation_rate_min", None)
        tier1AllocationRateMax = tiering_policy.get("tier1_allocation_rate_max", None)
        tier3AllocationRateMin = tiering_policy.get("tier3_allocation_rate_min", None)
        tier3AllocationRateMax = tiering_policy.get("tier3_allocation_rate_max", None)

        is0to5 = False
        if tier_level >= 0 and tier_level <= 5:
            is0to5 = True

        if (
            tier1AllocationRateMin
            and tier1AllocationRateMax
            and tier3AllocationRateMin
            and tier3AllocationRateMax
        ):
            if is0to5:
                raise ValueError(
                    "Any other of the tiering policy attributes must not be specified for tier_level between 0 and 5."
                )
        else:
            if is0to5:
                return

            raise ValueError(
                "All four of the tiering policy attributes must be specified."
            )

        isTier1AllocRateMinSet = (
            tier1AllocationRateMin > 0 and tier1AllocationRateMin <= 100
        )
        isTier1AllocRateMaxSet = (
            tier1AllocationRateMax > 0 and tier1AllocationRateMax <= 100
        )
        isTier3AllocRateMinSet = (
            tier3AllocationRateMin > 0 and tier3AllocationRateMin <= 100
        )
        isTier3AllocRateMaxSet = (
            tier3AllocationRateMax > 0 and tier3AllocationRateMax <= 100
        )

        if (
            isTier1AllocRateMinSet
            and isTier1AllocRateMaxSet
            and isTier3AllocRateMinSet
            and isTier3AllocRateMaxSet
        ):
            pass
        else:
            raise ValueError(
                "All four of the tiering policy attributes must be from 1 to 100."
            )

        if isTier1AllocRateMinSet and isTier1AllocRateMaxSet:
            if tier1AllocationRateMin > tier1AllocationRateMax:
                raise ValueError(
                    "Tier1AllocationRateMin can not be greater than Tier1AllocationRateMax."
                )
            # Validation check: The difference between the values of the tier1AllocationRateMax and tier1AllocationRateMin attributes is a multiple of 10.
            if (tier1AllocationRateMax - tier1AllocationRateMin) % 10 != 0:
                raise ValueError(
                    "Difference between Tier1AllocationRateMax and Tier1AllocationRateMin is not a multiple of 10."
                )

        if isTier3AllocRateMinSet and isTier3AllocRateMaxSet:
            if tier3AllocationRateMin > tier3AllocationRateMax:
                raise ValueError(
                    "Tier3AllocationRateMin can not be greater than Tier3AllocationRateMax."
                )
            if (tier3AllocationRateMax - tier3AllocationRateMin) % 10 != 0:
                raise ValueError(
                    "Difference between Tier3AllocationRateMax and Tier3AllocationRateMin is not a multiple of 10."
                )

        if isTier1AllocRateMinSet and isTier3AllocRateMinSet:
            # Validation check: The sum of the values of the tier1AllocationRateMin and tier3AllocationRateMin attributes is equal to or less than 100.
            if (tier1AllocationRateMin + tier3AllocationRateMin) > 100:
                raise ValueError(
                    "Sum of Tier1AllocationRateMin and Tier3AllocationRateMin exceeds 100."
                )

    @log_entry_exit
    def create_volume(self, spec: CreateVolumeSpec):
        if spec.pool_id is not None and (
            spec.parity_group or spec.external_parity_group
        ):
            raise ValueError(VSPVolValidationMsg.POOL_ID_PARITY_GROUP.value)
        if spec.parity_group and spec.external_parity_group:
            raise ValueError(VSPVolValidationMsg.BOTH_PARITY_GROUPS_SPECIFIED.value)
        if (spec.parity_group or spec.external_parity_group) and spec.tiering_policy:
            raise ValueError(VSPVolValidationMsg.BOTH_PARITY_GRP_TIERING.value)

        self.validate_tiering_policy(spec)
        if (
            spec.pool_id is None
            and not spec.parity_group
            and not spec.external_parity_group
        ):
            raise ValueError(VSPVolValidationMsg.NOT_POOL_ID_OR_PARITY_ID.value)
        if not spec.size:
            raise ValueError(VSPVolValidationMsg.SIZE_REQUIRED.value)
        # if "." in spec.size:
        #     raise ValueError(VSPVolValidationMsg.SIZE_INT_REQUIRED.value)
        found = False
        if spec.nvm_subsystem_name:
            found = self.does_nvme_subsystem_exist(spec.nvm_subsystem_name)
            if not found:
                raise ValueError(
                    VSPVolValidationMsg.NVM_SUBSYSTEM_DOES_NOT_EXIST.value.format(
                        spec.nvm_subsystem_name
                    )
                )
            if (
                spec.state is not None
                and spec.state.lower() == VSPVolumeSubstates.REMOVE_HOST_NQN
            ):
                raise ValueError(VSPVolValidationMsg.CONTRADICT_INFO.value)
            else:
                logger.writeDebug("RC:create_volume:nvm_system={}", found)

        # spec.size = process_size_string(spec.size)
        spec.block_size = convert_decimal_size_to_bytes(spec.size)
        self.connection_info.changed = True
        volume_created = self.provisioner.create_volume(spec)
        if found:
            self.process_create_nvme(found, spec)
        return volume_created

    @log_entry_exit
    def get_snapshot_list_for_volume(self, volume, snapshots=None):
        retList = []
        snapshots = self.get_all_snapshots() if snapshots is None else snapshots
        if snapshots:
            for x in snapshots:
                if x["pvolLdevId"] == volume.ldevId or x["svolLdevId"] == volume.ldevId:
                    short_snapshot_object = VSPVolumeSnapshotInfo(
                        x["pvolLdevId"], x["muNumber"], x["svolLdevId"]
                    )
                    retList.append(short_snapshot_object)
        return retList

    @log_entry_exit
    def get_all_snapshots(self):
        if self.snapshots is None:
            snapshot_prov = VSPHtiSnapshotProvisioner(self.connection_info)
            start_time = time.time()
            self.snapshots = snapshot_prov.get_snapshot_facts()
            end_time = time.time()
            elapsed_time = float(f"{end_time - start_time:.2f}")
            logger.writeDebug("RC:time taken for get_all_snapshots={}", elapsed_time)
        return self.snapshots

    @log_entry_exit
    def get_nvm_subsystem_for_ldev(self, ldev_id):
        ldev_all = []
        nvms = self.nvme_provisioner.get_nvme_subsystems_by_namespace()
        for nvm in nvms.data:
            ldevs = self.find_ldevs_in_nvm_subsystem(nvm.nvmSubsystemId, ldev_id)
            if ldevs and len(ldevs) > 0:
                for x in ldevs:
                    ldev_all.append(x)

        logger.writeDebug("RC:get_nvm_subsystem_for_ldev:ldev_all={}", ldev_all)
        result_list = []
        ports = self.nvme_provisioner.get_nvme_subsystems_by_port()
        logger.writeDebug("RC:get_nvm_subsystem_for_ldev:ports={}", ports)
        for ldev in ldev_all:
            for p in ports.data:
                if ldev.nvmSubsystemId == p.nvmSubsystemId:
                    item = VSPVolumeNvmSubsystenInfo(
                        p.nvmSubsystemId, p.nvmSubsystemName, p.portIds
                    )
                    result_list.append(item)
        return result_list

    @log_entry_exit
    def get_host_nqn_paths_for_nvm_subsystem(self, volume):
        nvm_ss_paths = self.nvme_provisioner.get_namespace_paths(volume.nvmSubsystemId)
        host_nqns = []
        for p in nvm_ss_paths.data:
            if p.namespaceId == int(volume.namespaceId) and p.ldevId == volume.ldevId:
                host_nqns.append(p.hostNqn)

        return host_nqns

    @log_entry_exit
    def get_nvm_subsystem_info(self, volume):
        host_nqns = self.get_host_nqn_paths_for_nvm_subsystem(volume)
        volume.numOfPorts = len(host_nqns)
        logger.writeDebug("RC:get_nvm_subsystem_info:no_of_ports={}", volume.numOfPorts)

        result_list = []
        nvm_ss = self.nvme_provisioner.get_nvme_subsystem_by_id(volume.nvmSubsystemId)
        logger.writeDebug("RC:get_nvm_subsystem_info:nvm_subsystem = {}", nvm_ss)
        item = VSPVolumeNvmSubsystenInfo(
            nvm_ss.nvmSubsystemId, nvm_ss.nvmSubsystemName, nvm_ss.portIds, host_nqns
        )
        result_list.append(item)
        return result_list

    @log_entry_exit
    def get_volumes_with_hg_iscsi(self, volumes):
        retList = []
        if volumes:
            for volume in volumes:
                hg_iscsi_tar_info = self.get_hostgroup_and_iscsi_target_info(volume)
                hostgroups = hg_iscsi_tar_info["hostgroups"]
                iscsi_targets = hg_iscsi_tar_info["iscsiTargets"]
                volume.hostgroups = hostgroups
                volume.iscsiTargets = iscsi_targets
                retList.append(volume)
        return VSPVolumesInfo(data=retList)

    @log_entry_exit
    def get_volumes_detail_for_spec(self, volumes, spec):
        retList = []
        if volumes:
            for volume in volumes:
                new_volume = self.get_volume_detail_for_spec(volume, spec)
                retList.append(new_volume)
        return VSPVolumesInfo(data=retList)

    @log_entry_exit
    def get_volume_detail_for_spec(self, volume, spec):
        # host group and iSCSI target info are always included
        hg_iscsi_tar_info = self.get_hostgroup_and_iscsi_target_info(volume)
        hostgroups = hg_iscsi_tar_info["hostgroups"]
        iscsi_targets = hg_iscsi_tar_info["iscsiTargets"]
        volume.hostgroups = hostgroups
        volume.iscsiTargets = iscsi_targets

        if spec.is_detailed is not None and spec.is_detailed is True:
            return self.get_volume_detail_info(volume, self.get_all_snapshots())
        else:
            if spec.query:
                if "cmd_device_settings" in spec.query:
                    if volume.attributes and "CMD" in volume.attributes:
                        self.provisioner.fill_cmd_device_info(volume)
                if "encryption_settings" in spec.query:
                    volume.isEncryptionEnabled = self.is_encryption_enabled_on_volume(
                        volume
                    )
                if "nvm_subsystem_info" in spec.query:
                    if volume.nvmSubsystemId:
                        nvm_subsystems = self.get_nvm_subsystem_info(volume)
                        logger.writeDebug(
                            "RC:get_volume_detail_with_spec:nvm_subsystem = {}",
                            nvm_subsystems,
                        )
                        volume.nvmSubsystems = nvm_subsystems
                if "qos_settings" in spec.query:
                    qos_settings = self.provisioner.get_qos_settings(volume.ldevId)
                    if qos_settings:
                        volume.qosSettings = qos_settings
                if "snapshots_info" in spec.query:
                    volume.snapshots = self.get_snapshot_list_for_volume(volume)

        return volume

    @log_entry_exit
    def get_volume_detail_info(
        self, volume, all_snapshots=None, single_vol=True, create_qos_setting=True
    ):
        logger.writeDebug("RC:get_volume_detail_info:volume={}", volume)
        if all_snapshots:
            snapshots = self.get_snapshot_list_for_volume(volume, all_snapshots)
            volume.snapshots = snapshots

        volume.isEncryptionEnabled = self.is_encryption_enabled_on_volume(volume)

        if volume.nvmSubsystemId:
            nvm_subsystems = self.get_nvm_subsystem_info(volume)
            logger.writeDebug(
                "RC:get_volume_detail_info:nvm_subsystem = {}", nvm_subsystems
            )
            volume.nvmSubsystems = nvm_subsystems

        qos_settings = None
        if create_qos_setting:
            qos_settings = self.provisioner.get_qos_settings(volume.ldevId)

        volume.qosSettings = qos_settings

        # Check if the ldev is a command device
        # This get call is needed for newly created cmd device
        # check_vol = self.provisioner.get_volume_by_ldev(volume.ldevId)
        # if check_vol.attributes and "CMD" in check_vol.attributes:
        #     volume.attributes = check_vol.attributes
        #     self.provisioner.fill_cmd_device_info(volume)

        if volume.attributes and "CMD" in volume.attributes:
            self.provisioner.fill_cmd_device_info(volume)
        return volume

    @log_entry_exit
    def get_volumes_detail_info(self, volumes):
        retList = []
        if volumes:
            all_snapshots = self.get_all_snapshots()
            logger.writeDebug("RC:get_volumes_detail_info:snapshots={}", all_snapshots)
            single_vol = False if len(volumes) > 1 else True
            for volume in volumes:
                new_volume = self.get_volume_detail_info(
                    volume, all_snapshots, single_vol
                )
                retList.append(new_volume)
        return VSPVolumesInfo(data=retList)

    @log_entry_exit
    def is_encryption_enabled_on_volume(self, volume):

        # if there is parity group info then this is a basic volume
        if volume.numOfParityGroups is not None and volume.numOfParityGroups > 0:
            if volume.attributes is not None:
                if "ENCD" in volume.attributes:
                    return True
                else:
                    return False
            else:
                return False

        if volume.poolId is not None:
            pool_volumes = self.provisioner.get_volumes_by_pool_id(volume.poolId)
            logger.writeDebug(
                "RC:is_encryption_enabled_on_volume:pool_volumes={}", pool_volumes
            )
            if pool_volumes and len(pool_volumes.data) > 0:
                for v in pool_volumes.data:
                    if v.attributes is not None:
                        if "ENCD" not in v.attributes:
                            return False
                    else:
                        return False
                return True

        return False

    @log_entry_exit
    def get_hostgroup_and_iscsi_target_info(self, volume, single_vol=True):
        hostgroups = []
        iscsi_targets = []
        if volume:
            if volume.numOfPorts is not None and volume.numOfPorts > 0:

                logger.writeDebug(
                    "RC:get_hostgroup_and_iscsi_target_info:ports={}", volume.ports
                )
                for port in volume.ports:
                    port_type = self.get_port_type(port["portId"])
                    if single_vol:
                        port_details = self.hg_prov.get_one_host_group_using_hg_port_id(
                            port["portId"], port["hostGroupNumber"]
                        )
                    hg_name = (
                        port_details.hostGroupName
                        if single_vol and port_details
                        else port["hostGroupName"]
                    )
                    if port_type == "ISCSI":
                        iscsi_targets.append(
                            VSPVolumePortInfo(
                                port["portId"],
                                port["hostGroupNumber"],
                                hg_name,
                            )
                        )
                    elif port_type == "FIBRE":
                        hostgroups.append(
                            VSPVolumePortInfo(
                                port["portId"],
                                port["hostGroupNumber"],
                                hg_name,
                            )
                        )
                    else:
                        pass
        ret_dict = {"hostgroups": hostgroups, "iscsiTargets": iscsi_targets}
        return ret_dict

    @log_entry_exit
    def get_port_type(self, port_id):
        port_type = self.port_prov.get_port_type(port_id)
        return port_type

    @log_entry_exit
    def get_volumes(self, get_volume_spec: VolumeFactSpec):

        if get_volume_spec.query and "free_ldev_id" in get_volume_spec.query:
            return self.provisioner.get_free_ldevs_from_meta(
                get_volume_spec.count,
                get_volume_spec.start_ldev_id,
                get_volume_spec.end_ldev_id,
                get_volume_spec.resource_group_id,
            )

        if get_volume_spec.ldev_id is not None:
            # new_volume = None
            volume = self.provisioner.get_volume_by_ldev(get_volume_spec.ldev_id)
            if volume:
                # if (
                #     get_volume_spec.is_detailed is not None
                #     and get_volume_spec.is_detailed is True
                # ):

                #     all_snapshots = self.get_all_snapshots()
                #     volume = self.get_volume_detail_info(volume, all_snapshots)
                volume = self.get_volume_detail_for_spec(volume, get_volume_spec)
                logger.writeDebug("RC:get_volumes:found volume={}", volume)

                return VSPVolumesInfo(data=[volume])

        if (
            get_volume_spec.start_ldev_id is not None
            and get_volume_spec.end_ldev_id is not None
            and get_volume_spec.count is None
        ):
            get_volume_spec.count = (
                get_volume_spec.end_ldev_id - get_volume_spec.start_ldev_id + 1
            )
        volume_data = self.provisioner.get_volumes(
            get_volume_spec.start_ldev_id,
            get_volume_spec.count,
            get_volume_spec.pool_id,
            get_volume_spec.resource_group_id,
            get_volume_spec.journal_id,
            get_volume_spec.parity_group_id,
        )

        if get_volume_spec.end_ldev_id:
            end_ldev_id = get_volume_spec.end_ldev_id
            volume_data.data = [
                volume for volume in volume_data.data if volume.ldevId <= end_ldev_id
            ]

        if get_volume_spec.name:
            volume_data.data = [
                volume
                for volume in volume_data.data
                if volume.label == get_volume_spec.name
            ]
        if (
            get_volume_spec.is_detailed is not None
            and get_volume_spec.is_detailed is True
        ):
            return self.get_volumes_detail_for_spec(volume_data.data, get_volume_spec)
        else:
            return self.get_volumes_with_hg_iscsi(volume_data.data)

    @log_entry_exit
    def generate_volume_name(self, ldev_id, label):
        if label is None:
            label = f"{DEFAULT_NAME_PREFIX}-{ldev_id}"
        # else:
        #     do_not_need_prefix = label.lower().startswith("ansible")
        #     if do_not_need_prefix:
        #         pass
        #     else:
        #         label = f"ansible-{label}"
        return label

    @log_entry_exit
    def update_volume_name(self, ldev_id, name):
        name = self.generate_volume_name(ldev_id, name)
        self.provisioner.change_volume_settings_ext(ldev_id, label=name)

    @log_entry_exit
    def get_volume_by_name(self, name):

        volumes = self.provisioner.get_volumes()
        for volume in volumes.data:
            if volume.label == name:
                return volume

    @log_entry_exit
    def get_volume_by_id(self, id):

        volumes = self.provisioner.get_volumes()
        for volume in volumes.data:
            if volume.ldevId == int(id):
                return volume
        raise ValueError(VSPVolValidationMsg.VOLUME_NOT_FOUND.value.format(id))

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
            self.provisioner.delete_volume(ldev_id, force_execute)
            self.connection_info.changed = True
        except Exception as e:
            logger.writeError(f"An error occurred in delete_volume: {str(e)}")
            raise ValueError(VSPVolValidationMsg.VOLUME_HAS_PATH.value)

    @log_entry_exit
    def delete_volume_force(self, volume: VSPVolumeInfo):
        ports = volume.ports
        if ports:
            for port in ports:
                self.delete_lun_path(port)

        self.delete_host_ns_path_for_ldev(volume.ldevId)
        self.delete_ldev_from_nvme_subsystem(volume.ldevId)

        self.delete_volume(volume)

    @log_entry_exit
    def delete_host_nqns_from_nvme_subsystem(self, host_nqns):
        for host_nqn in host_nqns:
            self.delete_host_ns_path_for_host_nqn(host_nqn)
            self.delete_host_nqn_from_nvme_subsystem(host_nqn)

    @log_entry_exit
    def delete_host_nqn_from_nvme_subsystem(self, host_nqn):
        nvms = self.nvme_provisioner.get_nvme_subsystems_by_nqn()

        for nvm in nvms.data:
            host_nqns = self.find_host_nqn_in_nvm_subsystem(
                nvm.nvmSubsystemId, host_nqn
            )
            if host_nqns and len(host_nqns) > 0:
                for x in host_nqns:
                    self.nvme_provisioner.delete_host_nqn_by_id(x.hostNqnId)

    @log_entry_exit
    def find_host_nqn_in_nvm_subsystem(self, nvm_subsystem_id, host_nqn):
        host_nqns_to_delete = []
        host_nqns = self.nvme_provisioner.get_host_nqns(nvm_subsystem_id)
        for hn in host_nqns.data:
            if hn.hostNqn == host_nqn:
                host_nqns_to_delete.append(hn)
        return host_nqns_to_delete

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
    def delete_host_ns_path_for_host_nqn(self, host_nqn):
        nvms = self.nvme_provisioner.get_nvme_subsystems_by_nqn()
        for nvm in nvms.data:
            paths = self.find_host_nqn_in_paths(nvm.nvmSubsystemId, host_nqn)
            if paths and len(paths) > 0:
                # self.nvme_provisioner.delete_host_namespace_path(ldev_found.nvmSubsystemId, ldev_found.hostNqn, int(ldev_found.namespaceId))
                for x in paths:
                    self.nvme_provisioner.delete_host_namespace_path_by_id(
                        x.namespacePathId
                    )

    @log_entry_exit
    def find_host_nqn_in_paths(self, nvm_subsystem_id, host_nqn):
        host_nqns_to_delete = []
        paths = self.nvme_provisioner.get_namespace_paths(nvm_subsystem_id)
        for path in paths.data:
            if path.hostNqn == host_nqn:
                host_nqns_to_delete.append(path)
        return host_nqns_to_delete

    @log_entry_exit
    def delete_lun_path(self, port):
        self.provisioner.delete_lun_path(port)


class VolumeCommonPropertiesExtractor:
    def __init__(self, serial):

        self.serial = serial
        self.common_properties = {
            "ldev_id": int,
            "ldev_id_hex": str,
            "deduplication_compression_mode": str,
            "emulation_type": str,
            "name": str,
            "parity_group_id": str,
            "pool_id": int,
            "resource_group_id": int,
            "status": str,
            "total_capacity": str,
            "used_capacity": str,
            "path_count": int,
            "provision_type": str,
            # "logical_unit_id_hex_format": str,
            "canonical_name": str,
            "dedup_compression_progress": int,
            "dedup_compression_status": str,
            "is_alua": bool,
            "is_data_reduction_share_enabled": bool,
            "num_of_ports": int,
            # "ports": list,
            # "namespace_id": str,
            # "nvm_subsystem_id": str,
            "is_encryption_enabled": bool,
            "hostgroups": list,
            "iscsi_targets": list,
            "snapshots": list,
            "nvm_subsystems": list,
            "storage_serial_number": str,
            # sng20241202 tiering_policy extractor
            "tiering_policy": dict,
            "tier_level_for_new_page_alloc": str,
            "tier1_alloc_rate_min": int,
            "tier1_alloc_rate_max": int,
            "tier3_alloc_rate_min": int,
            "tier3_alloc_rate_max": int,
            "tier_level": str,  # tier_level='all' if is_relocation_enabled: false
            "qos_settings": dict,
            "virtual_ldev_id": int,
            "virtual_ldev_id_hex": str,
            "is_command_device": bool,
            "is_security_enabled": bool,
            "is_user_authentication_enabled": bool,
            "is_device_group_definition_enabled": bool,
            "is_write_protected": bool,
            "is_write_protected_by_key": bool,
            "is_compression_acceleration_enabled": bool,
            "compression_acceleration_status": str,
            "mp_blade_id": int,
            "clpr_id": int,
            "data_reduction_process_mode": str,
            "is_relocation_enabled": bool,
            "is_full_allocation_enabled": bool,
        }

        self.parameter_mapping = {
            #  20240914 - uca-1346 tieringProperties is changed to tieringPropertiesDto in the porcelain response
            "tiering_policy": "tieringPropertiesDto",
            # "tiering_policy": "tieringProperties",
            "tier_level_for_new_page_alloc": "tierLevelForNewPageAllocation",
            "tier1_alloc_rate_min": "tier1AllocationRateMin",
            "tier1_alloc_rate_max": "tier1AllocationRateMax",
            "tier3_alloc_rate_min": "tier3AllocationRateMin",
            "tier3_alloc_rate_max": "tier3AllocationRateMax",
            # "level": "tierLevel",
            "is_alua": "isAluaEnabled",
            # "is_data_reduction_share_enabled": "isDRS", # commented out as it is not in the response
            "is_data_reduction_share_enabled": "isDataReductionSharedVolumeEnabled",
            "parity_group_id": "parityGroupIds",
            "path_count": "numOfPorts",
            "provision_type": "attributes",
            "total_capacity": "blockCapacity",
            "used_capacity": "numOfUsedBlock",
            "name": "label",
            "deduplication_compression_mode": "dataReductionMode",
            "dedup_compression_status": "dataReductionStatus",
            "dedup_compression_progress": "dataReductionProgressRate",
        }
        self.size_properties = ("total_capacity", "used_capacity")
        self.provision_type = "provision_type"
        self.hex_value = "logical_unit_id_hex_format"
        self.parity_group_id = "parity_group_id"
        self.num_of_ports = "num_of_ports"

    def process_list(self, response_key):
        new_items = []

        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)
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
            # logger.writeDebug("20240825 after gateway creatlun response={}", response)
            new_dict = {}

            for key, value_type in self.common_properties.items():

                cased_key = snake_to_camel_case(key)
                # Get the corresponding key from the response or its mapped key

                response_key = get_response_key(
                    response,
                    cased_key,
                    self.parameter_mapping.get(cased_key),
                    key,
                    self.parameter_mapping.get(key),
                )

                # Assign the value based on the response key and its data type

                if response_key or isinstance(response_key, int):
                    if key == self.provision_type or key == self.parity_group_id:
                        new_dict[key] = value_type(
                            response_key
                            if isinstance(response_key, str)
                            else ",".join(response_key)
                        )
                    elif key == self.num_of_ports:
                        new_dict[key] = value_type(response_key)
                        new_dict["path_count"] = value_type(response_key)

                    elif key in self.size_properties:
                        if isinstance(response_key, str):
                            new_dict[key] = value_type(response_key)
                        else:
                            new_dict[key] = value_type(
                                convert_block_capacity(response_key)
                            )
                        # Add total_capacity_in_mb and used_capacity_in_mb fields
                        if key == "total_capacity":
                            mbvalue = convert_to_mb(new_dict[key])
                            new_dict["total_capacity_in_mb"] = mbvalue if mbvalue else 0
                        elif key == "used_capacity":
                            mbvalue = convert_to_mb(new_dict[key])
                            new_dict["used_capacity_in_mb"] = mbvalue if mbvalue else 0
                    else:
                        new_dict[key] = value_type(response_key)
                        self.build_tiering_policy_direct(new_dict, key, response_key)
                elif key == "tiering_policy":
                    if response_key is not None:
                        # build tiering_policy output for gateway
                        logger.writeDebug(
                            "tieringProperties={}", response["tiering_policy"]
                        )
                        logger.writeDebug(
                            "tiering_policy={}", response["tiering_policy"]
                        )
                        new_dict["tiering_policy"] = self.process_list(
                            response["tiering_policy"]
                        )
                        new_dict["tiering_policy"]["policy"] = self.process_list(
                            response["tiering_policy"]["policy"]
                        )
                    else:
                        logger.writeDebug("1053 response_key={}", response_key)
                elif key == self.hex_value:
                    new_dict[key] = (
                        response_key
                        if response_key
                        else volume_id_to_hex_format(response.get("ldevId")).upper()
                    )
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[key] = default_value

                if value_type == list and response_key:
                    new_dict[key] = self.process_list(response_key)

                # 20240825 voltiering tieringProperties
                if (
                    key == "tiering_policy"
                    and value_type == dict
                    and response_key is not None
                ):
                    # logger.writeDebug("tieringProperties={}", response["tieringProperties"])
                    logger.writeDebug(
                        "tieringProperties={}", response["tieringPropertiesDto"]
                    )
                    new_dict[key] = camel_to_snake_case_dict(response_key)
                    new_dict["tiering_policy"]["tier1_used_capacity_mb"] = new_dict[
                        "tiering_policy"
                    ]["tier1_used_capacity_m_b"]
                    new_dict["tiering_policy"]["tier2_used_capacity_mb"] = new_dict[
                        "tiering_policy"
                    ]["tier2_used_capacity_m_b"]
                    new_dict["tiering_policy"]["tier3_used_capacity_mb"] = new_dict[
                        "tiering_policy"
                    ]["tier3_used_capacity_m_b"]
                    new_dict[key]["policy"] = camel_to_snake_case_dict(
                        response.get("policy")
                    )
                    del new_dict["tiering_policy"]["tier1_used_capacity_m_b"]
                    del new_dict["tiering_policy"]["tier2_used_capacity_m_b"]
                    del new_dict["tiering_policy"]["tier3_used_capacity_m_b"]
                if key == "qos_settings":
                    new_dict[key] = camel_to_snake_case_dict(response_key)
            if new_dict.get("ldev_id_hex") == "":
                if (
                    new_dict.get("ldev_id") is not None
                    and new_dict.get("ldev_id") != ""
                ):
                    new_dict["ldev_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("ldev_id")
                    )
            if new_dict.get("vldev_id_hex") == "":
                if (
                    new_dict.get("vldev_id") is not None
                    and new_dict.get("vldev_id") != ""
                    and new_dict.get("vldev_id") != -1
                ):
                    new_dict["ldev_id_hex"] = volume_id_to_hex_format(
                        new_dict.get("vldev_id")
                    )
            if new_dict.get("storage_serial_number") is None:
                new_dict["storage_serial_number"] = self.serial

            if new_dict.get("tier1_alloc_rate_min") is not None:
                del new_dict["tier1_alloc_rate_min"]  # sng20241202
            if new_dict.get("tier1_alloc_rate_max") is not None:
                del new_dict["tier1_alloc_rate_max"]
            if new_dict.get("tier3_alloc_rate_min") is not None:
                del new_dict["tier3_alloc_rate_min"]
            if new_dict.get("tier3_alloc_rate_max") is not None:
                del new_dict["tier3_alloc_rate_max"]
            if new_dict.get("tier_level") is not None:
                del new_dict["tier_level"]
            if new_dict.get("tier_level_for_new_page_alloc") is not None:
                del new_dict["tier_level_for_new_page_alloc"]
                new_dict["tiering_policy"] = {}

            new_items.append(new_dict)
        return new_items

    # sng20241202 build tiering_policy output for direct
    def build_tiering_policy_direct(self, new_dict, key, value):

        if not (
            key == "tier_level"
            or key == "tier1_alloc_rate_min"
            or key == "tier1_alloc_rate_max"
            or key == "tier3_alloc_rate_min"
            or key == "tier3_alloc_rate_max"
            or key == "tier_level_for_new_page_alloc"
        ):
            return

        if new_dict.get("tiering_policy") is None:
            new_dict["tiering_policy"] = {}
            new_dict["tiering_policy"]["policy"] = {}
            new_dict["tiering_policy"]["tier1_used_capacity_mb"] = 0
            new_dict["tiering_policy"]["tier2_used_capacity_mb"] = 0
            new_dict["tiering_policy"]["tier3_used_capacity_mb"] = 0

        if key == "tier_level_for_new_page_alloc":
            new_dict["tiering_policy"]["tier_level_for_new_page_alloc"] = value
            del new_dict[key]
            return

        if key == "tier_level":
            if value == "all":
                value = 0
            new_dict["tiering_policy"]["policy"]["level"] = value
            del new_dict[key]
            return

        if (
            key == "tier1_alloc_rate_min"
            or key == "tier1_alloc_rate_max"
            or key == "tier3_alloc_rate_min"
            or key == "tier3_alloc_rate_max"
        ):
            new_dict["tiering_policy"]["policy"][key] = value
            del new_dict[key]
            return


class ExternalVolumePropertiesExtractor:
    def __init__(self, serial):

        self.serial = serial
        self.common_properties = {
            "externalPorts": list,
            "externalVolumeId": str,
            "ldev_id": int,
            "emulation_type": str,
            "name": str,
            "resource_group_id": int,
            "status": str,
            "total_capacity": str,
            "provision_type": str,
            "logical_unit_id_hex_format": str,
            "canonical_name": str,
            "virtual_ldev_id": int,
        }

        self.parameter_mapping = {
            #  20240914 - uca-1346 tieringProperties is changed to tieringPropertiesDto in the porcelain response
            "tiering_policy": "tieringPropertiesDto",
            # "tiering_policy": "tieringProperties",
            "tier_level_for_new_page_alloc": "tierLevelForNewPageAllocation",
            "tier1_alloc_rate_min": "tier1AllocationRateMin",
            "tier1_alloc_rate_max": "tier1AllocationRateMax",
            "tier3_alloc_rate_min": "tier3AllocationRateMin",
            "tier3_alloc_rate_max": "tier3AllocationRateMax",
            # "level": "tierLevel",
            "is_alua": "isAluaEnabled",
            # "is_data_reduction_share_enabled": "isDRS", # commented out as it is not in the response
            "is_data_reduction_share_enabled": "isDataReductionSharedVolumeEnabled",
            "parity_group_id": "parityGroupIds",
            "path_count": "numOfPorts",
            "provision_type": "attributes",
            "total_capacity": "blockCapacity",
            "used_capacity": "numOfUsedBlock",
            "name": "label",
            "deduplication_compression_mode": "dataReductionMode",
            "dedup_compression_status": "dataReductionStatus",
            "dedup_compression_progress": "dataReductionProgressRate",
        }
        self.size_properties = ("total_capacity", "used_capacity")
        self.provision_type = "provision_type"
        self.hex_value = "logical_unit_id_hex_format"
        self.parity_group_id = "parity_group_id"
        self.num_of_ports = "num_of_ports"

    def process_list(self, response_key):
        new_items = []

        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)
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
            logger.writeDebug("20250314 after gateway creatlun response={}", response)
            new_dict = {}

            for key, value_type in self.common_properties.items():

                cased_key = snake_to_camel_case(key)
                # Get the corresponding key from the response or its mapped key
                logger.writeDebug("20250314 cased_key={}", cased_key)
                logger.writeDebug("20250314 key={}", key)

                response_key = None
                if not isinstance(response, list):
                    response_key = get_response_key(
                        response,
                        cased_key,
                        self.parameter_mapping.get(cased_key),
                        key,
                        self.parameter_mapping.get(key),
                    )

                # Assign the value based on the response key and its data type
                logger.writeDebug("20250314 response_key={}", response_key)

                if response_key or isinstance(response_key, int):
                    if key == self.provision_type or key == self.parity_group_id:
                        new_dict[key] = value_type(
                            response_key
                            if isinstance(response_key, str)
                            else ",".join(response_key)
                        )
                    elif key == self.num_of_ports:
                        new_dict[key] = value_type(response_key)
                        new_dict["path_count"] = value_type(response_key)

                    elif key in self.size_properties:
                        if isinstance(response_key, str):
                            new_dict[key] = value_type(response_key)
                        else:
                            new_dict[key] = value_type(
                                convert_block_capacity(response_key)
                            )
                        # Add total_capacity_in_mb and used_capacity_in_mb fields
                        if key == "total_capacity":
                            mbvalue = convert_to_mb(new_dict[key])
                            new_dict["total_capacity_in_mb"] = mbvalue if mbvalue else 0
                        elif key == "used_capacity":
                            mbvalue = convert_to_mb(new_dict[key])
                            new_dict["used_capacity_in_mb"] = mbvalue if mbvalue else 0
                    else:
                        new_dict[key] = value_type(response_key)
                        self.build_tiering_policy_direct(new_dict, key, response_key)

                elif key == "tiering_policy":
                    if response_key is not None:
                        # 20250312 doesn't look like we can reach here,
                        # below is likely not used, do not follow
                        #
                        # build tiering_policy output for gateway
                        logger.writeDebug(
                            "tieringProperties={}", response["tiering_policy"]
                        )
                        logger.writeDebug(
                            "tiering_policy={}", response["tiering_policy"]
                        )
                        new_dict["tiering_policy"] = self.process_list(
                            response["tiering_policy"]
                        )
                        new_dict["tiering_policy"]["policy"] = self.process_list(
                            response["tiering_policy"]["policy"]
                        )
                    else:
                        logger.writeDebug("1053 response_key={}", response_key)
                elif key == self.hex_value:
                    new_dict[key] = (
                        response_key
                        if response_key
                        else volume_id_to_hex_format(response.get("ldevId")).upper()
                    )
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[key] = default_value

                if value_type == list and response_key:
                    new_dict[key] = self.process_list(response_key)

                # 20240825 voltiering tieringProperties
                if (
                    key == "tiering_policy"
                    and value_type == dict
                    and response_key is not None
                ):
                    # logger.writeDebug("tieringProperties={}", response["tieringProperties"])
                    logger.writeDebug(
                        "tieringProperties={}", response["tieringPropertiesDto"]
                    )
                    logger.writeDebug("response_key={}", response_key)
                    logger.writeDebug("key={}", key)
                    new_dict[key] = camel_to_snake_case_dict(response_key)
                    new_dict["tiering_policy"]["tier1_used_capacity_mb"] = new_dict[
                        "tiering_policy"
                    ]["tier1_used_capacity_m_b"]
                    new_dict["tiering_policy"]["tier2_used_capacity_mb"] = new_dict[
                        "tiering_policy"
                    ]["tier2_used_capacity_m_b"]
                    new_dict["tiering_policy"]["tier3_used_capacity_mb"] = new_dict[
                        "tiering_policy"
                    ]["tier3_used_capacity_m_b"]
                    new_dict[key]["policy"] = camel_to_snake_case_dict(
                        response.get("policy")
                    )
                    del new_dict["tiering_policy"]["tier1_used_capacity_m_b"]
                    del new_dict["tiering_policy"]["tier2_used_capacity_m_b"]
                    del new_dict["tiering_policy"]["tier3_used_capacity_m_b"]
                if key == "qos_settings":
                    new_dict[key] = camel_to_snake_case_dict(response_key)

            if new_dict.get("storage_serial_number"):
                del new_dict["storage_serial_number"]

            if new_dict.get("tier1_alloc_rate_min") is not None:
                del new_dict["tier1_alloc_rate_min"]  # sng20241202
            if new_dict.get("tier1_alloc_rate_max") is not None:
                del new_dict["tier1_alloc_rate_max"]
            if new_dict.get("tier3_alloc_rate_min") is not None:
                del new_dict["tier3_alloc_rate_min"]
            if new_dict.get("tier3_alloc_rate_max") is not None:
                del new_dict["tier3_alloc_rate_max"]
            if new_dict.get("tier_level") is not None:
                del new_dict["tier_level"]
            if new_dict.get("tier_level_for_new_page_alloc") is not None:
                del new_dict["tier_level_for_new_page_alloc"]
                new_dict["tiering_policy"] = {}

            new_items.append(new_dict)
        return new_items

    # sng20241202 build tiering_policy output for direct
    def build_tiering_policy_direct(self, new_dict, key, value):

        if not (
            key == "tier_level"
            or key == "tier1_alloc_rate_min"
            or key == "tier1_alloc_rate_max"
            or key == "tier3_alloc_rate_min"
            or key == "tier3_alloc_rate_max"
            or key == "tier_level_for_new_page_alloc"
        ):
            return

        if new_dict.get("tiering_policy") is None:
            new_dict["tiering_policy"] = {}
            new_dict["tiering_policy"]["policy"] = {}
            new_dict["tiering_policy"]["tier1_used_capacity_mb"] = 0
            new_dict["tiering_policy"]["tier2_used_capacity_mb"] = 0
            new_dict["tiering_policy"]["tier3_used_capacity_mb"] = 0

        if key == "tier_level_for_new_page_alloc":
            new_dict["tiering_policy"]["tier_level_for_new_page_alloc"] = value
            del new_dict[key]
            return

        if key == "tier_level":
            if value == "all":
                value = 0
            new_dict["tiering_policy"]["policy"]["level"] = value
            del new_dict[key]
            return

        if (
            key == "tier1_alloc_rate_min"
            or key == "tier1_alloc_rate_max"
            or key == "tier3_alloc_rate_min"
            or key == "tier3_alloc_rate_max"
        ):
            new_dict["tiering_policy"]["policy"][key] = value
            del new_dict[key]
            return
