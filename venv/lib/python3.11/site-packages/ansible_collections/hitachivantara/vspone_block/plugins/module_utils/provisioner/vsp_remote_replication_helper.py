try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.vsp_constants import VolumePayloadConst, DEFAULT_NAME_PREFIX
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg, TrueCopyFailedMsg
    from ..model.vsp_volume_models import CreateVolumeSpec
    from .vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from .vsp_host_group_provisioner import VSPHostGroupProvisioner
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.vsp_constants import VolumePayloadConst, DEFAULT_NAME_PREFIX
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
    )
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg, TrueCopyFailedMsg
    from model.vsp_volume_models import CreateVolumeSpec
    from .vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from .vsp_host_group_provisioner import VSPHostGroupProvisioner

logger = Log()


class RemoteReplicationHelperForSVol:

    def __init__(self, connection_info, serial):
        self.hg_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_HOST_GROUP
        )
        self.sp_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.STORAGE_PORT
        )
        self.vol_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )
        self.nvme_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_NVME_SUBSYSTEM
        )
        self.iscsi_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_ISCSI_TARGET
        )
        self.hg_prov = VSPHostGroupProvisioner(connection_info)
        self.port_prov = VSPStoragePortProvisioner(connection_info)
        self.connection_info = connection_info
        self.serial = serial
        self.hg_gateway.set_serial(serial)
        self.sp_gateway.set_serial(serial)
        self.vol_gateway.set_serial(serial)

    @log_entry_exit
    def delete_lun_path(self, volume):
        if volume.ports is not None and len(volume.ports) > 0:
            for port in volume.ports:
                logger.writeDebug("PROV:delete_volume:port = {}", port)
                self.vol_gateway.delete_lun_path(port)

    @log_entry_exit
    def delete_actual_volume(self, secondary_vol_id, volume):
        force_execute = (
            True
            if volume.dataReductionMode
            and volume.dataReductionMode.lower() != VolumePayloadConst.DISABLED
            else None
        )
        try:
            self.vol_gateway.delete_volume(secondary_vol_id, force_execute)
            self.connection_info.changed = False
            return
        except Exception as e:
            err_msg = TrueCopyFailedMsg.SEC_VOLUME_DELETE_FAILED.value + str(e)
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def delete_volume(self, secondary_vol_id, volume=None):

        if volume is None:
            volume = self.vol_gateway.get_volume_by_id(secondary_vol_id)

        self.delete_lun_path(volume)
        self.delete_actual_volume(secondary_vol_id, volume)

    @log_entry_exit
    def select_secondary_volume_id(self, pvol_id, spec=None):
        if spec is None:
            free_vol_info = self.vol_gateway.get_free_ldev_matching_pvol(pvol_id)
            logger.writeDebug(
                "PROV:select_secondary_volume_id:free_vol_info = {}", free_vol_info
            )
            return free_vol_info.data[0].ldevId
        else:
            if (
                spec.begin_secondary_volume_id is not None
                and spec.end_secondary_volume_id is not None
            ):
                # Select the first free volume in the range
                free_vol_info = self.vol_gateway.get_free_ldev_matching_svol_range(
                    spec.begin_secondary_volume_id, spec.end_secondary_volume_id
                )
                logger.writeDebug(
                    "PROV:select_secondary_volume_id:for range:free_vol_info = {}",
                    free_vol_info,
                )
                if free_vol_info.data:
                    for free_vol in free_vol_info.data:
                        if free_vol.resourceGroupId == 0:
                            if (
                                free_vol.ldevId > spec.begin_secondary_volume_id
                                and free_vol.ldevId < spec.end_secondary_volume_id
                            ):
                                return free_vol.ldevId
                            else:
                                logger.writeDebug(
                                    "PROV:select_secondary_volume_id:free_vol = {}",
                                    free_vol,
                                )

                err_msg = VSPTrueCopyValidateMsg.NO_FREE_LDEV_IN_RANGE.value.format(
                    spec.begin_secondary_volume_id, spec.end_secondary_volume_id
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            else:
                # If no range is specified, get the first free volume
                free_vol_info = self.vol_gateway.get_free_ldev_matching_pvol(pvol_id)
                logger.writeDebug(
                    "PROV:select_secondary_volume_id:free_vol_info = {}", free_vol_info
                )
                if free_vol_info.data:
                    return free_vol_info.data[0].ldevId
                else:
                    err_msg = VSPTrueCopyValidateMsg.NO_FREE_LDEV_FOUND.value.format(
                        pvol_id
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

    @log_entry_exit
    def validate_for_iscsi(self, vol_info):
        # check if pvol is iscsi
        if vol_info.ports is not None and len(vol_info.ports) > 0:
            port = vol_info.ports[0]
            if isinstance(port, dict) and port.get("hostGroupNumber") is None:
                err_msg = VSPTrueCopyValidateMsg.PVOL_ISCSI_MISSING.value.format(
                    vol_info.ldevId
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

    @log_entry_exit
    def construct_svol_spec(self, svol_id, pvol_info, spec):
        sec_vol_spec = CreateVolumeSpec()
        sec_vol_spec.ldev_id = svol_id
        sec_vol_spec.pool_id = spec.secondary_pool_id
        sec_vol_spec.size = self.get_size_from_byte_format_capacity(
            pvol_info.byteFormatCapacity
        )
        sec_vol_spec.capacity_saving = pvol_info.dataReductionMode
        if pvol_info.dataReductionMode != VolumePayloadConst.DISABLED:
            sec_vol_spec.is_compression_acceleration_enabled = (
                pvol_info.isCompressionAccelerationEnabled
            )
            spec.is_data_reduction_force_copy = True

        return sec_vol_spec

    @log_entry_exit
    def get_secondary_volume_id(self, vol_info, spec, is_iscsi=False):
        logger.writeDebug("PROV:get_secondary_volume_id:vol_info = {}", vol_info)
        # Before creating the secondary volume check if secondary hostgroup exists
        if is_iscsi:
            self.validate_for_iscsi(vol_info)
            host_groups = self.get_secondary_hostgroups(
                spec.secondary_iscsi_targets, is_iscsi
            )
        else:
            host_groups = self.get_secondary_hostgroups(spec.secondary_hostgroups)

        logger.writeDebug("PROV:get_secondary_volume_id:host_groups = {}", host_groups)
        if host_groups is None and spec.provisioned_secondary_volume_id is None:
            err_msg = None
            if is_iscsi:
                err_msg = VSPTrueCopyValidateMsg.NO_REMOTE_ISCSI_FOUND.value
            else:
                err_msg = VSPTrueCopyValidateMsg.NO_REMOTE_HG_FOUND.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if spec.provisioned_secondary_volume_id is not None:
            svol_id = spec.provisioned_secondary_volume_id
            sec_vol_info = self.vol_gateway.get_volume_by_id(svol_id)
            hgs_prov_svol = self.get_hgs_for_provisioned_svol(sec_vol_info, is_iscsi)
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
        if spec.provisioned_secondary_volume_id is not None:
            sec_vol_id = spec.provisioned_secondary_volume_id
        else:
            sec_vol_id = self.vol_gateway.create_volume(sec_vol_spec)
            # the name change is done in the update_volume method
            if vol_info.label is not None and vol_info.label != "":
                sec_vol_name = vol_info.label
            else:
                sec_vol_name = f"{DEFAULT_NAME_PREFIX}-{vol_info.ldevId}"
            try:
                self.vol_gateway.change_volume_settings(sec_vol_id, label=sec_vol_name)
            except Exception as ex:
                err_msg = TrueCopyFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
                logger.writeError(err_msg)
                # if setting the volume name fails, delete the secondary volume
                self.delete_volume(sec_vol_id)
                raise ValueError(err_msg)
        try:
            lun_ids = {}
            if host_groups is not None and len(host_groups) > 0:
                if is_iscsi:
                    lun_ids = self.find_lun_ids_from_spec(
                        host_groups, spec.secondary_iscsi_targets, is_iscsi
                    )
                    self.add_luns_to_iscsi_targets(sec_vol_id, host_groups, lun_ids)
                else:
                    lun_ids = self.find_lun_ids_from_spec(
                        host_groups, spec.secondary_hostgroups
                    )
                    self.add_luns_to_host_groups(sec_vol_id, host_groups, lun_ids)
        except Exception as ex:
            err_msg = TrueCopyFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
            logger.writeError(err_msg)
            if not spec.provisioned_secondary_volume_id:
                # if attaching the volume to the host group fails, delete the secondary volume
                try:
                    self.delete_volume(sec_vol_id)
                except Exception as e:
                    logger.writeError(err_msg)
            else:
                # if attaching the volume to the host group fails, detach them
                try:
                    if is_iscsi:
                        self.dettach_iscsi_targets(host_groups, lun_ids)
                    else:
                        self.dettach_hostgroups(host_groups, lun_ids)
                except Exception as e:
                    logger.writeError(err_msg)
            raise ValueError(err_msg)

        logger.writeDebug(
            "PROV:get_secondary_volume_id:sec_vol_name = {}", sec_vol_name
        )
        return sec_vol_id

    @log_entry_exit
    def add_luns_to_host_groups(self, sec_vol_id, host_groups, lun_ids):
        for i in range(0, len(host_groups)):
            hg = host_groups[i]
            self.hg_gateway.add_luns_to_host_group(
                hg,
                [sec_vol_id],
                lun_ids.get(hg.hostGroupName, None),
            )

    @log_entry_exit
    def add_luns_to_iscsi_targets(self, sec_vol_id, iscsi_targets, lun_ids):
        for i in range(0, len(iscsi_targets)):
            iscsi_target = iscsi_targets[i]
            self.iscsi_gateway.add_luns_to_iscsi_target(
                iscsi_target,
                [sec_vol_id],
                None,
                lun_ids.get(iscsi_target.iscsiName, None),
            )

    @log_entry_exit
    def dettach_hostgroups(self, host_groups, lun_ids):
        for host_group in host_groups:
            try:
                lun_id = lun_ids.get(host_group.hostGroupName, None)
                if lun_id is not None and lun_id != -1:
                    self.hg_gateway.delete_one_lun_from_host_group(
                        host_group,
                        lun_id,
                    )
            except Exception as e:
                logger.writeError(e)

    @log_entry_exit
    def dettach_iscsi_targets(self, iscsi_targets, lun_ids):
        for host_group in iscsi_targets:
            try:
                lun_id = lun_ids.get(host_group.iscsiName, None)
                if lun_id is not None and lun_id != -1:
                    self.iscsi_gateway.delete_one_lun_from_iscsi_target(
                        host_group,
                        lun_id,
                    )
            except Exception as e:
                logger.writeError(e)

    @log_entry_exit
    def get_secondary_hostgroups(self, secondary_hostgroup, is_iscsi=False):
        hostgroups_list = self.validate_secondary_hostgroups(
            secondary_hostgroup, is_iscsi
        )
        logger.writeDebug(
            "PROV:get_secondary_hostgroups:hostgroups_list = {}", hostgroups_list
        )
        if hostgroups_list is None or len(hostgroups_list) == 0:
            return None
        return hostgroups_list

    @log_entry_exit
    def parse_hostgroup(self, hostgroup):
        hostgroup.port = hostgroup.portId
        return hostgroup

    @log_entry_exit
    def get_size_from_byte_format_capacity(self, byte_format):
        logger.writeDebug(
            "PROV:get_size_from_byte_format_capacity:hgs = {}", byte_format
        )
        value = byte_format.split(" ")[0]
        unit = byte_format.split(" ")[1]
        int_value = value.split(".")[0]
        return f"{int_value}{unit}"

    def get_secondary_hostgroups_payload(self, secondary_hostgroups):
        hostgroups_list = self.validate_secondary_hostgroups(secondary_hostgroups)
        payload = self.create_secondary_hgs_payload(hostgroups_list)
        return payload

    def validate_secondary_hostgroups(self, secondary_hgs, is_iscsi=False):
        logger.writeDebug("PROV:validate_secondary_hostgroups:hgs = {}", secondary_hgs)
        hostgroup_list = []
        if secondary_hgs is None:
            return hostgroup_list
        for hg in secondary_hgs:
            hostgroup = self.get_hg_by_name_port(hg.name, hg.port, is_iscsi)
            if hostgroup is None:
                err_msg = ""
                if is_iscsi:
                    err_msg = VSPTrueCopyValidateMsg.NO_REMOTE_ISCSI_FOUND.value.format(
                        hg.name, hg.port
                    )
                else:
                    err_msg = VSPTrueCopyValidateMsg.NO_REMOTE_HG_FOUND.value.format(
                        hg.name, hg.port
                    )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

            hostgroup_list.append(hostgroup)

        logger.writeDebug(
            f"PROV:validate_secondary_hostgroups:hostgroup_list = {hostgroup_list}"
        )

        for hg in secondary_hgs:
            port = self.get_port_by_name(hg.port)
            if port is None:
                err_msg = VSPTrueCopyValidateMsg.SEC_PORT_NOT_FOUND.value.format(
                    hg.port
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

            # if port.portInfo["portType"] != "FIBRE" or port.portInfo["mode"] != "SCSI":
            #     raise ValueError(VSPTrueCopyValidateMsg.WRONG_PORT_PROVIDED.value.format(port.resourceId, port.portInfo["portType"], port.portInfo["mode"]))

        return hostgroup_list

    @log_entry_exit
    def get_hg_by_name_port(self, name, port, is_iscsi=False):
        hg = {}
        if is_iscsi is True:
            hg = self.iscsi_gateway.get_one_iscsi_target(port, name)
        else:
            hg = self.hg_gateway.get_one_host_group(port, name)
        logger.writeDebug("PROV:get_hg_by_name_port:hgs = {}", hg)
        if hg is None:
            return None
        return hg.data

    @log_entry_exit
    def get_port_by_name(self, port):
        return self.sp_gateway.get_single_storage_port(port)

    @log_entry_exit
    def create_secondary_hgs_payload(self, hgs):
        ret_list = []
        for hg in hgs:
            item = {}
            item["hostGroupID"] = hg.hostGroupInfo["hostGroupId"]
            item["name"] = hg.hostGroupInfo["hostGroupName"]
            item["port"] = hg.hostGroupInfo["port"]
            item["resourceGroupID"] = hg.hostGroupInfo["resourceGroupId"] or 0
            ret_list.append(item)
        return ret_list

    @log_entry_exit
    def validate_namespace_id(self, vol_info):
        namespace_id = vol_info.namespaceId
        if namespace_id is None or namespace_id == "":
            err_msg = VSPTrueCopyValidateMsg.PVOL_NAMESPACE_MISSING.value.format(
                vol_info.ldevId
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def get_secondary_volume_id_when_nvme(self, vol_info, spec):
        logger.writeDebug(
            "PROV:get_secondary_volume_id_when_nvme:vol_info = {}", vol_info
        )
        # capture namespace ID
        pvolNameSpaceId = vol_info.namespaceId
        # pvolNvmSubsystemId = vol_info.nvmSubsystemId

        self.validate_namespace_id(vol_info)
        # if pvolNameSpaceId is None or pvolNameSpaceId == "":
        #     err_msg = VSPTrueCopyValidateMsg.PVOL_NAMESPACE_MISSING.value.format(
        #         vol_info.ldevId
        #     )
        #     logger.writeError(err_msg)
        #     raise ValueError(err_msg)

        logger.writeDebug("PROV: nvmesubsystem spec = {}", spec.secondary_nvm_subsystem)

        # Before creating the secondary volume check if secondary nvmsubsystem exists
        nvme_subsystem = self.get_nvmesubsystem_by_name(spec.secondary_nvm_subsystem)
        if nvme_subsystem is None:
            err_msg = VSPTrueCopyValidateMsg.NO_REMOTE_NVME_FOUND.value.format(
                spec.secondary_nvm_subsystem.name
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        # if int(nvme_subsystem.nvmSubsystemId) != int(pvolNvmSubsystemId):
        #     err_msg = VSPTrueCopyValidateMsg.NVMSUBSYSTEM_DIFFER.value.format(
        #         nvme_subsystem.nvmSubsystemId, pvolNvmSubsystemId
        #     )
        #     logger.writeError(err_msg)
        #     raise ValueError(err_msg)

        svol_id = self.select_secondary_volume_id(vol_info.ldevId, spec)
        sec_vol_spec = self.construct_svol_spec(svol_id, vol_info, spec)

        sec_vol_id = self.vol_gateway.create_volume(sec_vol_spec)
        sec_vol_name = None
        # the name change is done in the update_volume method
        if vol_info.label is not None and vol_info.label != "":
            sec_vol_name = vol_info.label
        else:
            sec_vol_name = f"{DEFAULT_NAME_PREFIX}-{vol_info.ldevId}"

        try:
            self.vol_gateway.change_volume_settings(sec_vol_id, label=sec_vol_name)
            ns_id = self.create_namespace_for_svol(
                nvme_subsystem.nvmSubsystemId, sec_vol_id, None
            )
            ns_id = ns_id.split(",")[-1]
            self.create_namespace_paths(
                nvme_subsystem.nvmSubsystemId,
                ns_id,
                spec.secondary_nvm_subsystem,
            )
        except Exception as ex:
            err_msg = TrueCopyFailedMsg.SEC_VOLUME_OPERATION_FAILED.value + str(ex)
            logger.writeError(err_msg)
            # if setting the volume name fails, delete the secondary volume
            # if attaching the volume to the host group fails, delete the secondary volume
            self.delete_volume_when_nvme(
                sec_vol_id,
                nvme_subsystem.nvmSubsystemId,
                spec.secondary_nvm_subsystem,
                pvolNameSpaceId,
            )
            raise ValueError(err_msg)

        logger.writeDebug(
            "PROV:get_secondary_volume_id:sec_vol_name = {}", sec_vol_name
        )
        # logger.writeDebug("PROV:get_secondary_volume_id:spec = {}", spec)
        # logger.writeDebug("PROV:get_secondary_volume_id:host_group = {}", host_group)

        # self.hg_gateway.add_luns_to_host_group(host_group, [sec_vol_id])
        return sec_vol_id

    @log_entry_exit
    def get_nvmesubsystem_by_name(self, nvmsubsystem):
        nvme_subsystems = self.nvme_gateway.get_nvme_subsystems()
        for nvme in nvme_subsystems.data:
            if nvme.nvmSubsystemName == nvmsubsystem.name:
                logger.writeDebug("PROV:get_nvmesubsystem_by_name:nvme = {}", nvme)
                return nvme
        return None

    @log_entry_exit
    def create_namespace_for_svol(self, nvm_subsystem_id, ldev_id, ns_id):
        ns_id = self.nvme_gateway.create_namespace(nvm_subsystem_id, ldev_id, ns_id)
        logger.writeDebug("PROV:add_svol_to_nvmesubsystem:ns_id = {}", ns_id)
        return ns_id

    @log_entry_exit
    def create_namespace_paths(self, nvm_subsystem_id, namespace_id, nvmsubsystem):
        nqns = []
        if nvmsubsystem.paths is not None:
            nqns = nvmsubsystem.paths
        else:
            host_nqns = self.nvme_gateway.get_host_nqns(nvm_subsystem_id)
            nqns = [nqn.hostNqn for nqn in host_nqns.data]

        for nqn in nqns:
            host_ns_path_id = self.nvme_gateway.set_host_namespace_path(
                nvm_subsystem_id, nqn, namespace_id
            )
            logger.writeDebug(
                "PROV:create_namespace_paths:host_ns_path_id = {}", host_ns_path_id
            )
        return None

    @log_entry_exit
    def delete_ns_path_and_namespace(self, nvm_id, nvmsubsystem, namespace_id):
        nqns = []
        if nvmsubsystem is not None and nvmsubsystem.paths is not None:
            nqns = nvmsubsystem.paths
        else:
            host_nqns = self.nvme_gateway.get_host_nqns(nvm_id)
            nqns = [nqn.hostNqn for nqn in host_nqns.data]

        for nqn in nqns:
            self.nvme_gateway.delete_host_namespace_path(nvm_id, nqn, namespace_id)

        self.nvme_gateway.delete_namespace(nvm_id, namespace_id)

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
        self.delete_actual_volume(secondary_vol_id, volume)

    @log_entry_exit
    def get_secondary_hg_payload(self, hg):
        ret_list = []
        item = {}
        item["hostGroupID"] = hg.hostGroupInfo["hostGroupId"]
        item["name"] = hg.hostGroupInfo["hostGroupName"]
        item["port"] = hg.hostGroupInfo["port"]
        item["resourceGroupID"] = hg.hostGroupInfo["resourceGroupId"] or 0
        ret_list.append(item)
        return ret_list

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
    def get_hgs_for_provisioned_svol(self, volume, is_iscsi=False):
        hostgroups = []
        iscsi_targets = []
        if volume.numOfPorts is not None and volume.numOfPorts > 0:
            logger.writeDebug(
                "PROV:get_hgs_for_provisioned_svol:ports={}", volume.ports
            )
            for port in volume.ports:
                port_type = self.get_port_type(port["portId"])
                port_details = self.hg_prov.get_one_host_group_using_hg_port_id(
                    port["portId"], port["hostGroupNumber"]
                )
                logger.writeDebug(
                    "PROV:get_hgs_for_provisioned_svol:port_details={}", port_details
                )
                hg_name = (
                    port_details.hostGroupName
                    if port_details
                    else port["hostGroupName"]
                )
                port_details.hostGroupName = hg_name
                if port_type == "ISCSI":
                    iscsi_targets.append(port_details)
                elif port_type == "FIBRE":
                    hostgroups.append(port_details)
                else:
                    pass
        if is_iscsi:
            return iscsi_targets
        else:
            return hostgroups

    @log_entry_exit
    def get_port_type(self, port_id):
        return self.port_prov.get_port_type(port_id)

    @log_entry_exit
    def find_hgs_to_add_for_provisioned_svol(self, hgs_from_spec, hgs_for_prov_svol):
        hgs_to_attach = []
        if hgs_from_spec is None:
            return None

        if hgs_for_prov_svol is None:
            return None

        hg_map = {}
        for hg in hgs_for_prov_svol:
            key = f"{hg.portId},{hg.hostGroupId}"
            hg_map[key] = hg

        for hg in hgs_from_spec:
            key = f"{hg.port},{hg.hostGroupId}"
            value = hg_map.get(key, None)
            if value is None:
                hgs_to_attach.append(hg)

        return hgs_to_attach

    @log_entry_exit
    def find_lun_ids_from_spec(self, hostgroups, spec_sec_hgs, is_iscsi=False):

        logger.writeDebug(f"hostgroups={hostgroups}")
        logger.writeDebug(f"spec_sec_hgs={spec_sec_hgs}")
        hg_map = {}
        for spec_hg in spec_sec_hgs:
            hg_map[spec_hg.name] = spec_hg

        logger.writeDebug(f"hg_map={hg_map}")
        lun_ids = {}
        for hg in hostgroups:
            hg_name = None
            if is_iscsi:
                hg_name = hg.iscsiName
            else:
                hg_name = hg.hostGroupName
            spec_hg = hg_map.get(hg_name, None)
            if spec_hg is None:
                raise ValueError(
                    f"Something went wrong, could not find the hostgroup or iscsi with name {hg_name} specified in the spec."
                )

            lun_ids[spec_hg.name] = spec_hg.lun_id

        return lun_ids
