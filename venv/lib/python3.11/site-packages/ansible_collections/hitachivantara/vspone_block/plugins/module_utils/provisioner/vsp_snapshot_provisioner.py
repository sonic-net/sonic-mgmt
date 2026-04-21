from typing import Optional, Any
import time
from typing import List, Dict

try:
    from ..common.ansible_common import log_entry_exit, volume_id_to_hex_format
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.vsp_constants import AutomationConstants
    from ..common.vsp_constants import (
        PairStatus,
        VolumePayloadConst,
        DEFAULT_NAME_PREFIX,
    )
    from ..message.vsp_snapshot_msgs import VSPSnapShotValidateMsg
    from ..model.vsp_volume_models import (
        CreateVolumeSpec,
    )
    from ..model.vsp_host_group_models import VSPHostGroupInfo
    from .vsp_nvme_provisioner import VSPNvmeProvisioner
    from ..model.vsp_snapshot_models import (
        DirectSnapshotsInfo,
        DirectSnapshotInfo,
        UAIGSnapshotInfo,
    )
    from .vsp_volume_prov import VSPVolumeProvisioner
    from .vsp_host_group_provisioner import VSPHostGroupProvisioner
    from .vsp_iscsi_target_provisioner import VSPIscsiTargetProvisioner
    from .vsp_storage_port_provisioner import VSPStoragePortProvisioner

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.vsp_constants import AutomationConstants
    from common.vsp_constants import PairStatus, VolumePayloadConst, DEFAULT_NAME_PREFIX
    from message.vsp_snapshot_msgs import VSPSnapShotValidateMsg
    from model.vsp_volume_models import (
        CreateVolumeSpec,
    )
    from .vsp_volume_prov import VSPVolumeProvisioner
    from .vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from .vsp_host_group_provisioner import VSPHostGroupProvisioner
    from .vsp_iscsi_target_provisioner import VSPIscsiTargetProvisioner
    from .vsp_nvme_provisioner import VSPNvmeProvisioner
    from common.ansible_common import log_entry_exit, volume_id_to_hex_format
    from model.vsp_host_group_models import VSPHostGroupInfo
    from model.vsp_snapshot_models import (
        DirectSnapshotsInfo,
        DirectSnapshotInfo,
        UAIGSnapshotInfo,
    )


# @LogDecorator.debug_methods
class VSPHtiSnapshotProvisioner:
    def __init__(self, connection_info, serial=None):
        self.logger = Log()
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_SNAPSHOT
        )
        self.connection_info = connection_info
        self.vol_provisioner = VSPVolumeProvisioner(self.connection_info)
        self.hg_prov = VSPHostGroupProvisioner(self.connection_info)
        # self.nvme_provisioner = VSPNvmeProvisioner(self.connection_info, self.serial)
        self.port_prov = VSPStoragePortProvisioner(self.connection_info)
        self.serial_number = serial

    @log_entry_exit
    def get_snapshot_facts(
        self, pvol: Optional[int] = None, mirror_unit_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        resp = self.gateway.get_all_snapshots(pvol, mirror_unit_id)
        new_resp = self.fill_additional_info_for_snapshots(resp.data)
        return new_resp.data_to_list()

    @log_entry_exit
    def get_one_snapshot(self, pvol: int, mirror_unit_id: int):

        try:
            resp = self.gateway.get_one_snapshot(pvol, mirror_unit_id)
            resp = self.fill_nvm_subsystem_info_for_one_snapshot(resp)
            return self.fill_host_group_info_for_one_snapshot(resp)
        except Exception as e:
            self.logger.writeError(f"An error occurred: {str(e)}")
            if "404" in str(e) or "Specified object does not exist" in str(e):
                msg = f"Snapshot Pair with Primary volume Id {pvol} and Mirror unit Id {mirror_unit_id} is not present"
                raise ValueError(msg)
            else:
                raise ValueError(str(e))

    @log_entry_exit
    # this version of the get_one_snapshot will return None instead of raising an exception,
    # if the snapshot does not exist
    def get_one_snapshot_if_exist(self, pvol: int, mirror_unit_id: int):

        try:
            resp = self.gateway.get_one_snapshot(pvol, mirror_unit_id)
            resp = self.fill_nvm_subsystem_info_for_one_snapshot(resp)
            return self.fill_host_group_info_for_one_snapshot(resp)
        except Exception as e:
            self.logger.writeError(f"ok if not exist: {str(e)}")
            if "404" in str(e) or "Specified object does not exist" in str(e):
                return None
            else:
                raise ValueError(str(e))

    @log_entry_exit
    def fill_host_group_info_for_one_snapshot(self, snapshot):
        self.logger.writeDebug(f"snapshot_pair= {snapshot}")
        pvol = snapshot.pvolLdevId
        svol = snapshot.svolLdevId
        if pvol:
            snapshot.pvolHostGroups = self.host_group_for_ldev_id(pvol)
        if svol:
            snapshot.svolHostGroups = self.host_group_for_ldev_id(svol)

        return snapshot

    @log_entry_exit
    def fix_host_group_names(self, vol_ports):
        if vol_ports is None:
            return
        hg_provisioner = VSPHostGroupProvisioner(self.connection_info)
        for port in vol_ports:
            self.logger.writeDebug("20250324 port={}", port)
            hg = hg_provisioner.get_one_host_group_using_hg_port_id(
                port["portId"], port["hostGroupNumber"]
            )
            self.logger.writeDebug("20250324 hg={}", hg)
            if hg is None:
                continue
            port["hostGroupName"] = hg.hostGroupName

        return

    @log_entry_exit
    def host_group_for_ldev_id(self, ldev_id):
        volume = self.vol_provisioner.get_volume_by_ldev(ldev_id)
        self.logger.writeDebug(
            "PROV:20250324 volume = {}",
            volume,
        )

        if volume:
            # get the full hg name
            # self.fix_host_group_names(volume.ports)
            return volume.ports

    @log_entry_exit
    def fill_additional_info_for_snapshots(self, snapshots):
        self.logger.writeDebug(f"snapshots= {snapshots}")
        new_snapshots = []
        for sn in snapshots:
            new_sn = self.fill_nvm_subsystem_info_for_one_snapshot(sn)
            new_sn = self.fill_host_group_info_for_one_snapshot(new_sn)
            new_snapshots.append(new_sn)
        return DirectSnapshotsInfo(data=new_snapshots)

    @log_entry_exit
    def fill_nvm_subsystem_info_for_snapshots(self, snapshots):
        self.logger.writeDebug(
            f"fill_nvm_subsystem_info_for_snapshots:snapshots= {snapshots}"
        )
        new_snapshots = []
        for sn in snapshots:
            new_sn = self.fill_nvm_subsystem_info_for_one_snapshot(sn)
            new_snapshots.append(new_sn)
        return DirectSnapshotsInfo(data=new_snapshots)

    @log_entry_exit
    def fill_nvm_subsystem_info_for_one_snapshot(self, snapshot):
        self.logger.writeDebug(
            f"fill_nvm_subsystem_info_for_one_snapshot:shadow_image_pair= {snapshot}"
        )
        pvol = snapshot.pvolLdevId
        svol = snapshot.svolLdevId
        if pvol:
            snapshot.pvolNvmSubsystemName = self.nvm_subsystem_name_for_ldev_id(pvol)
        if svol:
            snapshot.svolNvmSubsystemName = self.nvm_subsystem_name_for_ldev_id(svol)

        return snapshot

    @log_entry_exit
    def nvm_subsystem_name_for_ldev_id(self, ldev_id):
        volume = self.vol_provisioner.get_volume_by_ldev(ldev_id)
        if volume.nvmSubsystemId:
            nvm_subsystem_name = self.get_nvm_subsystem_name(volume)
            self.logger.writeDebug(
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
        self.logger.writeDebug("PROV:get_nvm_subsystem_info:nvm_subsystem = {}", nvm_ss)

        return nvm_ss.nvmSubsystemName

    @log_entry_exit
    def validate_create_spec(self, spec: Any) -> None:
        if spec.mirror_unit_id:
            mu = spec.mirror_unit_id
            if mu < 0 or mu > AutomationConstants.LDEV_MAX_MU_NUMBER:
                err_msg = VSPSnapShotValidateMsg.MU_VALID_RANGE.value
                self.logger.writeError(err_msg)
                raise ValueError(err_msg)

    @log_entry_exit
    def create_snapshot(self, spec):
        self.validate_create_spec(spec)
        if spec.mirror_unit_id:
            ssp = self.get_one_snapshot_if_exist(spec.pvol, spec.mirror_unit_id)
            if ssp:
                return self.add_remove_svol_to_snapshot(spec, ssp)

        # this function only deals with creating new pair
        self.logger.writeDebug(f"20250324 spec: {spec}")

        if spec.pvol is None:
            err_msg = VSPSnapShotValidateMsg.PVOL_NOT_FOUND.value
            raise ValueError("The primary volume parameter is not found")

        # the pool_id is not required for the new snapshot creation
        # if none, use the pvol pool_id
        if spec.pool_id is None:
            pvol = self.vol_provisioner.get_volume_by_ldev(spec.pvol)
            self.logger.writeDebug(f"20250324 pvol: {pvol}")
            if pvol.emulationType == VolumePayloadConst.NOT_DEFINED:
                err_msg = VSPSnapShotValidateMsg.PVOL_NOT_FOUND.value
                self.logger.writeError(err_msg)
                raise ValueError(err_msg)
            if pvol.poolId is None:
                err_msg = "The pool id is not found for the primary volume"
                self.logger.writeError(err_msg)
                raise ValueError(err_msg)
            else:
                spec.pool_id = pvol.poolId

        self.logger.writeDebug(f"20250324 spec: {spec}")
        if spec.snapshot_group_name is None:
            err_msg = VSPSnapShotValidateMsg.SNAPSHOT_GRP_NAME.value
            self.logger.writeError(err_msg)
            raise ValueError(err_msg)

        return self.process_svol(spec)

    @log_entry_exit
    def delete_nvmss_namespace(self, id, svol):
        self.logger.writeDebug(f"20250324 svol: {svol}")
        nvm_provisioner = VSPNvmeProvisioner(self.connection_info)
        nvm_ss = nvm_provisioner.get_nvme_subsystem_by_id(svol.nvmSubsystemId)
        if nvm_ss is None:
            return
        self.logger.writeDebug(f"20250324 nvme: {nvm_ss}")
        for ns in nvm_ss.namespaces:
            if ns["ldevId"] != id:
                continue
            namespace_id = ns["namespaceId"]
            self.logger.writeDebug(
                f"20250324 svol.nvmSubsystemId: {svol.nvmSubsystemId}"
            )
            self.logger.writeDebug(f"20250324 namespaceId: {namespace_id}")
            nvm_provisioner.delete_namespace(svol.nvmSubsystemId, namespace_id)

    @log_entry_exit
    def delete_svol_force(self, ssp):
        self.logger.writeDebug(f"20250324 ssp: {ssp}")
        if ssp.svolLdevId is None:
            # floating snapshot
            return
        svol = self.vol_provisioner.get_volume_by_ldev(ssp.svolLdevId)
        self.delete_nvmss_namespace(ssp.svolLdevId, svol)
        if svol.ports is not None and len(svol.ports) > 0:
            for hg_info in svol.ports:
                self.logger.writeDebug(f"20250324 hg_info: {hg_info}")
                port_type = self.get_port_type(hg_info["portId"])
                if port_type == "ISCSI":
                    hg_provisioner = VSPIscsiTargetProvisioner(self.connection_info)
                    # get the hg with the full name
                    hg = hg_provisioner.get_iscsi_target_by_id(
                        hg_info["portId"], hg_info["hostGroupNumber"]
                    )
                    self.logger.writeDebug(f"20250324 hg: {hg}")
                    # get the hg with the attached luns info
                    hg = hg_provisioner.get_one_iscsi_target(
                        hg_info["portId"], hg.iscsiName, None
                    ).data
                    self.logger.writeDebug(f"20250324 hg: {hg}")
                    hg_provisioner.delete_luns_from_iscsi_target(
                        hg, luns=[ssp.svolLdevId], serial=None
                    )
                else:

                    # option #1
                    # hg_provisioner = VSPHostGroupProvisioner(self.connection_info)
                    # this call is getting 500 since its trying to get all hgs
                    # hg = hg_provisioner.get_one_host_group_using_hg_port_id(
                    #     hg_info["portId"], hg_info["hostGroupNumber"]
                    # )
                    # self.logger.writeDebug(f"20250324 hg: {hg}")
                    # hg = hg_provisioner.get_one_host_group(
                    #     hg_info["portId"], hg.hostGroupName, None).data
                    # # we need the hg with the full name
                    # self.logger.writeDebug(f"20250324 hg: {hg}")
                    # # unpresent the svol from the host group
                    # hg_provisioner.delete_luns_from_host_group(hg, luns=[ssp.svolLdevId])

                    # option #2, the hostGroupName is incomplete from pf-rest
                    # hg_provisioner = VSPHostGroupProvisioner(self.connection_info)
                    # for hg_info in svol.ports:
                    #     hg = hg_provisioner.get_one_host_group(
                    #         hg_info["portId"], hg_info["hostGroupName"]
                    #     ).data
                    #     self.logger.writeDebug(f"20250324 hg_info: {hg_info}")
                    #     self.logger.writeDebug(f"20250324 hg: {hg}")
                    #     hg_provisioner.delete_luns_from_host_group(hg, luns=[ssp.svolLdevId])

                    hg_provisioner = VSPHostGroupProvisioner(self.connection_info)
                    # query for the hg.lunPaths
                    hgs = hg_provisioner.get_host_groups(
                        None, None, volume_id_to_hex_format(ssp.svolLdevId), ["ldev"]
                    )
                    for hg_info in svol.ports:
                        for hg in hgs.data:
                            # the name in hg_info is not the full name, its 16 char max
                            self.logger.writeDebug(f"20250324 this hg_info: {hg_info}")
                            if hg.hostGroupId != hg_info["hostGroupNumber"]:
                                continue
                            if hg.port != hg_info["portId"]:
                                continue
                            self.logger.writeDebug(
                                f"20250324 that hg: {hg.hostGroupId}"
                            )
                            self.logger.writeDebug(f"20250324 that hg: {hg.port}")
                            self.logger.writeDebug(
                                f"20250324 that hg.lunPaths: {hg.lunPaths}"
                            )
                            self.logger.writeDebug(
                                f"20250324 that hg full name: {hg.hostGroupName}"
                            )
                            hg_provisioner.delete_luns_from_host_group(
                                hg, luns=[ssp.svolLdevId]
                            )

        # delete the svol
        force_execute = (
            True
            if svol.dataReductionMode
            and svol.dataReductionMode.lower() != VolumePayloadConst.DISABLED
            else None
        )
        self.logger.writeDebug(f"20250324 force_execute: {force_execute}")
        self.vol_provisioner.delete_volume(ssp.svolLdevId, force_execute)

    @log_entry_exit
    def check_for_pegasus(self, ssp):
        if self.gateway.is_pegasus() and ssp.status != PairStatus.PSUS:
            err_msg = "For VSP One B Series, assigning VVOL to ThinImage pair requires PSUS status."
            self.logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def add_remove_svol_to_snapshot(self, spec, ssp):
        if spec.svol is not None and spec.svol == -1 and ssp.svolLdevId is not None:
            self.gateway.unassign_svol_to_snapshot(spec.pvol, spec.mirror_unit_id)
            self.delete_svol_force(ssp)
            self.connection_info.changed = True
        elif spec.svol is not None and spec.svol >= 0 and ssp.svolLdevId is None:
            # assign svol to the floating snapshot
            self.check_for_pegasus(ssp)
            svol_id, port = self.create_snapshot_svol(spec)
            self.gateway.assign_svol_to_snapshot(
                spec.pvol, spec.mirror_unit_id, svol_id
            )
            self.connection_info.changed = True
        elif (
            ssp.svolLdevId is not None
            and spec.svol is not None
            and spec.svol != ssp.svolLdevId
        ):
            #  remove the svol from the snapshot first then assign
            self.check_for_pegasus(ssp)
            self.gateway.unassign_svol_to_snapshot(spec.pvol, spec.mirror_unit_id)
            self.delete_svol_force(ssp)
            #  assign the new svol to the snapshot
            self.gateway.assign_svol_to_snapshot(
                spec.pvol, spec.mirror_unit_id, spec.svol
            )
            self.connection_info.changed = True

        if spec.retention_period is not None:
            self.add_retention_period(
                spec.retention_period, snapshot_id=f"{spec.pvol},{spec.mirror_unit_id}"
            )
            self.connection_info.changed = True

        return (
            self.get_one_snapshot(spec.pvol, spec.mirror_unit_id)
            if self.connection_info.changed
            else ssp
        )

    @log_entry_exit
    def add_retention_period(self, retention_period, snapshot_id=None, group_id=None):
        try:
            if snapshot_id is not None:
                self.gateway.set_snapshot_retention_period(
                    snapshot_id, retention_period
                )
            elif group_id is not None:
                self.gateway.set_snapshot_retention_period_for_group(
                    group_id, retention_period
                )

        except Exception as e:
            if "KART20009-E" in str(
                e
            ) or "No resource exists at the specified URL. (URL" in str(e):
                msg = (
                    f"Add retention period failed for snapshot id {snapshot_id} or group id {group_id}",
                    "Check if the storage system is VSP One B20 and the pair status is PSUS.",
                )
                self.logger.writeWarning(msg)

            else:
                raise e
        return

    @log_entry_exit
    def create_direct_snapshot_floating(self, spec):
        self.logger.writeDebug(f"20250324 spec: {spec}")
        try:
            result = self.gateway.create_snapshot(
                spec.pvol,
                spec.pool_id,
                spec.allocate_consistency_group,
                spec.snapshot_group_name,
                spec.auto_split,
                spec.is_data_reduction_force_copy,
                spec.can_cascade,
                None,
                spec.is_clone,
                spec.mirror_unit_id,
                spec.retention_period,
                spec.copy_speed,
                spec.clones_automation,
            )
        except Exception as e:
            self.logger.writeException(e)
            raise e
        self.logger.writeDebug(f"20250324 mirror_unit_id and pvol_id: {result}")
        mu_id = result.split(",")[1]

        try:
            ssp = self.get_one_snapshot(spec.pvol, mu_id)
        except Exception as e:
            if (
                "Snapshot Pair with Primary volume Id" in str(e)
                and "not present" in str(e)
                and spec.is_clone is True
            ):
                msg = "Snapshot cloned successfully"
                return msg
            else:
                self.logger.writeException(e)
                raise e

        self.connection_info.changed = True
        self.logger.writeDebug(f"20250324 ssp: {ssp}")
        return ssp

    @log_entry_exit
    def process_svol(self, spec, ssp=None):
        svol_id = spec.svol
        # 4 cases for svol_id:
        #
        # 1. svol is undefined - create a new volume using the svol_id
        # 2. svol is defined - validate then use it to create snapshot
        # 3. svol is -1 - create/unassign floating volume snapshot
        # 4. svol_id is None - create a new volume and use it to create snapshot

        if svol_id is None:
            return self.create_snapshot_auto_svol(spec)

        if svol_id == -1:
            # case 3, create floating snapshot
            return self.create_direct_snapshot_floating(spec)

        # m.id not given, only pvol and svol, idempotent check before creating snapshot
        rsp = self.gateway.get_snapshot_by_pvol(spec.pvol)
        for ssp in rsp.data:
            self.logger.writeDebug(f"20250324 ssp: {ssp}")
            if ssp.svolLdevId == svol_id:
                # changed = False
                resp = self.fill_nvm_subsystem_info_for_one_snapshot(ssp)
                return self.fill_host_group_info_for_one_snapshot(resp)

        return self.create_snapshot_auto_svol(spec)

    @log_entry_exit
    def create_snapshot_auto_svol(self, spec):
        self.logger.writeDebug(f"20250324 spec: {spec}")
        svol_id, port = self.create_snapshot_svol(spec)
        try:
            result = self.gateway.create_snapshot(
                spec.pvol,
                spec.pool_id,
                spec.allocate_consistency_group,
                spec.snapshot_group_name,
                spec.auto_split,
                spec.is_data_reduction_force_copy,
                spec.can_cascade,
                svol_id,
                spec.is_clone,
                spec.mirror_unit_id,
                spec.retention_period,
                spec.copy_speed,
                spec.clones_automation,
            )
        except Exception as e:

            # fix uca-3157, we want to show the error message from create_snapshot
            try:
                if port:
                    self.vol_provisioner.delete_lun_path(port)
                self.vol_provisioner.delete_volume(
                    svol_id, spec.is_data_reduction_force_copy
                )
            except Exception as e2:
                self.logger.writeDebug(
                    f"Exception in create_snapshot failure cleanup: {str(e2)}"
                )

            self.logger.writeException(e)
            raise e
        self.logger.writeDebug(f"mirror_unit_id and pvol_id: {result}")
        mu_id = result.split(",")[1]

        try:
            ssp = self.get_one_snapshot(spec.pvol, mu_id)
        except Exception as e:
            if (
                "Snapshot Pair with Primary volume Id" in str(e)
                and "not present" in str(e)
                and spec.is_clone is True
            ):
                msg = "Snapshot cloned successfully"
                return msg
            else:
                self.logger.writeException(e)
                raise e
        self.connection_info.changed = True
        return ssp

    @log_entry_exit
    def is_volume_defined(self, svol_id):
        if svol_id is None or svol_id == -1:
            return False, None
        svol = self.vol_provisioner.get_volume_by_ldev(svol_id)
        self.logger.writeDebug(f"20250324 svol: {svol}")
        if svol is None:
            return False, None
        if svol.emulationType != "NOT DEFINED":
            return True, svol
        return False, None

    @log_entry_exit
    def create_snapshot_svol(self, spec):
        is_compression_acceleration_enabled = False
        hg_info = None
        svol_id = spec.svol
        self.logger.writeDebug(f"20250324 svol_id: {svol_id}")
        hg_provisioner = VSPHostGroupProvisioner(self.connection_info)

        pvol = self.vol_provisioner.get_volume_by_ldev(spec.pvol)
        if pvol.emulationType == VolumePayloadConst.NOT_DEFINED:
            err_msg = VSPSnapShotValidateMsg.PVOL_NOT_FOUND.value
            self.logger.writeError(err_msg)
            raise ValueError(err_msg)

        # Check if vvol or normal lun is required to create
        pool_id = (
            pvol.poolId
            if pvol.dataReductionMode
            and pvol.dataReductionMode != VolumePayloadConst.DISABLED
            else -1
        )
        capacity_saving = (
            pvol.dataReductionMode
            if pvol.dataReductionMode
            and pvol.dataReductionMode != VolumePayloadConst.DISABLED
            else VolumePayloadConst.DISABLED
        )
        if capacity_saving != VolumePayloadConst.DISABLED:
            is_compression_acceleration_enabled = pvol.isCompressionAccelerationEnabled

        data_reduction_share = (
            pvol.isDataReductionShareEnabled
            if pvol.isDataReductionShareEnabled
            else False
        )

        # 1. svol_id is none - same as before, create a new volume
        # 2. svol is defined - use svol, no need to create a new volume
        # 3. svol is not defined - use svol_id to create volume
        svol = None
        defined, svol = self.is_volume_defined(svol_id)

        if defined:
            hg_info = None
            if svol.ports is not None and len(svol.ports) > 0:
                hg_info = svol.ports[0]
            return svol_id, hg_info

        if not defined:
            # create a new volume, svol
            vol_spec = CreateVolumeSpec(
                pool_id=pool_id,
                size=pvol.byteFormatCapacity.replace(" ", "").replace(".00", ""),
                block_size=pvol.blockCapacity,
                data_reduction_share=data_reduction_share,
                capacity_saving=capacity_saving,
                ldev_id=svol_id,
                is_compression_acceleration_enabled=is_compression_acceleration_enabled,
            )
            if svol_id is not None:
                # use the user provided svol_id, a freelun/undefined ldev id
                vol_spec.ldev_id = svol_id
            svol_id = self.vol_provisioner.create_volume(vol_spec)
            self.logger.writeDebug(f"20250324 created_volume: {svol_id}")

        if pvol.label is not None and pvol.label != "":
            svol_name = pvol.label
        else:
            svol_name = f"{DEFAULT_NAME_PREFIX}-{pvol.ldevId}"
        self.vol_provisioner.change_volume_settings(svol_id, name=svol_name)

        # set the data reduction force copy to true
        spec.is_data_reduction_force_copy = (
            True
            if pvol.dataReductionMode
            and pvol.dataReductionMode != VolumePayloadConst.DISABLED
            and spec.is_data_reduction_force_copy is None
            else spec.is_data_reduction_force_copy
        )
        spec.can_cascade = (
            spec.is_data_reduction_force_copy
            if spec.can_cascade is None
            else spec.can_cascade
        )
        if pvol.nvmSubsystemId:
            ns_id = self.create_name_space_for_svol(pvol.nvmSubsystemId, svol_id)
        else:
            if pvol.ports is None and capacity_saving == VolumePayloadConst.DISABLED:
                err_msg = VSPSnapShotValidateMsg.PVOL_IS_NOT_IN_HG.value
                self.logger.writeError(err_msg)
                raise ValueError(err_msg)

            elif pvol.ports is not None and len(pvol.ports) > 0:

                hg_info = pvol.ports[0]
                hg = VSPHostGroupInfo(
                    port=hg_info["portId"], hostGroupId=hg_info["hostGroupNumber"]
                )

                hg_provisioner.add_luns_to_host_group(hg, luns=[svol_id])
                svol = self.vol_provisioner.get_volume_by_ldev(svol_id)
                self.logger.writeDebug(f"20250324 created_volume svol: {svol}")
                if svol.ports:
                    hg_info = svol.ports[0]
            # Assign the svol and pvol to the host group

        return svol_id, hg_info

    @log_entry_exit
    def create_name_space_for_svol(self, nvm_subsystem_id, ldev_id):
        nvm_provisioner = VSPNvmeProvisioner(self.connection_info)
        return nvm_provisioner.create_namespace(nvm_subsystem_id, ldev_id)

    @log_entry_exit
    def find_mirror_unit_id(self, task_info: Dict[str, Any]) -> int:
        for attribute in task_info.get("data", {}).get("additionalAttributes", []):
            if attribute.get("type") == "mirrorUnitId":
                return int(attribute.get("id"))

        #  if mirror unit ID not found yet,
        #  see if it has gone thru entitlement
        return self.get_mirror_unit_id_tagged(task_info)

    @log_entry_exit
    def get_mirror_unit_id_tagged(self, task_response: Dict[str, Any]) -> int:
        self.logger.writeDebug(f"task_response: {task_response}")
        task_events = task_response["data"].get("events")
        if len(task_events):
            snapshot_resourceId = None
            for element in task_events:
                description = element.get("description", "")
                if "Successfully tagged snapshotpair" in description:
                    ss = description.split(" ")
                    snapshot_resourceId = ss[3]
                    break

            if snapshot_resourceId:
                self.logger.writeDebug(f"snapshot_resourceId: {snapshot_resourceId}")
                data = self.gateway.get_one_snapshot_by_resourceId(snapshot_resourceId)
                return int(data.mirrorUnitId)

        err_msg = VSPSnapShotValidateMsg.MIRROR_UNIT_ID_NOT_FOUND.value
        self.logger.writeError(err_msg)
        raise ValueError(err_msg)

    @log_entry_exit
    def auto_split_snapshot(self, spec):
        spec.auto_split = True
        ssp = self.create_snapshot(spec)
        mirror_unit_id = (
            ssp.mirrorUnitId if isinstance(ssp, UAIGSnapshotInfo) else ssp.muNumber
        )
        enable_quick_mode = spec.enable_quick_mode or False
        resp = self.split_snapshot(
            spec.pvol,
            mirror_unit_id,
            enable_quick_mode,
            retention_period=spec.retention_period,
        )

        self.connection_info.changed = True
        return resp

    @log_entry_exit
    def delete_snapshot(self, pvol: int, mirror_unit_id: int):
        try:
            ssp = self.get_one_snapshot(pvol, mirror_unit_id)
        except ValueError as e:
            return str(e)
        self.logger.writeDebug(f"20250324 ssp.svolLdevId: {ssp.svolLdevId}")
        self.gateway.delete_snapshot(pvol, mirror_unit_id)
        self.delete_svol_force(ssp)
        self.connection_info.changed = True
        return

    @log_entry_exit
    def delete_garbage_data_snapshot_tree(self, pvol: int, operation_type: str):
        self.logger.writeDebug(
            f"20250324 delete_garbage_data_snapshot_tree pvol: {pvol}"
        )
        self.gateway.delete_garbage_data_snapshot_tree(pvol, operation_type)
        self.connection_info.changed = True
        return

    @log_entry_exit
    def delete_ti_by_snapshot_tree(self, pvol: int):
        self.logger.writeDebug(f"20250324 delete_ti_by_snapshot_tree pvol: {pvol}")
        self.gateway.delete_ti_by_snapshot_tree(pvol)
        self.connection_info.changed = True
        return

    @log_entry_exit
    def resync_snapshot(self, pvol: int, mirror_unit_id: int, enable_quick_mode: bool):
        ssp = self.get_one_snapshot(pvol, mirror_unit_id)
        if ssp.status == PairStatus.PAIR:
            return ssp
        enable_quick_mode = enable_quick_mode or False
        unused = self.gateway.resync_snapshot(pvol, mirror_unit_id, enable_quick_mode)

        retryCount = 0
        while retryCount < 30:
            ssp = self.get_one_snapshot(pvol, mirror_unit_id)
            if ssp.status == PairStatus.PAIR:
                break
            retryCount = retryCount + 1
            self.logger.writeDebug(f"Polling for resync status: {retryCount}")
            time.sleep(20)

        self.connection_info.changed = True
        return ssp

    @log_entry_exit
    def clone_snapshot(
        self, pvol: int, mirror_unit_id: int, svol: int, copy_speed: str
    ):

        ssp = self.get_one_snapshot(pvol, mirror_unit_id)
        svol = (
            ssp.svolLdevId
            if isinstance(ssp, DirectSnapshotInfo)
            else ssp.secondaryVolumeId
        )
        unused = self.gateway.clone_snapshot(pvol, mirror_unit_id)
        ssp = f"Snapshot cloned successfully to secondary volume {svol}"
        self.connection_info.changed = True
        return ssp

    @log_entry_exit
    def get_snapshot_groups(self):
        return self.gateway.get_snapshot_groups()

    @log_entry_exit
    def get_snapshots_by_grp_name(self, grp_name):
        sgs = self.gateway.get_snapshot_groups()
        for sg in sgs.data:
            if sg.snapshotGroupName == grp_name:
                return self.get_snapshots_by_gid(sg.snapshotGroupId)

    @log_entry_exit
    def get_snapshots_by_gid(self, gid):
        return self.gateway.get_snapshots_using_group_id(gid)

    @log_entry_exit
    def get_snapshot_grp_by_name(self, grp_name):
        sgs = self.gateway.get_snapshot_groups()
        for sg in sgs.data:
            if sg.snapshotGroupName == grp_name:
                return sg

    @log_entry_exit
    def split_snapshots_by_gid(self, spec, first_snapshot):
        if first_snapshot.status == PairStatus.PSUS:
            # UCA-2602 for the case where the snapshot is already in PAIR status, do nothing, removed the check
            pass
        try:
            data = self.gateway.split_snapshot_using_ssg(spec.snapshot_group_id)
        except Exception as e:
            self.logger.writeError(f"An error occurred: {str(e)}")
            if "KART30000-E" in str(e) or "The command ended abnormally" in str(e):
                msg = (
                    f"Split Snapshot Pairs with Snapshot Group Id {spec.snapshot_group_id} failed ",
                    "Check if the snapshot group created in CTG mode or snapshot group contains two or more pairs that have the same volume as the P-VOL.",
                )
                error = {"msg": str(e), "cause": msg}
                raise ValueError(str(error))
            else:
                raise e

        if spec.retention_period is not None:
            self.add_retention_period(
                spec.retention_period, group_id=spec.snapshot_group_id
            )

        self.connection_info.changed = True
        return data

    @log_entry_exit
    def restore_snapshots_by_gid(self, spec, first_snapshot):

        if first_snapshot.status == PairStatus.PAIR:
            # UCA-2602 for the case where the snapshot is already in PAIR status, do nothing, removed the check
            pass
        data = self.gateway.restore_snapshot_using_ssg(
            spec.snapshot_group_id, spec.auto_split
        )
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def resync_snapshots_by_gid(self, spec, first_snapshot):

        if first_snapshot.status == PairStatus.PAIR:
            # UCA-2602 for the case where the snapshot is already in PAIR status, do nothing, removed the check
            pass
        data = self.gateway.resync_snapshot_using_ssg(spec.snapshot_group_id)
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def delete_snapshots_by_gid(self, spec, *args):
        data = self.gateway.delete_snapshot_using_ssg(spec.snapshot_group_id)
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def clone_snapshots_by_gid(self, spec, *args):
        data = self.gateway.clone_snapshot_using_ssg(
            spec.snapshot_group_id, spec.copy_speed
        )
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def split_snapshot(
        self,
        pvol: int,
        mirror_unit_id: int,
        enable_quick_mode: bool,
        retention_period=None,
    ):

        ssp = self.get_one_snapshot(pvol, mirror_unit_id)

        if ssp.status != PairStatus.PSUS:
            enable_quick_mode = enable_quick_mode or False
            unused = self.gateway.split_snapshot(
                pvol, mirror_unit_id, enable_quick_mode
            )

            #  20240816 - SPLIT: poll every 20 seconds for 10 mins for split status before returning
            retryCount = 0
            while retryCount < 30:
                ssp = self.get_one_snapshot(pvol, mirror_unit_id)
                if ssp.status == PairStatus.PSUS:
                    break
                retryCount = retryCount + 1
                self.logger.writeDebug(f"Polling for split status: {retryCount}")
                time.sleep(20)
            self.connection_info.changed = True

        if retention_period:
            if ssp.retentionPeriod != retention_period:
                self.add_retention_period(
                    retention_period, snapshot_id=f"{pvol},{mirror_unit_id}"
                )
                ssp = self.get_one_snapshot(pvol, mirror_unit_id)
                self.connection_info.changed = True

        return ssp

    @log_entry_exit
    def restore_snapshot(
        self, pvol: int, mirror_unit_id: int, enable_quick_mode: bool, auto_split: bool
    ):
        ssp = self.get_one_snapshot(pvol, mirror_unit_id)
        if ssp.status == PairStatus.PAIR and auto_split is not True:
            return ssp
        enable_quick_mode = enable_quick_mode or False
        unused = self.gateway.restore_snapshot(
            pvol=pvol,
            mirror_unit_id=mirror_unit_id,
            enable_quick_mode=enable_quick_mode,
            auto_split=auto_split,
        )

        retryCount = 0
        while retryCount < 3:
            ssp = self.get_one_snapshot(pvol, mirror_unit_id)
            if ssp.status == PairStatus.PAIR:
                break
            retryCount = retryCount + 1
            self.logger.writeDebug(f"Polling for restore status: {retryCount}")
            time.sleep(20)

        self.connection_info.changed = True
        return ssp

    @log_entry_exit
    def get_port_type(self, port_id):
        port_type = self.port_prov.get_port_type(port_id)
        return port_type
