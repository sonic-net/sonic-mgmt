from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass, base_dict_converter
    from ..common.ansible_common import (
        volume_id_to_hex_format,
        normalize_ldev_id,
    )
    from ..model.common_base_models import ConnectionInfo

except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass, base_dict_converter
    from common.ansible_common import (
        volume_id_to_hex_format,
        normalize_ldev_id,
    )
    from model.common_base_models import ConnectionInfo


@dataclass
class GADPairFactSpec:
    primary_volume_id: Optional[int] = None
    secondary_volume_id: Optional[int] = None
    secondary_storage_serial_number: Optional[str] = None
    secondary_connection_info: Optional[ConnectionInfo] = None
    copy_group_name: Optional[str] = None
    copy_pair_name: Optional[str] = None
    local_device_group_name: Optional[str] = None
    remote_device_group_name: Optional[str] = None

    def __post_init__(self, **kwargs):
        if self.secondary_connection_info:
            self.secondary_connection_info = ConnectionInfo(
                **self.secondary_connection_info
            )
        if self.primary_volume_id:
            self.primary_volume_id = normalize_ldev_id(self.primary_volume_id)
        if self.secondary_volume_id:
            self.secondary_volume_id = normalize_ldev_id(self.secondary_volume_id)


@dataclass
class HostgroupSpec:
    id: Optional[int] = None
    name: Optional[str] = None
    lun_id: Optional[int] = None
    enable_preferred_path: Optional[bool] = None
    port: Optional[str] = None
    resource_group_id: Optional[int] = None


@dataclass
class NVMeSubsystemSpec:
    id: Optional[int] = None
    name: Optional[str] = None
    paths: Optional[List[str]] = None


@dataclass
class VspGadPairSpec:
    primary_storage_serial_number: Optional[str] = None
    primary_volume_id: Optional[int] = None
    consistency_group_id: Optional[str] = None
    allocate_new_consistency_group: Optional[bool] = None
    primary_hostgroups: Optional[List[HostgroupSpec]] = None
    secondary_storage_serial_number: Optional[str] = None
    secondary_pool_id: Optional[str] = None
    secondary_hostgroups: Optional[List[HostgroupSpec]] = None
    secondary_iscsi_targets: Optional[List[HostgroupSpec]] = None
    secondary_nvm_subsystem: Optional[NVMeSubsystemSpec] = None
    set_alua_mode: Optional[bool] = None
    primary_resource_group_name: Optional[str] = None
    secondary_resource_group_name: Optional[str] = None
    quorum_disk_id: Optional[str] = None
    remote_ucp_system: Optional[str] = None

    path_group_id: Optional[int] = None
    mu_number: Optional[int] = None
    copy_pace: Optional[str] = None
    copy_pair_name: Optional[str] = None
    copy_group_name: Optional[str] = None
    fence_level: Optional[str] = None
    do_initial_copy: Optional[bool] = None
    is_data_reduction_force_copy: Optional[bool] = None
    is_consistency_group: Optional[bool] = None
    is_new_group_creation: Optional[bool] = None
    secondary_storage_connection_info: Optional[ConnectionInfo] = None
    secondary_connection_info: Optional[ConnectionInfo] = None
    local_device_group_name: Optional[str] = None
    remote_device_group_name: Optional[str] = None
    remote_connection_info: Optional[ConnectionInfo] = None
    new_volume_size: Optional[str] = None
    begin_secondary_volume_id: Optional[int] = None
    end_secondary_volume_id: Optional[int] = None
    is_svol_readwriteable: Optional[bool] = False
    should_delete_svol: Optional[bool] = False
    provisioned_secondary_volume_id: Optional[int] = None

    def __post_init__(self, **kwargs):
        if self.primary_hostgroups:
            self.primary_hostgroups = [
                HostgroupSpec(**x) for x in self.primary_hostgroups
            ]
        if self.secondary_hostgroups:
            self.secondary_hostgroups = [
                HostgroupSpec(**x) for x in self.secondary_hostgroups
            ]
        if self.secondary_iscsi_targets:
            self.secondary_iscsi_targets = [
                HostgroupSpec(**x) for x in self.secondary_iscsi_targets
            ]
        if self.secondary_storage_connection_info:
            self.secondary_storage_connection_info = ConnectionInfo(
                **self.secondary_storage_connection_info
            )
        if self.secondary_connection_info:
            self.secondary_connection_info = ConnectionInfo(
                **self.secondary_connection_info
            )
        if self.remote_connection_info:
            self.remote_connection_info = ConnectionInfo(**self.remote_connection_info)
        if self.secondary_nvm_subsystem:
            self.secondary_nvm_subsystem = NVMeSubsystemSpec(
                **self.secondary_nvm_subsystem
            )
        if self.primary_volume_id:
            self.primary_volume_id = normalize_ldev_id(self.primary_volume_id)
        if self.begin_secondary_volume_id:
            self.begin_secondary_volume_id = normalize_ldev_id(
                self.begin_secondary_volume_id
            )
        if self.end_secondary_volume_id:
            self.end_secondary_volume_id = normalize_ldev_id(
                self.end_secondary_volume_id
            )
        if self.provisioned_secondary_volume_id:
            self.provisioned_secondary_volume_id = normalize_ldev_id(
                self.provisioned_secondary_volume_id
            )


@dataclass
class VspGadPairInfo(SingleBaseClass):
    resourceId: Optional[str] = None
    consistencyGroupId: Optional[int] = None
    copyPaceTrackSize: Optional[int] = None
    copyRate: Optional[int] = None
    mirrorUnitId: Optional[int] = None
    pairName: Optional[str] = None
    primaryHexVolumeId: Optional[str] = None
    primaryVSMResourceGroupName: Optional[str] = None
    primaryVirtualHexVolumeId: Optional[str] = None
    primaryVirtualStorageId: Optional[str] = None
    primaryVirtualVolumeId: Optional[int] = None
    primaryVolumeId: Optional[int] = None
    primaryVolumeStorageId: Optional[int] = None
    secondaryHexVolumeId: Optional[str] = None
    secondaryVSMResourceGroupName: Optional[str] = None
    secondaryVirtualHexVolumeId: Optional[str] = None
    secondaryVirtualStorageId: Optional[str] = None
    secondaryVirtualVolumeId: Optional[int] = None
    secondaryVolumeId: Optional[int] = None
    secondaryVolumeStorageId: Optional[int] = None
    status: Optional[str] = None
    svolAccessMode: Optional[str] = None
    type: Optional[str] = None
    # entitlementStatus: Optional[str] = None
    storageId: Optional[str] = None
    # subscriberId: Optional[str] = None
    # partnerId: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        gadPairInfo = kwargs.get("gadPairInfo")
        if gadPairInfo:
            for key, value in gadPairInfo.items():
                # if not hasattr(self, key):
                setattr(self, key, value)
            if gadPairInfo.get("secondaryVirtualVolumeId"):
                self.secondaryVirtualHexVolumeId = volume_id_to_hex_format(
                    gadPairInfo.get("secondaryVirtualVolumeId")
                ).upper()

    def to_dict(self):

        data = base_dict_converter(self)
        if data.get("storage_id"):
            data.pop("storage_id", None)
        if data.get("resourceId"):
            data.pop("resourceId", None)
        # data["primary_vsm_resource_group_name"] = data.pop("primary_vsmresource_group_name", None)
        return data


@dataclass
class VspGadPairsInfo(BaseDataClass):
    data: List[VspGadPairInfo] = None


#  sng1104
@dataclass
class DirectGadPairInfo(SingleBaseClass):
    replicationType: str
    ldevId: int
    remoteSerialNumber: str
    remoteStorageTypeId: str
    remoteLdevId: int
    primaryOrSecondary: str
    muNumber: int
    status: str
    isSSWS: bool
    createdLocalTime: str
    quorumDiskId: int
    suspendedMode: str


@dataclass
class DirectGadPairInfoList(BaseDataClass):
    data: List[DirectGadPairInfo]
