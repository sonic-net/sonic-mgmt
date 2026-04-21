from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id
    from .vsp_true_copy_models import DirectTrueCopyPairInfo, DirectTrueCopyPairInfoList
    from ..model.common_base_models import ConnectionInfo

except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id
    from .vsp_true_copy_models import DirectTrueCopyPairInfo, DirectTrueCopyPairInfoList
    from model.common_base_models import ConnectionInfo


@dataclass
class HurHostGroupSpec:
    # id: int = None
    name: str = None
    port: str = None
    lun_id: Optional[int] = None
    # resource_group_id: Optional[int] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class NVMeSubsystemSpec:
    id: Optional[int] = None
    name: Optional[str] = None
    paths: Optional[List[str]] = None

    def to_dict(self):
        return asdict(self)


#  20240812 tag.HUR
@dataclass
class HurFactSpec(SingleBaseClass):
    primary_volume_id: Optional[int] = None
    secondary_volume_id: Optional[int] = None
    pvol: Optional[int] = None
    mirror_unit_id: Optional[int] = None

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
class HurSpec(SingleBaseClass):
    primary_volume_id: Optional[int] = None
    secondary_volume_id: Optional[int] = None
    copy_group_name: Optional[str] = None
    copy_pair_name: Optional[str] = None
    fence_level: Optional[str] = None
    local_device_group_name: Optional[str] = None
    remote_device_group_name: Optional[str] = None
    do_initial_copy: Optional[bool] = None
    is_data_reduction_force_copy: Optional[bool] = None
    consistency_group_id: Optional[int] = None
    enable_delta_resync: Optional[bool] = None
    allocate_new_consistency_group: Optional[bool] = None
    secondary_storage_serial_number: Optional[int] = None
    secondary_pool_id: Optional[int] = None
    secondary_hostgroups: Optional[List[HurHostGroupSpec]] = None
    secondary_iscsi_targets: Optional[List[HurHostGroupSpec]] = None
    secondary_nvm_subsystem: Optional[NVMeSubsystemSpec] = None
    primary_volume_journal_id: Optional[int] = None
    secondary_volume_journal_id: Optional[int] = None
    mirror_unit_id: Optional[int] = None
    do_delta_resync_suspend: Optional[bool] = None
    is_new_group_creation: Optional[bool] = None
    secondary_connection_info: Optional[ConnectionInfo] = None
    # remote_connection_info: Optional[ConnectionInfo] = None
    # secondary_storage_connection_info: Optional[ConnectionInfo] = None
    is_svol_readwriteable: Optional[bool] = False
    svolOperationMode: Optional[str] = None
    doSwapSvol: Optional[bool] = None
    new_volume_size: Optional[str] = None
    begin_secondary_volume_id: Optional[int] = None
    end_secondary_volume_id: Optional[int] = None
    path_group_id: Optional[int] = None
    should_delete_svol: Optional[bool] = False
    provisioned_secondary_volume_id: Optional[int] = None

    # Making a single hg
    secondary_hostgroup: Optional[HurHostGroupSpec] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if (
            "secondary_hostgroup" in kwargs
            and kwargs.get("secondary_hostgroup") is not None
        ):
            self.secondary_hostgroup = [
                HurHostGroupSpec(**kwargs.get("secondary_hostgroup"))
            ]
        if (
            "secondary_hostgroups" in kwargs
            and kwargs.get("secondary_hostgroups") is not None
        ):
            self.secondary_hostgroups = [
                HurHostGroupSpec(**x) for x in self.secondary_hostgroups
            ]
        if (
            "secondary_iscsi_targets" in kwargs
            and kwargs.get("secondary_iscsi_targets") is not None
        ):
            self.secondary_iscsi_targets = [
                HurHostGroupSpec(**x) for x in self.secondary_iscsi_targets
            ]
        if (
            "secondary_nvm_subsystem" in kwargs
            and kwargs.get("secondary_nvm_subsystem") is not None
        ):
            self.secondary_nvm_subsystem = NVMeSubsystemSpec(
                **kwargs.get("secondary_nvm_subsystem")
            )

        if self.primary_volume_id:
            self.primary_volume_id = normalize_ldev_id(self.primary_volume_id)
        if self.secondary_volume_id:
            self.secondary_volume_id = normalize_ldev_id(self.secondary_volume_id)
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
class VSPHurPairInfo(SingleBaseClass):
    resourceId: str
    consistencyGroupId: int
    copyRate: int
    fenceLevel: str
    mirrorUnitId: int
    pairName: str
    primaryVolumeId: int

    primaryVolumeStorageId: int
    secondaryVolumeId: int

    secondaryVolumeStorageId: int
    status: str
    svolAccessMode: str
    type: str

    # primaryHexVolumeId: Optional[str] = None
    # secondaryHexVolumeId: Optional[str] = None
    entitlementStatus: Optional[str] = None
    partnerId: Optional[str] = None
    subscriberId: Optional[str] = None
    primaryJournalPoolId: Optional[int] = None
    secondaryJournalPoolId: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        #  20240814 Porcelain DTO: VSPHurPairInfo
        #  hur_pair_info is from v3 response
        hur_pair_info = kwargs.get("hurPairInfo")

        #  flattern the struct from v3
        if hur_pair_info:
            for field in self.__dataclass_fields__.keys():
                if not getattr(self, field):
                    setattr(self, field, hur_pair_info.get(field, None))

    def to_dict(self):
        return asdict(self)


@dataclass
class VSPHurPairInfoList(BaseDataClass):
    data: List[VSPHurPairInfo]


DirectHurPairInfo = DirectTrueCopyPairInfo
DirectHurPairInfoList = DirectTrueCopyPairInfoList
