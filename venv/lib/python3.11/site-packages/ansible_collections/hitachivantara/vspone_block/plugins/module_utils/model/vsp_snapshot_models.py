from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class SnapshotFactSpec:
    pvol: Optional[int] = None
    mirror_unit_id: Optional[int] = None
    snapshot_group_name: Optional[str] = None
    primary_volume_id: Optional[int] = None

    def __init__(self, **kwargs):
        for field in self.__dataclass_fields__.keys():
            setattr(self, field, kwargs.get(field, None))
        if kwargs.get("primary_volume_id"):
            self.pvol = kwargs.get("primary_volume_id")
        self.__post_init__()

    def __post_init__(self):
        if self.primary_volume_id:
            self.primary_volume_id = normalize_ldev_id(self.primary_volume_id)
        if self.pvol:
            self.pvol = normalize_ldev_id(self.pvol)


@dataclass
class SnapshotGroupSpec:
    snapshot_group_name: Optional[str] = None
    snapshot_group_id: Optional[str] = None
    auto_split: Optional[bool] = None
    retention_period: Optional[int] = None
    copy_speed: Optional[str] = None


@dataclass
class SnapshotGroupFactSpec:
    snapshot_group_name: str = None


@dataclass
class SnapshotReqData:
    pass


@dataclass
class SnapshotReconcileSpec:
    pvol: int
    pool_id: Optional[int] = None
    allocate_consistency_group: Optional[bool] = False
    enable_quick_mode: Optional[bool] = False
    consistency_group_id: Optional[int] = -1
    mirror_unit_id: Optional[int] = None
    state: Optional[str] = "present"
    snapshot_group_name: Optional[str] = None
    auto_split: Optional[bool] = None
    is_data_reduction_force_copy: Optional[bool] = None
    is_clone: Optional[bool] = None
    can_cascade: Optional[bool] = None
    svol: Optional[int] = None
    primary_volume_id: Optional[int] = None
    secondary_volume_id: Optional[int] = None
    allocate_new_consistency_group: Optional[bool] = None
    retention_period: Optional[int] = None
    copy_speed: Optional[str] = None
    clones_automation: Optional[bool] = None
    operation_type: Optional[str] = None
    should_delete_tree: Optional[bool] = False

    def __init__(self, **kwargs):
        for field in self.__dataclass_fields__.keys():
            setattr(self, field, kwargs.get(field, None))
        if kwargs.get("primary_volume_id"):
            self.pvol = kwargs.get("primary_volume_id")
        if kwargs.get("secondary_volume_id"):
            self.svol = kwargs.get("secondary_volume_id")
        if kwargs.get("allocate_new_consistency_group"):
            self.allocate_consistency_group = kwargs.get(
                "allocate_new_consistency_group"
            )
        self.__post_init__()

    def __post_init__(self):
        if self.primary_volume_id:
            self.primary_volume_id = normalize_ldev_id(self.primary_volume_id)
        if self.pvol:
            self.pvol = normalize_ldev_id(self.pvol)
        if self.secondary_volume_id:
            self.primary_volume_id = normalize_ldev_id(self.secondary_volume_id)
        if self.svol:
            self.svol = normalize_ldev_id(self.svol)


@dataclass
class HostGroupInfo(SingleBaseClass):
    port: str = None
    name: str = None

    def __init__(self, **kwargs):
        self.name = kwargs.get("name")
        self.port = kwargs.get("port")

    def to_dict(self):
        return asdict(self)


@dataclass
class DirectSnapshotInfo(SingleBaseClass):
    snapshotGroupName: Optional[str] = None
    primaryOrSecondary: Optional[str] = None
    status: Optional[str] = None
    pvolLdevId: Optional[int] = None
    muNumber: Optional[int] = None
    svolLdevId: Optional[int] = None
    snapshotPoolId: Optional[int] = None
    concordanceRate: Optional[int] = None
    isConsistencyGroup: Optional[bool] = None
    isWrittenInSvol: Optional[bool] = None
    isClone: Optional[bool] = None
    canCascade: Optional[bool] = None
    isRedirectOnWrite: Optional[bool] = None
    splitTime: Optional[str] = None
    snapshotId: Optional[str] = None
    pvolProcessingStatus: Optional[str] = None
    snapshotDataReadOnly: Optional[bool] = None
    resourceId: Optional[str] = None
    snapshotReplicationId: Optional[str] = None
    consistencyGroupId: Optional[int] = None
    type: Optional[str] = "NORMAL"
    snapshotReplicationId: Optional[str] = None
    poolId: Optional[int] = None
    progressRate: Optional[int] = None
    pvolNvmSubsystemName: Optional[str] = None
    svolNvmSubsystemName: Optional[str] = None
    pvolHostGroups: Optional[List[HostGroupInfo]] = None
    svolHostGroups: Optional[List[HostGroupInfo]] = None
    retentionPeriod: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__()  # or selectively forward kwargs
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.__post_init__()

    def __post_init__(self):
        if self.isClone and self.canCascade:
            self.type = "CLONE"
        elif self.isClone is False and self.canCascade is True:
            self.type = "CASCADE"
        if self.snapshotReplicationId:
            self.snapshotId = self.snapshotReplicationId
        if self.snapshotPoolId is not None:
            self.poolId = self.snapshotPoolId


@dataclass
class SnapshotGroupInfo(SingleBaseClass):
    snapshotGroupName: Optional[str] = None
    snapshotGroupId: Optional[str] = None
    snapshots: Optional[List[DirectSnapshotInfo]] = None

    def __post_init__(self):
        if self.snapshots:
            snapshots = [DirectSnapshotInfo(**snapshot) for snapshot in self.snapshots]
            self.snapshots = DirectSnapshotsInfo(data=snapshots)


@dataclass
class DirectSnapshotsInfo(BaseDataClass):
    data: List[DirectSnapshotInfo] = None


@dataclass
class SnapshotGroup(SingleBaseClass):
    snapshotGroupName: Optional[str] = None
    snapshotGroupId: Optional[str] = None


@dataclass
class SnapshotGroups(BaseDataClass):
    data: List[SnapshotGroup] = None


@dataclass
class UAIGSnapshotInfo(SingleBaseClass):
    resourceId: Optional[str] = None
    storageSerialNumber: Optional[int] = None
    primaryVolumeId: Optional[int] = None
    primaryHexVolumeId: Optional[str] = None
    secondaryVolumeId: Optional[int] = None
    secondaryHexVolumeId: Optional[str] = None
    svolAccessMode: Optional[str] = None
    poolId: Optional[int] = None
    consistencyGroupId: Optional[int] = None
    mirrorUnitId: Optional[int] = None
    copyRate: Optional[int] = None
    copyPaceTrackSize: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None
    storageId: Optional[str] = None
    entitlementStatus: Optional[str] = None
    partnerId: Optional[str] = None
    subscriberId: Optional[str] = None
    snapshotGroupName: Optional[str] = None
    # snapshotPairInfo: Optional[str] = None
    isCTG: Optional[bool] = False
    retentionPeriod: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        #  20240825 snapshot_pair_info is from v3 response
        #  20240825 thinImagePropertiesDto is from v3 response
        snapshot_pair_info = kwargs.get("snapshotPairInfo")
        thinImagePropertiesDto = None

        #  v2 response does not have snapshot_pair_info
        #  thinImageProperties is from v2 response
        thinImageProperties = kwargs.get("thinImageProperties")
        if thinImageProperties:
            for field in self.__dataclass_fields__.keys():
                #  only if the base value is None
                if getattr(self, field) is None:
                    setattr(self, field, thinImageProperties.get(field, None))
                #  special overwrite
                if field == "type":
                    setattr(self, field, thinImageProperties.get(field, None))

        #  flatten the struct from v3
        if snapshot_pair_info:
            thinImagePropertiesDto = snapshot_pair_info.get("thinImagePropertiesDto")
            for field in self.__dataclass_fields__.keys():
                if getattr(self, field) is None:
                    setattr(self, field, snapshot_pair_info.get(field))
        if thinImagePropertiesDto:
            for field in self.__dataclass_fields__.keys():
                #  only if the base value is None
                if getattr(self, field) is None:
                    setattr(self, field, thinImagePropertiesDto.get(field, None))
                #  special overwrite
                if field == "type":
                    setattr(self, field, thinImagePropertiesDto.get(field, None))

    def to_dict(self):
        return asdict(self)


@dataclass
class UAIGSnapshotsInfo(BaseDataClass):
    data: List[UAIGSnapshotInfo] = None
