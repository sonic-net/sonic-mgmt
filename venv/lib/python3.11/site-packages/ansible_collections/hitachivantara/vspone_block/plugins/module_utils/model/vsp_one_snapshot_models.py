from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import (
        normalize_ldev_id,
        volume_id_to_hex_format,
    )
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class VspOneSnapshotFactSpec:
    master_volume_id: Optional[int] = None
    snapshot_date_from: Optional[str] = None
    snapshot_date_to: Optional[str] = None
    snapshot_group_name: Optional[str] = None
    start_id: Optional[str] = None
    count: Optional[int] = None
    snapshot_id: Optional[int] = None

    def __post_init__(self):
        if self.master_volume_id is not None:
            self.master_volume_id = normalize_ldev_id(self.master_volume_id)

    def is_empty(self):
        if (
            self.master_volume_id is None
            and self.snapshot_date_from is None
            and self.snapshot_date_to is None
            and self.snapshot_group_name is None
            and self.start_id is None
            and self.count is None
            or self.count == 0
        ):
            return True
        else:
            return False


@dataclass
class VspOneCreateSnapshotSpec(SingleBaseClass):
    type_map = {"snapshot": "Snapshot", "mapped_snapshot": "Mapped Snapshot"}
    master_volume_id: Optional[int] = None
    snapshot_group_name: Optional[str] = None
    pool_id: Optional[int] = None
    type: Optional[str] = None

    def __post_init__(self):
        if self.master_volume_id is not None:
            self.master_volume_id = normalize_ldev_id(self.master_volume_id)
        if self.type:
            lower_type = self.type.lower()
            user_type = self.type_map.get(lower_type, None)
            if user_type is None:
                raise ValueError(
                    f"Invalid type {self.type} provided. Valid types are {self.type_map.keys()}"
                )
            else:
                self.type = user_type


@dataclass
class VspOneSnapshotSpec:
    new_snapshots: Optional[List[VspOneCreateSnapshotSpec]] = None
    master_volume_id: Optional[int] = None
    pool_id: Optional[int] = None
    snapshot_id: Optional[int] = None
    should_delete_svol: Optional[bool] = None
    comments: Optional[List[str]] = None
    errors: Optional[List[str]] = None

    def __post_init__(self):
        if self.new_snapshots:
            self.new_snapshots = [
                VspOneCreateSnapshotSpec(**new_sn) for new_sn in self.new_snapshots
            ]
        if self.master_volume_id is not None:
            self.master_volume_id = normalize_ldev_id(self.master_volume_id)


@dataclass
class VspOneSnapshotResponse(SingleBaseClass):
    id: Optional[str] = None
    masterVolumeId: Optional[int] = None
    snapshotId: Optional[int] = None
    status: Optional[str] = None
    snapshotDate: Optional[str] = None
    snapshotGroupName: Optional[str] = None
    mappedVolumeId: Optional[int] = None
    rootVolumeId: Optional[int] = None
    poolId: Optional[int] = None
    usedCapacityPerRootVolume: Optional[int] = None
    isVolumeCapacityExpanding: Optional[bool] = None
    type: Optional[str] = None
    retentionPeriod: Optional[int] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__post_init__()

    def __post_init__(self):
        pass
        # if self.masterVolumeId is not None:
        #     self.masterVolumeId = normalize_ldev_id(self.masterVolumeId)

        # if self.nvmeTcpInformation is not None:
        #     self.nvmeTcpInformation = NvmeTcpInformation(**self.nvmeTcpInformation)
        # if self.fcInformation is not None:
        #     self.fcInformation = FCInformationRes(**self.fcInformation)

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        camel_dict["master_volume_id_hex"] = volume_id_to_hex_format(
            self.masterVolumeId
        )
        camel_dict["mapped_volume_id_hex"] = volume_id_to_hex_format(
            self.mappedVolumeId
        )
        camel_dict["root_volume_id_hex"] = volume_id_to_hex_format(self.rootVolumeId)
        camel_dict["used_capacity_in_mb_per_root_volume"] = camel_dict.get(
            "used_capacity_per_root_volume", None
        )
        camel_dict.pop("used_capacity_per_root_volume")
        return camel_dict


@dataclass
class VspOneSnapshotList(BaseDataClass):
    data: List[VspOneSnapshotResponse] = None


@dataclass
class VspOneSnapshotGroupResponse(SingleBaseClass):
    name: Optional[str] = None


@dataclass
class VspOneSnapshotGroupList(BaseDataClass):
    data: List[VspOneSnapshotGroupResponse] = None


@dataclass
class SnapshotsInGroup(SingleBaseClass):
    snapshotId: Optional[int] = None
    masterVolumeId: Optional[int] = None


@dataclass
class SnapshotGroupDetailResponse(SingleBaseClass):
    name: Optional[str] = None
    snapshots: List[SnapshotsInGroup] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__post_init__()

    def __post_init__(self):
        if self.snapshots is not None:
            self.snapshots = [
                (
                    SnapshotsInGroup(**item)
                    if not isinstance(item, SnapshotsInGroup)
                    else item
                )
                for item in self.snapshots
            ]


@dataclass
class VspOneSnapshotGroupFactSpec:
    include_snapshots: Optional[bool] = False
    snapshot_group_name: Optional[str] = None
    comment: Optional[str] = None
