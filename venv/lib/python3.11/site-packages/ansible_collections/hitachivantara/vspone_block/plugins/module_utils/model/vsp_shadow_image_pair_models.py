from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class GetShadowImageSpec:
    pvol: Optional[int] = None
    copy_group_name: Optional[str] = None
    copy_pair_name: Optional[str] = None
    refresh: Optional[bool] = None
    # svol: Optional[int] = None

    def __init__(self, **kwargs):
        for field in self.__dataclass_fields__.keys():
            setattr(self, field, kwargs.get(field, None))

        if kwargs.get("primary_volume_id"):
            self.pvol = kwargs.get("primary_volume_id")
        self.__post_init__()

    def __post_init__(self):
        if self.pvol:
            self.pvol = normalize_ldev_id(self.pvol)


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
class VSPShadowImagePairInfo(SingleBaseClass):
    localCloneCopypairId: Optional[str] = None
    copyGroupName: Optional[str] = None
    copyPairName: Optional[str] = None
    resourceId: Optional[str] = None
    consistencyGroupId: Optional[int] = None
    copyPaceTrackSize: Optional[str] = None
    copyRate: Optional[int] = None
    mirrorUnitId: Optional[int] = None
    primaryHexVolumeId: Optional[str] = None
    primaryVolumeId: Optional[int] = None
    storageSerialNumber: Optional[str] = None
    secondaryHexVolumeId: Optional[str] = None
    secondaryVolumeId: Optional[int] = None
    status: Optional[int] = None
    svolAccessMode: Optional[str] = None
    type: Optional[str] = None
    entitlementStatus: Optional[str] = None
    partnerId: Optional[str] = None
    subscriberId: Optional[str] = None
    pvolNvmSubsystemName: Optional[str] = None
    svolNvmSubsystemName: Optional[str] = None
    pvolHostGroups: Optional[List[HostGroupInfo]] = None
    svolHostGroups: Optional[List[HostGroupInfo]] = None
    __pvolMuNumber: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        shadow_image_info = kwargs.get("shadowImageInfo")
        if shadow_image_info:
            for field in self.__dataclass_fields__.keys():
                if getattr(self, field) is None:
                    setattr(self, field, shadow_image_info.get(field, None))

            self.type = shadow_image_info.get("type", None)
        self.__post_init__()

    def __post_init__(self):
        if self.pvolHostGroups:
            self.pvolHostGroups = [
                HostGroupInfo(**group) for group in self.pvolHostGroups
            ]
        if self.svolHostGroups:
            self.svolHostGroups = [
                HostGroupInfo(**group) for group in self.svolHostGroups
            ]

    def to_dict(self):
        return asdict(self)


@dataclass
class VSPShadowImagePairsInfo(BaseDataClass):
    data: List[VSPShadowImagePairInfo]


@dataclass
class ShadowImagePairSpec:
    pvol: Optional[int] = None
    svol: Optional[int] = None
    auto_split: Optional[bool] = None
    new_consistency_group: Optional[bool] = None
    is_new_group_creation: Optional[bool] = None
    consistency_group_id: Optional[int] = None
    copy_pace_track_size: Optional[str] = None
    enable_quick_mode: Optional[bool] = None
    enable_read_write: Optional[bool] = None
    copy_pace: Optional[str] = None
    is_data_reduction_force_copy: Optional[bool] = None
    pair_id: Optional[str] = None
    primary_volume_id: Optional[int] = None
    secondary_volume_id: Optional[int] = None
    allocate_new_consistency_group: Optional[bool] = None
    secondary_pool_id: Optional[int] = None
    copy_group_name: Optional[str] = None
    copy_pair_name: Optional[str] = None
    primary_volume_device_group_name: Optional[str] = None
    secondary_volume_device_group_name: Optional[str] = None
    should_delete_svol: Optional[bool] = None
    should_force_split: Optional[bool] = None
    create_for_migration: Optional[bool] = None

    def __init__(self, **kwargs):
        for field in self.__dataclass_fields__.keys():
            setattr(self, field, kwargs.get(field, None))

        if kwargs.get("primary_volume_id"):
            self.pvol = kwargs.get("primary_volume_id")
        if kwargs.get("secondary_volume_id"):
            self.svol = kwargs.get("secondary_volume_id")
        if kwargs.get("allocate_new_consistency_group"):
            self.new_consistency_group = kwargs.get("allocate_new_consistency_group")
        self.__post_init__()

    def __post_init__(self):
        if self.pvol:
            self.pvol = normalize_ldev_id(self.pvol)
        if self.svol:
            self.svol = normalize_ldev_id(self.svol)


@dataclass
class UaigResourceMappingInfo:
    deviceId: Optional[str] = None
    resourceId: Optional[str] = None
    partnerId: Optional[str] = None
    subscriberId: Optional[str] = None
    type: Optional[str] = None
    resourceValue: Optional[str] = None
    time: Optional[float] = None
    totalCapacity: Optional[str] = None

    def to_dict(self):
        return asdict(self)
