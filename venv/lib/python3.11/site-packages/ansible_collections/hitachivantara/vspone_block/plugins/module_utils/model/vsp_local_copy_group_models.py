from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass

except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class LocalCopyGroupSpec(SingleBaseClass):
    name: Optional[str] = None
    copy_group_name: Optional[str] = None
    primary_volume_device_group_name: Optional[str] = None
    secondary_volume_device_group_name: Optional[str] = None
    quick_mode: Optional[bool] = None
    copy_pace: Optional[int] = None
    force_suspend: Optional[bool] = None
    force_delete: Optional[bool] = None
    should_force_split: Optional[bool] = None

    # secondary_connection_info: Optional[ConnectionInfo] = None
    # secondary_storage_serial_number: Optional[int] = None
    # copy_pair_name: Optional[str] = None
    # local_device_group_name: Optional[str] = None
    # remote_device_group_name: Optional[str] = None
    # replication_type: str = ""
    # svol_operation_mode: str = ""
    # is_svol_writable: Optional[bool] = False
    # do_pvol_write_protect: Optional[bool] = False
    # do_data_suspend: Optional[bool] = False
    # do_failback: Optional[bool] = False
    # failback_mirror_unit_number: Optional[int] = None
    # is_consistency_group: Optional[bool] = False
    # consistency_group_id: Optional[int] = None
    # fence_level: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class LocalCopyGroupFactSpec(SingleBaseClass):
    # secondary_connection_info: Optional[ConnectionInfo] = None
    # secondary_storage_serial_number: Optional[int] = None
    # copy_group_name: Optional[str] = None
    name: Optional[str] = None
    primary_volume_device_group_name: Optional[str] = None
    secondary_volume_device_group_name: Optional[str] = None
    should_include_copy_pairs: Optional[bool] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class LocalCopyGroupInfo(SingleBaseClass):
    copyGroupName: str
    pvolDeviceGroupName: str
    svolDeviceGroupName: str
    localCloneCopygroupId: str


@dataclass
class LocalCopyGroupInfoList(BaseDataClass):
    data: List[LocalCopyGroupInfo]


@dataclass
class LocalCopyPairInfo(SingleBaseClass):
    copyGroupName: str
    copyPairName: str
    pvolLdevId: int
    svolLdevId: int
    pvolMuNumber: int
    consistencyGroupId: int = ""
    pvolStatus: str = ""
    svolStatus: str = ""
    localCloneCopypairId: str = ""
    replicationType: str = ""
    copyMode: str = ""
    replicationType: str = ""
    copyProgressRate: int = 0
    pvolDifferenceDataManagement: str = ""
    svolDifferenceDataManagement: str = ""
    pvolProcessingStatus: str = ""
    svolProcessingStatus: str = ""


@dataclass
class LocalCopyPairInfoList(BaseDataClass):
    data: List[LocalCopyPairInfo]


@dataclass
class LocalSpecificCopyGroupInfo(SingleBaseClass):
    copyGroupName: str
    pvolDeviceGroupName: str
    svolDeviceGroupName: str
    localCloneCopygroupId: str
    copyPairs: Optional[List[LocalCopyPairInfo]] = None

    def __init__(self, **kwargs):
        self.localCloneCopygroupId = kwargs.get("localCloneCopygroupId")
        self.copyGroupName = kwargs.get("copyGroupName")
        self.pvolDeviceGroupName = kwargs.get("pvolDeviceGroupName")
        self.svolDeviceGroupName = kwargs.get("svolDeviceGroupName")
        if "copyPairs" in kwargs and kwargs.get("copyPairs") is not None:
            self.copyPairs = [
                LocalCopyPairInfo(**copyPair) for copyPair in kwargs.get("copyPairs")
            ]

    def to_dict(self):
        return asdict(self)


@dataclass
class LocalSpecificCopyGroupInfoList(BaseDataClass):
    data: List[LocalSpecificCopyGroupInfo]
