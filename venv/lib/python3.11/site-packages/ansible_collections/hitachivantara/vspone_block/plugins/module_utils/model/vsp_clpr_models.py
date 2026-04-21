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
class ClprFactSpec(SingleBaseClass):
    clpr_id: Optional[int] = None
    clpr_name: Optional[str] = None
    cache_memory_capacity_mb: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class ClprSpec(SingleBaseClass):
    clpr_id: Optional[int] = None
    clpr_name: Optional[str] = None
    cache_memory_capacity_mb: Optional[int] = None
    ldev_id: Optional[int] = None
    parity_group_id: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class ClprInfo(SingleBaseClass):
    clprId: int
    clprName: str
    cacheMemoryCapacity: int
    cacheMemoryUsedCapacity: int
    writePendingDataCapacity: int
    sideFilesCapacity: int
    cacheUsageRate: int
    writePendingDataRate: int
    sideFilesUsageRate: int

    def __init__(self, **kwargs):
        self.clprId = kwargs.get("clprId")
        self.clprName = kwargs.get("clprName")
        self.cacheMemoryCapacity = kwargs.get("cacheMemoryCapacity")
        self.cacheMemoryUsedCapacity = kwargs.get("cacheMemoryUsedCapacity")
        self.writePendingDataCapacity = kwargs.get("writePendingDataCapacity")
        self.sideFilesCapacity = kwargs.get("sideFilesCapacity")
        self.cacheUsageRate = kwargs.get("cacheUsageRate")
        self.writePendingDataRate = kwargs.get("writePendingDataRate")
        self.sideFilesUsageRate = kwargs.get("sideFilesUsageRate")

    def to_dict(self):
        return asdict(self)


@dataclass
class ClprInfoList(BaseDataClass):
    data: List[ClprInfo]
