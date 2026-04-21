from dataclasses import dataclass
from typing import Optional, List, Any

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id

except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class ExtVolumeInfo(SingleBaseClass):
    externalLun: Optional[int] = None
    portId: Optional[str] = None
    externalWwn: Optional[str] = None
    externalVolumeCapacity: Optional[int] = None
    externalVolumeInfo: Optional[str] = None


@dataclass
class ExtVolumeInfoList(BaseDataClass):
    data: List[ExtVolumeInfo]


@dataclass
class ExternalPathInfo(SingleBaseClass):
    portId: str
    externalWwn: str
    qDepth: str
    ioTimeOut: int
    blockedPathMonitoring: int


@dataclass
class ExternalPathInfoList(BaseDataClass):
    data: List[ExternalPathInfo]


@dataclass
class ExternalPathGroupInfo(SingleBaseClass):
    externalPathGroupId: int
    externalSerialNumber: str
    externalProductId: str
    externalParityGroups: List[Any]
    externalPaths: List[ExternalPathInfo]
    nextPageHeadPathGroupId: int


@dataclass
class ExternalPathGroupInfoList(BaseDataClass):
    data: List[ExternalPathGroupInfo]


@dataclass
class ExternalVolumeSpec:
    external_storage_serial: str
    external_ldev_id: int
    external_parity_group: str
    ldev_id: Optional[int] = None

    def __post_init__(self):
        if self.ldev_id:
            self.ldev_id = normalize_ldev_id(self.ldev_id)
        if self.external_ldev_id:
            self.external_ldev_id = normalize_ldev_id(self.external_ldev_id)


@dataclass
class ExternalVolumeFactSpec:
    external_storage_serial: str
    external_ldev_id: int

    def __post_init__(self):
        if self.external_ldev_id:
            self.external_ldev_id = normalize_ldev_id(self.external_ldev_id)
