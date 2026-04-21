from dataclasses import dataclass
from typing import Optional, List, Any

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class HostgroupSpec:
    id: Optional[int] = None
    name: Optional[str] = None
    enable_preferred_path: Optional[bool] = None
    port: Optional[str] = None
    resource_group_id: Optional[int] = None


@dataclass
class ExtVolumeInfo(SingleBaseClass):
    externalLun: Optional[int] = None
    portId: Optional[str] = None
    externalWwn: Optional[str] = None
    externalVolumeCapacity: Optional[int] = None
    externalVolumeInfo: Optional[str] = None
    externalPathGroupId: int = None
    externalSerialNumber: str = None
    externalProductId: str = None
    externalVolumeCapacityInMb: Optional[int] = None
    externalLdevId: Optional[int] = None
    ldevIds: Optional[list[int]] = None


@dataclass
class ExtVolumeLocalInfo(SingleBaseClass):
    externalStorage: Optional[Any] = None
    externalParityGroupId: Optional[str] = None
    ldevId: Optional[int] = None


@dataclass
class ExtVolumeInfoList(BaseDataClass):
    data: List[ExtVolumeInfo]


@dataclass
class ExtVolumeLocalInfoList(BaseDataClass):
    data: List[ExtVolumeLocalInfo]


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
class SalamanderExternalPathInfo(SingleBaseClass):
    portId: str
    portProtocol: str
    externalPortIpAddress: str = None
    externalPortIscsiName: str = None
    externalTcpPortNumber: int = None
    virtualPortNumber: int = None
    externalPortWwn: str = None


@dataclass
class SalamanderExternalPathInfoList(BaseDataClass):
    data: List[SalamanderExternalPathInfo]


@dataclass
class ExternalPathGroupInfo(SingleBaseClass):
    externalPathGroupId: int
    externalSerialNumber: str
    externalProductId: str
    externalParityGroups: List[Any]
    externalPaths: List[ExternalPathInfo]
    nextPageHeadPathGroupId: int = None


@dataclass
class ExternalPathGroupInfoList(BaseDataClass):
    data: List[ExternalPathGroupInfo]


@dataclass
class SalamanderExternalPathGroupInfo(SingleBaseClass):
    id: int
    externalPaths: List[SalamanderExternalPathInfo]


@dataclass
class SalamanderExternalPathGroupInfoList(BaseDataClass):
    data: List[SalamanderExternalPathGroupInfo]


@dataclass
class QuorumDiskInfo(SingleBaseClass):
    quorumDiskId: int
    remoteSerialNumber: str
    remoteStorageTypeId: str
    readResponseGuaranteedTime: int
    ldevId: Optional[int] = -1
    status: Optional[str] = ""


@dataclass
class QuorumDiskInfoList(BaseDataClass):
    data: List[QuorumDiskInfo]


@dataclass
class QuorumDiskSpec:

    secondary_storage_serial_number: Optional[str] = None
    remote_storage_serial_number: Optional[str] = None
    remote_storage_type: Optional[str] = None
    # local map of external volume
    ldev_id: Optional[int] = None
    # qrd id
    id: Optional[int] = None

    def __post_init__(self):
        if self.ldev_id:
            self.ldev_id = normalize_ldev_id(self.ldev_id)


@dataclass
class QuorumDiskFactSpec:
    id: Optional[int] = None
