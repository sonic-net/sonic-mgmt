from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class VSPResourceGroupFactSpec(SingleBaseClass):
    name: Optional[str] = None
    id: Optional[int] = None
    is_locked: Optional[bool] = None
    query: Optional[List[str]] = None

    def is_empty(self):
        if (
            self.name is None
            and self.id is None
            and self.is_locked is None
            and self.query is None
        ):
            return True
        return False


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
class VSPResourceGroupSpec(SingleBaseClass):
    id: Optional[int] = None
    name: Optional[str] = None
    virtual_storage_serial: Optional[str] = None
    virtual_storage_model: Optional[str] = None
    virtual_storage_type: Optional[str] = None
    ldevs: Optional[List[int]] = None
    ports: Optional[List[str]] = None
    parity_groups: Optional[List[str]] = None
    storage_pool_ids: Optional[List[int]] = None
    host_groups_simple: Optional[List[str]] = None
    host_groups: Optional[List[HostGroupInfo]] = None
    iscsi_targets: Optional[List[HostGroupInfo]] = None
    iscsi_targets_simple: Optional[List[str]] = None
    nvm_subsystem_ids: Optional[List[int]] = None
    state: Optional[str] = None
    force: Optional[bool] = False
    add_resource_time_out_in_sec: Optional[int] = None

    external_parity_groups: Optional[List[str]] = None
    start_ldev: Optional[int] = None
    end_ldev: Optional[int] = None

    def __post_init__(self):
        if self.start_ldev:
            self.start_ldev = normalize_ldev_id(self.start_ldev)
        if self.end_ldev:
            self.end_ldev = normalize_ldev_id(self.end_ldev)
        if self.ldevs:
            self.ldevs = [normalize_ldev_id(ldev) for ldev in self.ldevs]


@dataclass
class VirtualStorageMachineInfo(SingleBaseClass):
    virtualStorageDeviceId: str
    virtualSerialNumber: str
    virtualModel: str
    resourceGroupIds: List[int]
    virtualStorageTypeId: str
    virtualModelDetail: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class VirtualStorageMachineInfoList(BaseDataClass):
    data: List[VirtualStorageMachineInfo]


@dataclass
class VspResourceGroupInfo(SingleBaseClass):
    resourceGroupName: str
    resourceGroupId: int
    lockStatus: str
    virtualStorageId: int
    ldevIds: List[int]
    parityGroupIds: List[str]
    externalParityGroupIds: List[str]
    portIds: List[str]
    hostGroupIds: List[HostGroupInfo]
    nvmSubsystemIds: List[int] = None
    selfLock: bool = None
    lockOwner: str = None
    lockHost: str = None
    lockSessionId: int = None
    virtualStorageDeviceId: str = None
    virtualSerialNumber: str = None
    virtualModel: str = None

    def __init__(self, **kwargs):
        self.resourceGroupName = kwargs.get("resourceGroupName")
        self.resourceGroupId = kwargs.get("resourceGroupId")
        self.lockStatus = kwargs.get("lockStatus")
        if "selfLock" in kwargs:
            self.selfLock = kwargs.get("selfLock")
        if "lockOwner" in kwargs:
            self.selfLock = kwargs.get("lockOwner")
        if "lockHost" in kwargs:
            self.lockHost = kwargs.get("lockHost")
        if "lockSessionId" in kwargs:
            self.lockSessionId = kwargs.get("lockSessionId")
        self.virtualStorageId = kwargs.get("virtualStorageId")
        self.ldevIds = kwargs.get("ldevIds")
        self.parityGroupIds = kwargs.get("parityGroupIds")
        self.externalParityGroupIds = kwargs.get("externalParityGroupIds")
        self.portIds = kwargs.get("portIds")
        self.hostGroupIds = kwargs.get("hostGroupIds")
        if "nvmSubsystemIds" in kwargs:
            self.nvmSubsystemIds = kwargs.get("nvmSubsystemIds")

    def to_dict(self):
        return asdict(self)


@dataclass
class VspResourceGroupInfoList(BaseDataClass):
    data: List[VspResourceGroupInfo]


@dataclass
class DisplayResourceGroup:
    name: str
    id: int
    lockStatus: str
    virtualStorageId: int
    ldevs: List[int]
    parityGroups: List[str]
    externalParityGroups: List[str]
    ports: List[str]
    hostGroups: List[HostGroupInfo]
    nvmSubsystemIds: List[int]
    storagePoolIds: List[int]
    iscsiTargets: List[HostGroupInfo]
    selfLock: bool
    lockOwner: str
    lockHost: str
    lockSessionId: int
    virtualStorageDeviceId: str
    virtualSerialNumber: str
    virtualModel: str
    virtualDeviceType: str

    def __init__(self):
        self.name = None
        self.id = None
        self.lockStatus = None
        self.virtualStorageId = None
        self.ldevs = None
        self.parityGroups = None
        self.externalParityGroups = None
        self.ports = None
        self.hostGroups = None
        self.nvmSubsystemIds = None
        self.storagePoolIds = None
        self.iscsiTargets = None
        self.selfLock = None
        self.lockOwner = None
        self.lockHost = None
        self.lockSessionId = None
        self.virtualStorageDeviceId = None
        self.virtualSerialNumber = None
        self.virtualModel = None
        self.virtualDeviceType = None

    def to_dict(self):
        return asdict(self)


@dataclass
class DisplayResourceGroupList(BaseDataClass):
    data: List[DisplayResourceGroup]
