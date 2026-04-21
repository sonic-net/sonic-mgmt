from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class StorageNodeBmcAccessSettingFactSpec:
    id: Optional[str] = None


@dataclass
class StorageNodeBmcAccessSettingSpec:
    id: Optional[str] = None
    name: Optional[str] = None
    bmc_name: Optional[str] = None
    bmc_user: Optional[str] = None
    bmc_password: Optional[str] = None


@dataclass
class StorageNodeFactSpec:
    id: Optional[str] = None
    fault_domain_id: Optional[str] = None
    name: Optional[str] = None
    cluster_role: Optional[str] = None
    protection_domain_id: Optional[str] = None


@dataclass
class StorageNodeSpec:
    id: Optional[str] = None
    name: Optional[str] = None
    os_type: Optional[str] = None
    state: Optional[str] = None
    iscsi_initiators: Optional[List[str]] = None
    volumes: Optional[List[str]] = None
    host_nqns: Optional[List[str]] = None
    should_delete_all_volumes: Optional[bool] = False
    is_capacity_balancing_enabled: Optional[bool] = None


@dataclass
class InsufficientResourcesForRebuildCapacity:
    capacityOfDrive: int = 0
    numberOfDrives: int = 0


@dataclass
class RebuildableResources:
    numberOfDrives: int = 0


@dataclass
class SDSBStorageNodeInfo(SingleBaseClass):
    id: str = None
    biosUuid: str = None
    protectionDomainId: str = None
    faultDomainId: str = None
    faultDomainName: str = None
    name: str = None
    clusterRole: str = None
    storageNodeAttributes: Optional[List[str]] = None
    statusSummary: str = None
    status: str = None
    driveDataRelocationStatus: str = None
    controlPortIpv4Address: str = None
    internodePortIpv4Address: str = None
    softwareVersion: str = None
    modelName: str = None
    serialNumber: str = None
    memory: int = 0
    insufficientResourcesForRebuildCapacity: InsufficientResourcesForRebuildCapacity = (
        None
    )
    rebuildableResources: RebuildableResources = None
    availabilityZoneId: str = None
    physicalZone: str = None
    logicalZone: str = None
    is_capacity_balancing_enabled: bool = None
    isStorageMasterNodePrimary: bool = None

    def __init__(self, **kwargs):
        # for key, value in kwargs.items():
        #     if hasattr(self, key):
        #         setattr(self, key, value)
        super().__init__(**kwargs)
        if "physicalZone" in kwargs:
            self.physicalZone = kwargs.get("physicalZone")
        if "logicalZone" in kwargs:
            self.logicalZone = kwargs.get("logicalZone")

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBStorageNodeInfoList(BaseDataClass):
    data: List[SDSBStorageNodeInfo]
