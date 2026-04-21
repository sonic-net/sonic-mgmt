from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class StoragePoolFactSpec:
    id: Optional[str] = None
    names: Optional[List[str]] = None


@dataclass
class StoragePoolSpec:
    id: Optional[str] = None
    name: Optional[str] = None
    drive_ids: Optional[List[str]] = None
    rebuild_capacity_policy: Optional[str] = None
    number_of_tolerable_drive_failures: Optional[int] = None
    is_encryption_enabled: Optional[bool] = None


@dataclass
class CapacityManage:
    usedCapacityRate: int = None
    maximumReserveRate: int = -1
    thresholdWarning: int = 0
    thresholdDepletion: int = 0
    thresholdStorageControllerDepletion: int = 0


@dataclass
class SavingEffectOfPool(SingleBaseClass):
    efficiencyDataReduction: int = None
    preCapacityDataReduction: int = None
    postCapacityDataReduction: int = None
    totalEfficiencyStatus: str = None
    dataReductionWithoutSystemDataStatus: str = None
    totalEfficiency: int = None
    dataReductionWithoutSystemData: int = None
    preCapacityDataReductionWithoutSystemData: int = None
    postCapacityDataReductionWithoutSystemData: int = None
    calculationStartTime: str = None
    calculationEndTime: str = None


@dataclass
class RebuildCapacityResourceSetting:
    numberOfTolerableDriveFailures: int = 0


@dataclass
class RebuildableResources:
    numberOfDrives: int = 0


@dataclass
class SDSBStoragePoolInfo:
    id: str = None
    name: str = None
    protectionDomainId: str = None
    statusSummary: str = None
    status: str = None
    totalCapacity: int = 0
    totalRawCapacity: int = 0
    usedCapacity: int = 0
    freeCapacity: int = 0
    totalPhysicalCapacity: int = 0
    metaDataPhysicalCapacity: int = 0
    reservedPhysicalCapacity: int = 0
    usablePhysicalCapacity: int = 0
    blockedPhysicalCapacity: int = 0
    totalVolumeCapacity: int = 0
    provisionedVolumeCapacity: int = 0
    otherVolumeCapacity: int = 0
    temporaryVolumeCapacity: int = 0
    capacityManage: CapacityManage = None
    savingEffects: SavingEffectOfPool = None
    numberOfVolumes: int = 0
    redundantPolicy: str = None
    redundantType: str = None
    dataRedundancy: int = 0
    storageControllerCapacitiesGeneralStatus: str = None
    rebuildCapacityPolicy: str = None
    rebuildCapacityResourceSetting: RebuildCapacityResourceSetting = None
    rebuildCapacityStatus: str = None
    rebuildableResources: RebuildableResources = None
    encryptionStatus: str = None

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBStoragePoolInfoList(BaseDataClass):
    data: List[SDSBStoragePoolInfo]
