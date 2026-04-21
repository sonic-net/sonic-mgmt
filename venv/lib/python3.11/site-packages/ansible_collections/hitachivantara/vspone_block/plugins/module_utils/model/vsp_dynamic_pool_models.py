from dataclasses import dataclass
from typing import Optional, List, Any

try:
    from .common_base_models import BaseDataClass, SingleBaseClass

except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class CapacityManage(SingleBaseClass):
    usedCapacityRate: int = None
    thresholdWarning: int = None
    thresholdDepletion: int = None


@dataclass
class SavingEffects(SingleBaseClass):
    efficiencyDataReduction: int = None
    efficiencyFmdSaving: int = None
    preCapacityFmdSaving: int = None
    postCapacityFmdSaving: int = None
    isTotalEfficiencySupport: bool = None
    totalEfficiencyStatus: str = None
    dataReductionWithoutSystemDataStatus: str = None
    softwareSavingWithoutSystemDataStatus: str = None
    totalEfficiency: int = None
    dataReductionWithoutSystemData: int = None
    softwareSavingWithoutSystemData: int = None
    calculationStartTime: str = None
    calculationEndTime: str = None


@dataclass
class Drive(SingleBaseClass):
    driveType: str = None
    driveInterface: str = None
    driveRpm: str = None
    driveCapacity: int = None
    displayDriveCapacity: str = None
    totalCapacity: int = None
    numberOfDrives: int = None
    locations: List[str] = None
    raidLevel: str = None
    parityGroupType: str = None

    def camel_to_snake_dict(self):
        data = super().camel_to_snake_dict()
        data["drive_capacity_gb"] = data["drive_capacity"]
        data["total_capacity_mb"] = data["total_capacity"]

        data.pop("drive_capacity", None)
        data.pop("total_capacity", None)
        return data


@dataclass
class SubscriptionLimit(SingleBaseClass):
    isEnabled: bool = None
    currentRate: int = None


@dataclass
class VspDynamicPoolInfo(SingleBaseClass):
    id: Optional[int] = None
    name: Optional[str] = None
    status: Optional[str] = None
    encryption: Optional[str] = None
    totalCapacity: Optional[int] = None
    effectiveCapacity: Optional[int] = None
    usedCapacity: Optional[int] = None
    freeCapacity: Optional[int] = None
    capacityManage: Optional[CapacityManage] = None
    savingEffects: Optional[SavingEffects] = None
    configStatus: Optional[List[Any]] = None
    numberOfVolumes: Optional[int] = None
    numberOfTiers: Optional[int] = None
    numberOfDriveTypes: Optional[int] = None
    tiers: Optional[List[Any]] = None
    drives: Optional[List[Drive]] = None
    subscriptionLimit: Optional[SubscriptionLimit] = None
    containsCapacitySavingVolume: Optional[bool] = None

    def __post_init__(self, **kwargs):
        if self.drives:
            self.drives = [Drive(**drive) for drive in self.drives]
        if self.capacityManage:
            self.capacityManage = CapacityManage(**self.capacityManage)
        if self.savingEffects:
            self.savingEffects = SavingEffects(**self.savingEffects)
        if self.subscriptionLimit:
            self.subscriptionLimit = SubscriptionLimit(**self.subscriptionLimit)

    def camel_to_snake_dict(self):
        data = super().camel_to_snake_dict()
        data["total_capacity_mb"] = data["total_capacity"]
        data["effective_capacity_mb"] = data["effective_capacity"]
        data["used_capacity_mb"] = data["used_capacity"]
        data["free_capacity_mb"] = data["free_capacity"]

        data.pop("total_capacity", None)
        data.pop("effective_capacity", None)
        data.pop("used_capacity", None)
        data.pop("free_capacity", None)
        return data


@dataclass
class VspDynamicPoolsInfo(BaseDataClass):
    data: List[VspDynamicPoolInfo] = None


@dataclass
class DriveSpec:
    drive_type_code: str = None
    data_drive_count: int = None
    raid_level: str = "RAID6"
    parity_group_type: str = "DDP"


@dataclass
class VspDynamicPoolSpec:
    pool_id: str = None
    pool_name: Optional[str] = None
    is_encryption_enabled: Optional[bool] = None
    threshold_warning: Optional[int] = None
    threshold_depletion: Optional[int] = None
    drives: Optional[List[DriveSpec]] = None

    def __post_init__(self, **kwargs):
        if self.drives:
            self.drives = [DriveSpec(**drive) for drive in self.drives]


@dataclass
class VspDynamicPoolFactsSpec:
    pool_id: str = None
    pool_name: Optional[str] = None


@dataclass
class PoolConfigurationResponse(SingleBaseClass):
    driveTypeCode: str = None
    raidLevel: str = None
    parityGroupType: str = None
    numberOfCurrentDataDrives: int = None
    numberOfCurrentFreeDrives: int = None
    numberOfRecommendedAddDataDrives: int = None
    numberOfRecommendedRemainedFreeDrives: int = None
    currentPoolCapacity: int = None
    afterOperationPoolCapacity: int = None


@dataclass
class PoolConfigurationResponseList(BaseDataClass):
    data: List[PoolConfigurationResponse] = None
