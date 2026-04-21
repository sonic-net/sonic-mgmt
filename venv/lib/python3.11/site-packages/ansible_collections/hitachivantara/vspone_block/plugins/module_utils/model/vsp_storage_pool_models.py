from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class PoolFactSpec:
    pool_id: Optional[int] = None
    pool_name: Optional[str] = None


@dataclass
class PoolVolumesSpec:
    parity_group_id: str = None
    capacity: str = None


@dataclass
class Tier(SingleBaseClass):
    tier_number: int = None
    table_space_rate: int = None
    buffer_rate: int = None


@dataclass
class StoragePoolSpec:
    id: int = None
    name: str = None
    type: str = None
    pool_volumes: List[PoolVolumesSpec] = None
    resource_group_id: int = None
    warning_threshold_rate: int = None
    depletion_threshold_rate: int = None
    should_enable_deduplication: bool = None
    ldev_ids: List[int] = None
    duplication_ldev_ids: List[int] = None
    start_ldev_id: int = None
    end_ldev_id: int = None
    operation_type: str = None
    pool_type: str = None
    suspend_snapshot: bool = None
    virtual_volume_capacity_rate: int = None
    blocking_mode: str = None
    tier: Tier = None
    monitoring_mode: str = None
    should_delete_pool_volumes: bool = False

    def __post_init__(self):
        if self.pool_volumes:
            self.pool_volumes = [
                (
                    PoolVolumesSpec(**volume)
                    if not isinstance(volume, PoolVolumesSpec)
                    else volume
                )
                for volume in self.pool_volumes
            ]
        if self.tier:
            self.tier = (
                Tier(**self.tier) if not isinstance(self.tier, Tier) else self.tier
            )
        if self.start_ldev_id:
            self.start_ldev_id = normalize_ldev_id(self.start_ldev_id)
        if self.end_ldev_id:
            self.end_ldev_id = normalize_ldev_id(self.end_ldev_id)
        if self.ldev_ids:
            self.ldev_ids = [normalize_ldev_id(ldev_id) for ldev_id in self.ldev_ids]


@dataclass
class TierObject(SingleBaseClass):
    tierNumber: int = None
    tierLevelRange: str = None
    tierDeltaRange: str = None
    tierUsedCapacity: int = None
    tierTotalCapacity: int = None
    tablespaceRate: int = None
    performanceRate: int = None
    progressOfReplacing: int = None
    bufferRate: int = None

    def camel_to_snake_dict(self):
        data = super().camel_to_snake_dict()
        if data.get("tier_total_capacity", None):
            data["tier_total_capacity_mb"] = data.pop("tier_total_capacity")
        if data.get("tier_used_capacity", None):
            data["tier_used_capacity_mb"] = data.pop("tier_used_capacity")
        return data


@dataclass
class TierUpdated(TierObject):
    raidLevel: str = None
    raidType: str = None
    driveSpeed: int = None
    driveTypeName: str = None
    substance: str = None


@dataclass
class VSPDpVolume(SingleBaseClass):
    logicalUnitId: int = None
    size: int = None


@dataclass
class DataReductionAccelerateCompIncludingSystemData_object(SingleBaseClass):
    isReductionCapacityAvailable: bool = None
    reductionCapacity: int = None
    isReductionRateAvailable: bool = None
    reductionRate: int = None


@dataclass
class DataReductionIncludingSystemDataObject(SingleBaseClass):
    isReductionCapacityAvailable: bool = None
    reductionCapacity: int = None
    isReductionRateAvailable: bool = None
    reductionRate: int = None


@dataclass
class CapacitiesExcludingSystemDataObject(SingleBaseClass):
    usedVirtualVolumeCapacity: Optional[int] = None
    compressedCapacity: Optional[int] = None
    dedupedCapacity: Optional[int] = None
    reclaimedCapacity: Optional[int] = None
    systemDataCapacity: Optional[int] = None
    preUsedCapacity: Optional[int] = None
    preCompressedCapacity: Optional[int] = None
    preDedupredCapacity: Optional[int] = None


@dataclass
class VSPPfrestStoragePool(SingleBaseClass):
    poolId: Optional[int] = None
    poolName: Optional[str] = None
    poolType: Optional[str] = None
    poolStatus: Optional[str] = None
    usedCapacityRate: Optional[int] = None
    availableVolumeCapacity: Optional[int] = None
    totalPoolCapacity: Optional[int] = None
    totalLocatedCapacity: Optional[int] = None
    warningThreshold: Optional[int] = None
    depletionThreshold: Optional[int] = None
    virtualVolumeCapacityRate: Optional[int] = None
    locatedVolumeCount: Optional[int] = None
    snapshotCount: Optional[int] = None
    isShrinking: Optional[bool] = None
    usedPhysicalCapacityRate: Optional[int] = None
    availablePhysicalVolumeCapacity: Optional[int] = None
    totalPhysicalCapacity: Optional[int] = None
    numOfLdevs: Optional[int] = None
    firstLdevId: Optional[int] = None
    suspendSnapshot: Optional[bool] = None
    snapshotUsedCapacity: Optional[int] = None
    blockingMode: Optional[str] = None
    totalReservedCapacity: Optional[int] = None
    reservedVolumeCount: Optional[int] = None
    poolActionMode: Optional[str] = None
    monitoringMode: Optional[str] = None
    tierOperationStatus: Optional[str] = None
    dat: Optional[str] = None
    tiers: Optional[List[TierObject]] = None
    duplicationLdevIds: Optional[List[int]] = None
    duplicationNumber: Optional[int] = None
    dataReductionAccelerateCompCapacity: Optional[int] = None
    dataReductionCapacity: Optional[int] = None
    dataReductionBeforeCapacity: Optional[int] = None
    dataReductionAccelerateCompRate: Optional[int] = None
    dataReductionRate: Optional[int] = None
    dataReductionAccelerateCompIncludingSystemData: Optional[
        DataReductionAccelerateCompIncludingSystemData_object
    ] = None
    dataReductionIncludingSystemData: Optional[
        DataReductionIncludingSystemDataObject
    ] = None
    capacitiesExcludingSystemData: Optional[CapacitiesExcludingSystemDataObject] = None
    compressionRate: Optional[int] = None
    duplicationRate: Optional[int] = None
    isMainframe: Optional[bool] = None
    effectiveCapacity: Optional[int] = None
    usedPhysicalCapacity: Optional[int] = None
    hasBlockedPoolVolume: Optional[bool] = None
    # dpVolumes: List[VSPDpVolume] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__post_init__(**kwargs)

    def __post_init__(self, **kwargs):
        # super().__init__(**kwargs)
        # if self.dpVolumes:
        #     self.dpVolumes = [VSPDpVolume(**dp) for dp in self.dpVolumes]

        if self.isShrinking:
            self.poolStatus = "SHRINKING"
        else:
            if self.poolStatus == "POLN":
                self.poolStatus = "NORMAL"
            elif self.poolStatus == "POLF":
                self.poolStatus = "OVER_THRESHOLD"
            elif self.poolStatus == "POLS":
                self.poolStatus = "SUSPENDED"
            elif self.poolStatus == "POLE":
                self.poolStatus = "FAILURE"
            else:
                self.poolStatus = "UNKNOWN"
        if self.capacitiesExcludingSystemData:
            self.capacitiesExcludingSystemData = CapacitiesExcludingSystemDataObject(
                **self.capacitiesExcludingSystemData
            )
        if self.dataReductionAccelerateCompIncludingSystemData:
            self.dataReductionAccelerateCompIncludingSystemData = (
                DataReductionAccelerateCompIncludingSystemData_object(
                    **self.dataReductionAccelerateCompIncludingSystemData
                )
            )
        if self.dataReductionIncludingSystemData:
            self.dataReductionIncludingSystemData = (
                DataReductionIncludingSystemDataObject(
                    **self.dataReductionIncludingSystemData
                )
            )
        if self.tiers is not None:
            self.tiers = [
                (
                    TierUpdated(**tier)
                    if tier.get("raidLevel", None)
                    else TierObject(**tier)
                )
                for tier in self.tiers
            ]

    def camel_to_snake_dict(self):
        """
        Convert the dataclass instance to a dictionary with snake_case keys,
        replacing None values with default fillers based on data type.
        """
        result = super().camel_to_snake_dict()
        # Handle specific fields that need special treatment
        if result.get("total_located_capacity") is not None:
            result["total_located_capacity_mb"] = result.pop("total_located_capacity")
        if result.get("total_physical_capacity") is not None:
            result["total_physical_capacity_mb"] = result.pop("total_physical_capacity")
        if result.get("available_volume_capacity") is not None:
            result["available_volume_capacity_mb"] = result.pop(
                "available_volume_capacity"
            )
        if result.get("total_pool_capacity") is not None:
            result["total_pool_capacity_mb"] = result.pop("total_pool_capacity")
        if result.get("snapshot_used_capacity") is not None:
            result["snapshot_used_capacity_mb"] = result.pop("snapshot_used_capacity")
        if result.get("available_physical_volume_capacity") is not None:
            result["available_physical_volume_capacity_mb"] = result.pop(
                "available_physical_volume_capacity"
            )
        if result.get("data_reduction_accelerate_comp_capacity") is not None:
            result["data_reduction_accelerate_comp_capacity_mb"] = result.pop(
                "data_reduction_accelerate_comp_capacity"
            )

        if result.get("data_reduction_capacity") is not None:
            result["data_reduction_capacity_mb"] = result.pop("data_reduction_capacity")
        if result.get("data_reduction_before_capacity") is not None:
            result["data_reduction_before_capacity_mb"] = result.pop(
                "data_reduction_before_capacity"
            )
        if result.get("total_reserved_capacity") is not None:
            result["total_reserved_capacity_mb"] = result.pop("total_reserved_capacity")

        if result.get("effective_capacity") is not None:
            result["effective_capacity_mb"] = result.pop("effective_capacity")
        return result


@dataclass
class VSPPfrestStoragePoolExtended(VSPPfrestStoragePool):
    relocationInterval: Optional[int] = None
    monitoringStartTime: Optional[str] = None
    monitoringEndTime: Optional[str] = None
    lastMonitoringEndTime: Optional[str] = None
    lastMonitoringStartTime: Optional[str] = None
    relocationSpeed: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPPfrestStoragePoolList(BaseDataClass):
    data: List[VSPPfrestStoragePool] = None


@dataclass
class VSPPfrestStoragePoolExtendedList(BaseDataClass):
    data: List[VSPPfrestStoragePoolExtended] = None


@dataclass
class VSPPfrestLdev(SingleBaseClass):
    ldevId: int = None
    blockCapacity: int = None
    resourceGroupId: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPPfrestLdevList(BaseDataClass):
    data: List[VSPPfrestLdev] = None


@dataclass
class UAIGStoragePool(SingleBaseClass):

    resourceId: str = None
    name: str = None
    type: str = None
    poolId: int = None
    status: str = None
    utilizationRate: int = None
    freeCapacity: int = None
    freeCapacityInUnits: str = None
    totalCapacity: int = None
    totalCapacityInUnit: str = None
    warningThresholdRate: int = None
    depletionThresholdRate: int = None
    subscriptionLimitRate: int = None
    virtualVolumeCount: int = None
    subscriptionRate: int = None
    ldevIds: List[int] = None
    dpVolumes: List[VSPDpVolume] = None
    deduplicationEnabled: bool = None
    entitlementStatus: str = None
    partnerId: str = None
    subscriberId: str = None
    resourceGroupId: int = None
    replicationDataReleasedRate: int = None
    warningThresholdRate: int = None
    virtualVolumeCount: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        pool_info = kwargs.get("storagePoolInfo")
        if pool_info:
            self.type = pool_info.get("poolType", None)
            self.name = pool_info.get("poolName", None)
            self.dpVolumes = pool_info.get("dpVolumes", [])
            self.deduplicationEnabled = pool_info.get("isDeduplicationEnabled", None)
            self.depletionThresholdRate = pool_info.get("depletionThresholdRate", None)
            for field in self.__dataclass_fields__.keys():
                if not getattr(self, field):
                    setattr(self, field, pool_info.get(field, None))


class UAIGStoragePools(BaseDataClass):
    data: List[UAIGStoragePool] = None


@dataclass
class JournalVolumeSpec:
    journal_id: int = None
    start_ldev_id: int = None
    end_ldev_id: int = None
    data_overflow_watch_in_seconds: int = None
    mp_blade_id: int = None
    is_cache_mode_enabled: bool = None
    ldev_ids: List[int] = None
    mirror_unit_number: int = None
    copy_pace: str = None
    path_blockade_watch_in_minutes: int = None

    def __post_init__(self):
        if self.start_ldev_id:
            self.start_ldev_id = normalize_ldev_id(self.start_ldev_id)
        if self.end_ldev_id:
            self.end_ldev_id = normalize_ldev_id(self.end_ldev_id)
        if self.ldev_ids:
            self.ldev_ids = [normalize_ldev_id(ldev_id) for ldev_id in self.ldev_ids]


@dataclass
class JournalVolumeFactSpec:
    journal_id: Optional[int] = None
    is_free_journal_pool_id: Optional[bool] = None
    free_journal_pool_id_count: Optional[int] = None
    is_mirror_not_used: Optional[bool] = None
