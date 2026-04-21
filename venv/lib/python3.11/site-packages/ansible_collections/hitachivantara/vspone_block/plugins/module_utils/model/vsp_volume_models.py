from dataclasses import dataclass, field, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        convert_capacity_to_mib,
        normalize_ldev_id,
        volume_id_to_hex_format,
    )

except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.hv_log import Log
    from ..common.ansible_common import (
        convert_capacity_to_mib,
        normalize_ldev_id,
        volume_id_to_hex_format,
    )

logger = Log()


@dataclass
class VolumeFactSpec:
    ldev_id: Optional[int] = None
    name: Optional[str] = None
    count: Optional[int] = None
    end_ldev_id: Optional[int] = None
    start_ldev_id: Optional[int] = None
    is_detailed: Optional[bool] = None
    query: Optional[List[str]] = None
    pool_id: Optional[int] = None
    resource_group_id: Optional[int] = None
    journal_id: Optional[int] = None
    parity_group_id: Optional[str] = None

    def __post_init__(self):
        if self.ldev_id:
            self.ldev_id = normalize_ldev_id(self.ldev_id)
        if self.start_ldev_id:
            self.start_ldev_id = normalize_ldev_id(self.start_ldev_id)
        if self.end_ldev_id:
            self.end_ldev_id = normalize_ldev_id(self.end_ldev_id)


@dataclass
class TieringPolicySpec:
    tier_level: Optional[int] = None
    tier1_allocation_rate_min: Optional[int] = None
    tier1_allocation_rate_max: Optional[int] = None
    tier3_allocation_rate_min: Optional[int] = None
    tier3_allocation_rate_max: Optional[int] = None


@dataclass
class VolumeQosParamsOutput:
    upperIops: Optional[int] = field(default=-1)
    upperTransferRate: Optional[int] = field(default=-1)
    upperAlertAllowableTime: Optional[int] = field(default=-1)
    upperAlertTime: Optional[int] = field(default=-1)
    lowerIops: Optional[int] = field(default=-1)
    lowerTransferRate: Optional[int] = field(default=-1)
    lowerAlertAllowableTime: Optional[str] = field(default=-1)
    lowerAlertTime: Optional[int] = field(default=-1)
    responsePriority: Optional[int] = field(default=-1)
    targetResponseTime: Optional[int] = field(default=-1)
    responseAlertAllowableTime: Optional[int] = field(default=-1)
    responseAlertTime: Optional[int] = field(default=-1)


@dataclass
class VolumeQosParamsSpec:
    upper_iops: int = None
    upper_transfer_rate: int = None
    upper_alert_allowable_time: int = None
    lower_iops: int = None
    lower_transfer_rate: int = None
    lower_alert_allowable_time: int = None
    response_priority: int = None
    response_alert_allowable_time: int = None


@dataclass
class CreateVolumeSpec:
    data_reduction_share: Optional[bool] = None
    name: Optional[str] = None
    size: Optional[str] = None
    block_size: Optional[int] = None
    ldev_id: Optional[int] = None
    vldev_id: Optional[int] = None
    pool_id: Optional[int] = None
    capacity_saving: Optional[str] = None
    parity_group: Optional[str] = None
    force: Optional[bool] = None
    is_relocation_enabled: Optional[bool] = None
    is_compression_acceleration_enabled: Optional[bool] = None
    compression_acceleration_status: Optional[str] = None
    tier_level_for_new_page_allocation: Optional[str] = None
    tiering_policy: Optional[TieringPolicySpec] = None
    nvm_subsystem_name: Optional[str] = None
    host_nqns: Optional[List[str]] = None
    state: Optional[str] = None
    should_shred_volume_enable: Optional[bool] = None
    qos_settings: Optional[VolumeQosParamsSpec] = None
    mp_blade_id: Optional[int] = None
    clpr_id: Optional[int] = None
    should_reclaim_zero_pages: Optional[bool] = None
    # Added for UCA-3302
    is_parallel_execution_enabled: Optional[bool] = None
    start_ldev_id: Optional[int] = None
    end_ldev_id: Optional[int] = None
    external_parity_group: Optional[str] = None
    is_compression_acceleration_enabled: Optional[bool] = None
    should_format_volume: Optional[bool] = None
    data_reduction_process_mode: Optional[str] = None
    is_relocation_enabled: Optional[bool] = None
    is_full_allocation_enabled: Optional[bool] = None
    is_alua_enabled: Optional[bool] = None
    format_type: Optional[str] = None
    is_task_timeout: Optional[bool] = None
    # added comment for ldev module
    comment: Optional[str] = None

    def __post_init__(self):
        if self.qos_settings:
            self.qos_settings = VolumeQosParamsSpec(**self.qos_settings)
        if self.ldev_id:
            self.ldev_id = normalize_ldev_id(self.ldev_id)
        if self.vldev_id:
            self.vldev_id = normalize_ldev_id(self.vldev_id)
        if self.start_ldev_id:
            self.start_ldev_id = normalize_ldev_id(self.start_ldev_id)
        if self.end_ldev_id:
            self.end_ldev_id = normalize_ldev_id(self.end_ldev_id)


@dataclass
class SalamanderNicknameParam:
    base_name: str
    start_number: Optional[int] = None
    number_of_digits: Optional[int] = None


@dataclass
class VSPPortInfo(SingleBaseClass):
    portId: Optional[str] = None
    hostGroupNumber: Optional[int] = None
    hostGroupName: Optional[str] = None
    lun: Optional[int] = None


@dataclass
class VSPVolumeSnapshotInfo(SingleBaseClass):
    pvolLdevId: Optional[int] = None
    muNumber: Optional[int] = None
    svolLdevId: Optional[int] = None


@dataclass
class VSPVolumePortInfo(SingleBaseClass):
    portId: Optional[int] = None
    id: Optional[int] = None
    name: Optional[str] = None


@dataclass
class VSPVolumeNvmSubsystenInfo(SingleBaseClass):
    id: Optional[int] = None
    name: Optional[str] = None
    ports: Optional[List[str]] = None
    host_nqns: Optional[List[str]] = None


@dataclass
class VSPVolumeInfo(SingleBaseClass):

    ldevId: int
    clprId: int
    emulationType: str
    externalVolumeId: Optional[str] = None
    externalVolumeIdString: Optional[str] = None
    byteFormatCapacity: Optional[str] = None
    blockCapacity: Optional[int] = None
    numOfPorts: Optional[int] = None
    externalPorts: Optional[List[VSPPortInfo]] = None
    ports: Optional[List[VSPPortInfo]] = None
    composingPoolId: Optional[int] = None
    attributes: Optional[List[str]] = None
    raidLevel: Optional[str] = None
    raidType: Optional[str] = None
    numOfParityGroups: Optional[int] = None
    parityGroupIds: Optional[List[str]] = None
    driveType: Optional[str] = None
    driveByteFormatCapacity: Optional[str] = None
    driveBlockCapacity: Optional[int] = None
    label: Optional[str] = None
    status: Optional[str] = None
    mpBladeId: Optional[int] = None
    ssid: Optional[str] = None
    resourceGroupId: Optional[int] = None
    isAluaEnabled: Optional[bool] = None
    virtualLdevId: Optional[int] = None
    poolId: Optional[int] = None
    numOfUsedBlock: Optional[int] = None
    dataReductionMode: Optional[str] = None
    dataReductionStatus: Optional[str] = None
    dataReductionProcessMode: Optional[str] = None
    isEncryptionEnabled: Optional[bool] = None
    isDRS: Optional[bool] = None
    namespaceId: Optional[str] = None
    nvmSubsystemId: Optional[str] = None
    snapshots: Optional[List[VSPVolumeSnapshotInfo]] = None
    hostgroups: Optional[List[VSPVolumePortInfo]] = None
    iscsiTargets: Optional[List[VSPVolumePortInfo]] = None
    nvmSubsystems: List[VSPVolumeNvmSubsystenInfo] = None
    canonicalName: Optional[str] = None
    storageSerialNumber: Optional[str] = None
    isDataReductionShareEnabled: Optional[bool] = None
    qosSettings: Optional[VolumeQosParamsOutput] = None
    virtualLdevId: Optional[int] = None
    isCommandDevice: Optional[bool] = None
    isSecurityEnabled: Optional[bool] = None
    isUserAuthenticationEnabled: Optional[bool] = None
    isDeviceGroupDefinitionEnabled: Optional[bool] = None
    naaId: Optional[str] = None
    tierLevel: Optional[int] = None
    tierLevelForNewPageAllocation: Optional[str] = None
    tier1AllocationRateMin: Optional[int] = None
    tier1AllocationRateMax: Optional[int] = None
    tier3AllocationRateMin: Optional[int] = None
    tier3AllocationRateMax: Optional[int] = None
    isCompressionAccelerationEnabled: Optional[bool] = None
    compressionAccelerationStatus: Optional[str] = None
    dataReductionProcessMode: Optional[str] = None
    isRelocationEnabled: Optional[bool] = None
    isFullAllocationEnabled: Optional[bool] = None

    def __init__(self, **kwargs):
        try:
            from ..common.vsp_utils import NAIDCalculator
            from ..common.vsp_constants import get_basic_storage_details
        except ImportError:
            from common.vsp_utils import NAIDCalculator
            from common.vsp_constants import get_basic_storage_details

        super().__init__(**kwargs)
        try:
            storage_info = get_basic_storage_details()
            if storage_info is None:
                return
            self.storageSerialNumber = storage_info.serialNumber
            if self.naaId is None:
                if storage_info.firstWWN and self.canonicalName is None:
                    self.canonicalName = NAIDCalculator(
                        storage_info.firstWWN,
                        int(storage_info.serialNumber),
                        storage_info.model,
                    ).calculate_naid(kwargs.get("ldevId", None))
            else:
                self.canonicalName = self.naaId

            self.isDataReductionShareEnabled = (
                True if "DRS" in self.attributes else None
            )

            if self.qosSettings is not None:
                self.qosSettings = VolumeQosParamsOutput(**self.qosSettings)

        except Exception as ex:
            logger.writeDebug(f"MODEL: exception in initializing VSPVolumeInfo {ex}")
        return


@dataclass
class VSPVolumesInfo(BaseDataClass):
    data: List[VSPVolumeInfo] = None


@dataclass
class VSPVolumeDetailInfo(SingleBaseClass):
    volumeInfo: VSPVolumeInfo
    snapshotInfo: List[VSPVolumeSnapshotInfo]
    hostgroupInfo: List[VSPVolumePortInfo]
    iscsiTargetInfo: List[VSPVolumePortInfo]
    nvmSubsystemInfo: List[VSPVolumeNvmSubsystenInfo]

    def to_dict(self):
        return asdict(self)


@dataclass
class VSPVolumeDetailInfoList(BaseDataClass):
    data: List[VSPVolumeDetailInfo]


@dataclass
class VSPStorageVolumeUAIGInfo(SingleBaseClass):
    ldevId: int = -1
    poolId: int = -1
    totalCapacity: int = 0
    usedCapacity: int = 0
    poolName: str = None


@dataclass
class VSPStorageVolumeUAIG(SingleBaseClass):
    resourceId: str = None
    type: str = None
    storageId: str = None
    entitlementStatus: str = None
    partnerId: str = None
    subscriberId: str = None
    storageVolumeInfo: VSPStorageVolumeUAIGInfo = None


@dataclass
class VSPStorageVolumesUAIG(BaseDataClass):
    data: List[VSPStorageVolumeUAIG] = None


@dataclass
class PortGroups:
    group: int = -1
    lun: int = -1
    port: str = None


@dataclass
class Policy:
    level: int = -1
    tier1AllocRateMin: int = -1
    tier1AllocRateMax: int = -1
    tier3AllocRateMin: int = -1
    tier3AllocRateMax: int = -1


@dataclass
class TieringPropertiesDto:
    policy: Policy = None
    tier1UsedCapacityMB: int = -1
    tier2UsedCapacityMB: int = -1
    tier3UsedCapacityMB: int = -1
    tierLevelForNewPageAlloc: str = None


@dataclass
class VSPVolume_V2:
    resourceId: str = None
    deduplicationCompressionMode: str = None
    emulationType: str = None
    formatOrShredRate: int = 0
    ldevId: int = 0
    name: str = None
    parityGroupId: str = None
    poolId: int = 0
    resourceGroupId: int = 0
    status: str = None
    totalCapacity: int = 0
    usedCapacity: int = 0
    virtualStorageDeviceId: str = None
    stripeSize: int = 0
    type: str = None
    pathCount: int = 0
    provisionType: str = None
    isCommandDevice: bool = False
    logicalUnitIdHexFormat: str = None
    virtualLogicalUnitId: int = 0
    naaId: str = None
    dedupCompressionProgress: int = -1
    dedupCompressionStatus: str = None
    isALUA: bool = False
    isDynamicPoolVolume: bool = False
    isJournalPoolVolume: bool = False
    isPoolVolume: bool = False
    poolName: str = None
    quorumDiskId: int = -1
    isDRS: bool = False
    isInGadPair: bool = False
    isInTrueCopy: bool = False
    isVVol: bool = False
    portGroups: List[PortGroups] = None
    nvmNamespaceId: int = -1
    nvmSubsystemId: int = -1
    tieringPropertiesDto: TieringPropertiesDto = None
    isTieringRelocation: Optional[bool] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class VSPUndefinedVolumeInfo:
    ldevId: int = 0
    emulationType: str = None
    ssid: str = None
    resourceGroupId: int = 0
    virtualLdevId: int = 0


@dataclass
class VSPUndefinedVolumeInfoList(BaseDataClass):
    data: List[VSPUndefinedVolumeInfo] = None


@dataclass
class VolumeQosThreshold(SingleBaseClass):
    isUpperIopsEnabled: Optional[bool] = None
    upperIops: Optional[int] = None
    isUpperTransferRateEnabled: Optional[bool] = None
    upperTransferRate: Optional[int] = None
    isLowerIopsEnabled: Optional[bool] = None
    lowerIops: Optional[int] = None
    isLowerTransferRateEnabled: Optional[bool] = None
    lowerTransferRate: Optional[int] = None
    isResponsePriorityEnabled: Optional[bool] = None
    responsePriority: Optional[str] = None
    targetResponseTime: Optional[int] = None


@dataclass
class VolumeQosAlertSetting(SingleBaseClass):
    isUpperAlertEnabled: Optional[bool] = None
    upperAlertAllowableTime: Optional[int] = None
    isLowerAlertEnabled: Optional[bool] = None
    lowerAlertAllowableTime: Optional[int] = None
    isResponseAlertEnabled: Optional[bool] = None
    responseAlertAllowableTime: Optional[int] = None


@dataclass
class VolumeQosAlertTime(SingleBaseClass):
    # No fields specified in example, placeholder for future extension
    upperAlertTime: Optional[int] = None
    lowerAlertTime: Optional[int] = None
    responseAlertTime: Optional[int] = None


@dataclass
class SimpleVolumeQosConfig(SingleBaseClass):
    # volumeId: int
    threshold: Optional[VolumeQosThreshold] = None
    alertSetting: Optional[VolumeQosAlertSetting] = None
    alertTime: Optional[VolumeQosAlertTime] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__post_init__()

    def __post_init__(self):
        if self.threshold:
            self.threshold = VolumeQosThreshold(**self.threshold)
        if self.alertSetting:
            self.alertSetting = VolumeQosAlertSetting(**self.alertSetting)
        if self.alertTime:
            self.alertTime = VolumeQosAlertTime(**self.alertTime)


@dataclass
class SimpleAPILuns(SingleBaseClass):
    lun: int
    portId: str
    serverId: int


@dataclass
class SalamanderSimpleVolumeInfo(SingleBaseClass):
    id: Optional[int] = None
    nickname: Optional[str] = None
    poolId: Optional[int] = None
    poolName: Optional[str] = None
    totalCapacity: Optional[int] = None
    totalCapacityInMB: Optional[int] = None
    freeCapacity: Optional[int] = None
    freeCapacityInMB: Optional[int] = None
    usedCapacity: Optional[int] = None
    usedCapacityInMB: Optional[int] = None
    reservedCapacity: Optional[int] = None
    savingSetting: Optional[str] = None
    capacitySaving: Optional[str] = None
    isDataReductionShareEnabled: Optional[bool] = None
    compressionAcceleration: Optional[bool] = None
    compressionAccelerationStatus: Optional[str] = None
    capacitySavingStatus: Optional[str] = None
    numberOfConnectingServers: Optional[int] = None
    numberOfSnapshots: Optional[int] = None
    volumeTypes: Optional[List[str]] = None
    luns: Optional[List[str]] = None
    qosSettings: Optional[dict] = None
    parentVolumeId: Optional[int] = None
    capacitySavingProgress: Optional[int] = None

    def __post_init__(self):
        # if self.qosSettings:
        #     self.qosSettings = SimpleVolumeQosConfig(**self.qosSettings)
        if self.totalCapacity is not None:
            # Convert totalCapacity from bytes to MiB
            self.totalCapacityInMB = self.totalCapacity
        if self.usedCapacity is not None:
            # Convert usedCapacity from bytes to MiB
            self.usedCapacityInMB = self.usedCapacity
        if self.freeCapacity is not None:
            # Convert freeCapacity from bytes to MiB
            self.freeCapacityInMB = self.freeCapacity
        if self.luns is not None:
            self.luns = [SimpleAPILuns(**lun) for lun in self.luns]
        if self.capacitySaving is None:
            self.capacitySaving = self.savingSetting

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        camel_dict.pop("saving_setting")
        camel_dict["id_hex"] = volume_id_to_hex_format(self.id)
        camel_dict["parent_volume_id_hex"] = volume_id_to_hex_format(
            self.parentVolumeId
        )
        return camel_dict


@dataclass
class SalamanderVSPVolumesInfo(BaseDataClass):
    data: List[SalamanderSimpleVolumeInfo] = None


@dataclass
class VolumeQosThresholdSimple(SingleBaseClass):
    is_upper_iops_enabled: Optional[bool] = None
    upper_iops: Optional[int] = None
    is_upper_transfer_rate_enabled: Optional[bool] = None
    upper_transfer_rate: Optional[int] = None
    is_lower_iops_enabled: Optional[bool] = None
    lower_iops: Optional[int] = None
    is_lower_transfer_rate_enabled: Optional[bool] = None
    lower_transfer_rate: Optional[int] = None
    is_response_priority_enabled: Optional[bool] = None
    response_priority: Optional[int] = None


@dataclass
class SimpleVolumeQosAlert(SingleBaseClass):
    is_upper_alert_enabled: Optional[bool] = None
    upper_alert_allowable_time: Optional[int] = None
    is_lower_alert_enabled: Optional[bool] = None
    lower_alert_allowable_time: Optional[int] = None
    is_response_alert_enabled: Optional[bool] = None
    response_alert_allowable_time: Optional[int] = None


@dataclass
class SimpleVolumeQosParamsSpec(SingleBaseClass):
    threshold: Optional[VolumeQosThresholdSimple] = None
    alert_setting: Optional[SimpleVolumeQosAlert] = None

    def __post_init__(self):
        if self.threshold:
            self.threshold = VolumeQosThresholdSimple(**self.threshold)
        if self.alert_setting:
            self.alert_setting = SimpleVolumeQosAlert(**self.alert_setting)


@dataclass
class SalamanderCreateVolumeRequestSpec(SingleBaseClass):
    capacity: Optional[int] = None  # in MiB
    number_of_volumes: Optional[int] = 1
    volume_name: Optional[SalamanderNicknameParam] = None
    # saving_setting: Optional[str] = None
    capacity_saving: Optional[str] = None
    is_data_reduction_share_enabled: Optional[bool] = False
    pool_id: Optional[int] = None
    volume_id: Optional[int] = None
    qos_settings: Optional[SimpleVolumeQosParamsSpec] = None
    server_ids: Optional[List[str]] = None
    comments: Optional[List[str]] = None
    compression_acceleration: Optional[bool] = None
    volume_ids: Optional[List[int]] = None  # For multiple volume

    def __post_init__(self):
        # Convert dict to NicknameParam instance if needed
        if self.volume_name and isinstance(self.volume_name, dict):
            self.volume_name = SalamanderNicknameParam(**self.volume_name)
        if self.capacity is not None:
            # Convert capacity from string to MiB
            self.capacity = convert_capacity_to_mib(self.capacity)
        if self.comments is None:
            self.comments = []
        if self.qos_settings and isinstance(self.qos_settings, dict):
            self.qos_settings = SimpleVolumeQosParamsSpec(**self.qos_settings)
        if self.volume_id:
            self.volume_id = normalize_ldev_id(self.volume_id)
        if self.volume_ids:
            self.volume_ids = [
                normalize_ldev_id(ldev_id) for ldev_id in self.volume_ids
            ]


@dataclass
class SalamanderVolumeServerLunInfo(SingleBaseClass):
    lun: int
    portId: str


@dataclass
class SalamanderVolumeServerInfo(SingleBaseClass):
    id: str
    volumeId: int
    serverId: int
    luns: List[SalamanderVolumeServerLunInfo]

    def __post_init__(self):
        # Ensure luns is a list of SalamanderVolumeServerLunInfo instances
        if self.luns:
            self.luns = [
                (
                    lun
                    if isinstance(lun, SalamanderVolumeServerLunInfo)
                    else SalamanderVolumeServerLunInfo(**lun)
                )
                for lun in self.luns
            ]


@dataclass
class SalamanderVolumeServerConnectionInfo(BaseDataClass):
    data: List[SalamanderVolumeServerInfo] = None


@dataclass
class SimpleAPIVolumeFactsSpec(SingleBaseClass):
    pool_id: Optional[int] = None
    pool_name: Optional[str] = None
    server_id: Optional[int] = None
    server_nickname: Optional[str] = None
    nickname: Optional[str] = None
    min_total_capacity: Optional[str] = None
    max_total_capacity: Optional[str] = None
    min_used_capacity: Optional[str] = None
    max_used_capacity: Optional[str] = None
    start_volume_id: Optional[int] = None
    count: Optional[int] = None
    volume_id: Optional[int] = None
    comments: Optional[List[str]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for key, value in kwargs.items():
            if isinstance(value, int) and value < 0:
                raise ValueError(
                    f"Invalid value for '{key}': Negative value is not allowed"
                )
        count = kwargs.get("count", None)
        if count is not None and count < 1:
            raise ValueError(
                "Invalid value for 'count': Must be greater than or equal to 1"
            )

        self.__post_init__()

    def __post_init__(self):
        if self.min_total_capacity is not None:
            self.min_total_capacity = convert_capacity_to_mib(self.min_total_capacity)
        if self.max_total_capacity is not None:
            self.max_total_capacity = convert_capacity_to_mib(self.max_total_capacity)
        if self.min_used_capacity is not None:
            self.min_used_capacity = convert_capacity_to_mib(self.min_used_capacity)
        if self.max_used_capacity is not None:
            self.max_used_capacity = convert_capacity_to_mib(self.max_used_capacity)
        if self.start_volume_id:
            self.start_volume_id = normalize_ldev_id(self.start_volume_id)
        if self.volume_id:
            self.volume_id = normalize_ldev_id(self.volume_id)
