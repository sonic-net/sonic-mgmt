from dataclasses import dataclass  # , asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class StorageSystemFactSpec:
    query: Optional[List[str]] = None
    refresh: Optional[bool] = None


@dataclass
class VSPStorageSystemsInfoPfrest:
    storageDeviceId: str = None
    model: str = None
    serialNumber: int = None
    svpIp: str = None
    ctl1Ip: str = None
    ctl2Ip: str = None

    def __init__(self, **kwargs):
        self.storageDeviceId = kwargs.get("storageDeviceId")
        self.model = kwargs.get("model")
        self.serialNumber = kwargs.get("serialNumber")
        if "svpIp" in kwargs:
            self.svpIp = kwargs.get("svpIp")
        if "ctl1Ip" in kwargs:
            self.ctl1Ip = kwargs.get("ctl1Ip")
        if "ctl2Ip" in kwargs:
            self.ctl2Ip = kwargs.get("ctl2Ip")


@dataclass
class VSPStorageSystemsInfoPfrestList(BaseDataClass):
    data: List[VSPStorageSystemsInfoPfrest]


@dataclass
class DedupCompression(SingleBaseClass):
    totalRatio: str = None
    compressionRatio: str = None
    dedupeRatio: str = None
    reclaimRatio: str = None


@dataclass
class AcceleratedCompression(SingleBaseClass):
    totalRatio: str = None
    compressionRatio: str = None
    reclaimRatio: str = None


@dataclass
class TotalEfficiency(SingleBaseClass):
    isCalculated: bool = None
    totalRatio: str = None
    compressionRatio: str = None
    snapshotRatio: str = None
    provisioningRate: str = None
    calculationStartTime: str = None
    calculationEndTime: str = None
    dedupeAndCompression: dict = None
    acceleratedCompression: dict = None

    def __post_init__(self):
        if self.dedupeAndCompression:
            self.dedupeAndCompression = DedupCompression(**self.dedupeAndCompression)
        if self.acceleratedCompression:
            self.acceleratedCompression = AcceleratedCompression(
                **self.acceleratedCompression
            )


@dataclass
class VSPStorageSystemInfoPfrest:
    storageDeviceId: str = None
    model: str = None
    serialNumber: str = None
    svpIp: str = None
    ctl1Ip: str = None
    ctl2Ip: str = None
    dkcMicroVersion: str = None
    detailDkcMicroVersion: str = None
    ctl1MicroVersion: str = None
    ctl2MicroVersion: str = None
    communicationModes: List[dict] = None
    isSecure: bool = None
    totalEfficiency: dict = None

    def __init__(self, **kwargs):
        self.storageDeviceId = kwargs.get("storageDeviceId")
        self.model = kwargs.get("model")
        self.serialNumber = str(kwargs.get("serialNumber"))
        if "svpIp" in kwargs:
            self.svpIp = kwargs.get("svpIp")
        if "ctl1Ip" in kwargs:
            self.ctl1Ip = kwargs.get("ctl1Ip")
        if "ctl2Ip" in kwargs:
            self.ctl2Ip = kwargs.get("ctl2Ip")
        self.dkcMicroVersion = kwargs.get("dkcMicroVersion")
        self.detailDkcMicroVersion = kwargs.get("detailDkcMicroVersion")
        if "ctl1MicroVersion" in kwargs:
            self.ctl1MicroVersion = kwargs.get("ctl1MicroVersion")
        if "ctl2MicroVersion" in kwargs:
            self.ctl2MicroVersion = kwargs.get("ctl2MicroVersion")
        self.communicationModes = kwargs.get("communicationModes")
        self.isSecure = kwargs.get("isSecure")


@dataclass
class VSPMirrorUnit:
    muNumber: int = None
    consistencyGroupId: int = None
    journalStatus: str = None
    pathBlockadeWatchInMinutes: int = None
    copyPace: str = None
    copySpeed: int = None
    isDataCopying: bool = None


@dataclass
class VSPDetailedJournalPoolPfrest:
    journalId: str = None
    isMainframe: bool = None
    isCacheModeEnabled: bool = None
    isInflowControlEnabled: bool = None
    dataOverflowWatchInSeconds: int = None
    copySpeed: int = None
    isDataCopying: bool = None
    mpBladeId: int = None
    mirrorUnits: List[VSPMirrorUnit] = None
    journalStatus: str = None


@dataclass
class VSPDetailedJournalPoolPfrestList(BaseDataClass):
    data: List[VSPDetailedJournalPoolPfrest]


@dataclass
class VSPBasicJournalPoolPfrest(SingleBaseClass):
    journalId: str = None
    muNumber: int = None
    consistencyGroupId: int = None
    journalStatus: str = None
    numOfActivePaths: int = None
    usageRate: int = None
    qMarker: str = None
    qCount: int = None
    byteFormatCapacity: str = None
    blockCapacity: int = None
    numOfLdevs: int = None
    firstLdevId: int = None


@dataclass
class VSPBasicJournalPoolPfrestList(BaseDataClass):
    data: List[VSPBasicJournalPoolPfrest] = None


@dataclass
class VSPNormalizedJournalPool:
    data_overflow_watch_seconds: int = None
    is_cache_mode_enabled: bool = None
    is_inflow_control_enabled: bool = None
    logical_unit_ids: List[int] = None
    logical_unit_ids_hex_format: List[str] = None
    mirror_unit_id: int = None
    mp_blade_id: int = None
    timer_type: str = None
    total_capacity: int = None
    type: str = None
    usage_rate: int = None


@dataclass
class VSPPortPfrest:
    portId: str = None
    portType: str = None
    portAttributes: List[str] = None
    portSpeed: str = None
    loopId: str = None
    fabricMode: bool = None
    portConnection: str = None
    lunSecuritySetting: bool = None
    wwn: str = None
    portMode: str = None


@dataclass
class VSPPortPfrestList(BaseDataClass):
    data: List[VSPPortPfrest]


@dataclass
class VSPNormalizedPort:
    port_id: str = None
    type: str = None
    speed: str = None
    resource_group_id: int = None
    wwn: str = None
    resource_id: str = None
    # tags: List[str] = None
    attribute: str = None
    connection_type: str = None
    fabric_on: bool = None
    mode: str = None
    iscsi_port_ip_address: str = None
    is_security_enabled: bool = None


@dataclass
class VSPDataReductionAccelerateCompIncludingSystemData:
    isReductionCapacityAvailable: bool = None
    reductionCapacity: int = None
    isReductionRateAvailable: bool = None
    reductionRate: int = None


@dataclass
class VSPDataReductionIncludingSystemData:
    isReductionCapacityAvailable: bool = None
    reductionCapacity: int = None
    isReductionRateAvailable: bool = None
    reductionRate: int = None


@dataclass
class VSPCapacitiesExcludingSystemData:
    usedVirtualVolumeCapacity: int = None
    compressedCapacity: int = None
    dedupedCapacity: int = None
    reclaimedCapacity: int = None
    systemDataCapacity: int = None
    preUsedCapacity: int = None
    preCompressedCapacity: int = None
    preDedupredCapacity: int = None


@dataclass
class VSPTier:
    tierNumber: int = None
    tierLevelRange: str = None
    tierDeltaRange: str = None
    diskType: str = None
    tierUsedPhysicalCapacity: int = None
    tierTotalPhysicalCapacity: int = None
    tierUsedCapacity: int = None
    tierTotalCapacity: int = None
    tablespaceRate: int = None
    performanceRate: int = None
    progressOfReplacing: int = None
    bufferRate: int = None


@dataclass
class VSPPoolPfrest:
    poolId: int = None
    poolName: str = None
    poolType: str = None
    poolStatus: str = None
    usedCapacityRate: int = None
    usedPhysicalCapacityRate: int = None
    availableVolumeCapacity: int = None
    availablePhysicalVolumeCapacity: int = None
    totalPoolCapacity: int = None
    totalPhysicalCapacity: int = None
    numOfLdevs: int = None
    firstLdevId: int = None
    warningThreshold: int = None
    depletionThreshold: int = None
    suspendSnapshot: bool = None
    virtualVolumeCapacityRate: int = None
    isShrinking: bool = None
    locatedVolumeCount: int = None
    totalLocatedCapacity: bool = None
    snapshotCount: int = None
    snapshotUsedCapacity: bool = None
    blockingMode: str = None
    totalReservedCapacity: int = None
    reservedVolumeCount: int = None
    poolActionMode: str = None
    monitoringMode: str = None
    tierOperationStatus: str = None
    dat: str = None
    tiers: List[VSPTier] = None
    duplicationLdevIds: List[int] = None
    duplicationNumber: int = None
    dataReductionAccelerateCompCapacity: int = None
    dataReductionCapacity: int = None
    dataReductionBeforeCapacity: int = None
    dataReductionAccelerateCompRate: int = None
    dataReductionRate: int = None
    dataReductionAccelerateCompIncludingSystemData: (
        VSPDataReductionAccelerateCompIncludingSystemData
    ) = None
    dataReductionIncludingSystemData: VSPDataReductionIncludingSystemData = None
    capacitiesExcludingSystemData: VSPCapacitiesExcludingSystemData = None
    compressionRate: int = None
    duplicationRate: int = None
    isMainframe: bool = None


@dataclass
class VSPPoolPfrestList(BaseDataClass):
    data: List[VSPPoolPfrest]


@dataclass
class VSPDpVolume:
    logicalUnitId: int = None
    size: str = None


@dataclass
class VSPNormalizedPool:
    resource_id: str = None
    pool_id: int = None
    ldev_ids: List[int] = None
    name: str = None
    depletion_threshold_rate: int = None
    dp_volumes: List[VSPDpVolume] = None
    free_capacity: int = None
    free_capacity_in_units: str = None
    replication_data_released_rate: int = None
    replication_depletion_alert_rate: int = None
    replication_usage_rate: int = None
    resource_group_id: int = None
    status: str = None
    subscription_limit_rate: int = None
    subscription_rate: int = None
    subscription_warning_rate: int = None
    total_capacity: int = None
    total_capacity_in_unit: str = None
    type: str = None
    utilization_rate: int = None
    virtual_volume_count: int = None
    warning_threshold_rate: int = None
    deduplication_enabled: bool = None


@dataclass
class VSPQuorumDiskPfrest:
    quorumDiskId: int = None
    remoteSerialNumber: str = None
    remoteStorageTypeId: str = None
    ldevId: int = None
    readResponseGuaranteedTime: int = None
    status: str = None


@dataclass
class VSPQuorumDiskPfrestList(BaseDataClass):
    data: List[VSPQuorumDiskPfrest]


@dataclass
class VSPNormalizedQuorumDisk:
    device_id: str = None
    device_type: str = None
    grid: str = None
    logical_unit_id: int = None
    quorum_disk_id: int = None
    status: str = None
    timeout: int = None


@dataclass
class VSPFreeLunPfrest:
    ldevId: int = None
    virtualLdevId: int = None
    emulationType: str = None
    ssid: str = None
    resourceGroupId: int = None


@dataclass
class VSPFreeLunPfrestList(BaseDataClass):
    data: List[VSPFreeLunPfrest]


@dataclass
class VSPNormalizedFreeLun:
    ldev_ids: List[int] = None


@dataclass
class VSPPrimaryAndSecondarySyslogServer:
    isEnabled: bool = None
    ipAddress: str = None
    port: int = None


@dataclass
class VSPSyslogServerPfrest(SingleBaseClass):
    transferProtocol: str = None
    locationName: str = None
    retries: bool = None
    retryInterval: int = None
    isDetailed: bool = None
    primarySyslogServer: VSPPrimaryAndSecondarySyslogServer = None
    secondarySyslogServer: VSPPrimaryAndSecondarySyslogServer = None


@dataclass
class TotalCapacitiesPfrest:
    freeSpace: int = None
    totalCapacity: int = None


@dataclass
class VSPStorageCapacitiesPfrest(SingleBaseClass):
    total: TotalCapacitiesPfrest = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPSyslogServer:
    id: int = None
    syslog_server_address: str = None
    syslog_server_port: str = None


@dataclass
class VSPSyslogConfig:
    syslog_servers: List[VSPSyslogServer] = None
    detailed: bool = None


@dataclass
class VSPLimits:
    is_valid: bool = None
    max_value: int = None
    min_value: int = None


@dataclass
class VSPDeviceLimits:
    external_group_number_range: VSPLimits = None
    external_group_sub_number_range: VSPLimits = None
    parity_group_number_range: VSPLimits = None
    parity_group_sub_number_range: VSPLimits = None


@dataclass
class StorageSystemDateTime(SingleBaseClass):
    isNtpEnabled: bool = None
    ntpServerNames: List[str] = None
    timeZoneId: str = None
    systemTime: str = None
    synchronizingLocalTime: str = None
    adjustsDaylightSavingTime: bool = None


@dataclass
class TimeZoneInfo(SingleBaseClass):
    timeZoneId: str = None
    timeZone: str = None
    displayName: str = None
    observesDaylightSavingTime: bool = None


@dataclass
class TimeZonesInfo(BaseDataClass):
    data: List[TimeZoneInfo] = None


@dataclass
class VSPStorageSystemInfo(SingleBaseClass):
    model: str = None
    serial_number: str = None
    microcode_version: str = None
    management_address: str = None
    controller_address: str = None
    total_capacity: str = None
    total_capacity_in_mb: int = None
    free_capacity: str = None
    free_capacity_in_mb: int = None
    resource_state: str = None
    health_status: str = None
    operational_status: str = None
    free_gad_consistency_group_id: int = None
    free_local_clone_consistency_group_id: int = None
    free_remote_clone_consistency_group_id: int = None
    syslog_config: VSPSyslogConfig = None
    device_limits: VSPDeviceLimits = None
    health_description: str = None
    journal_pools: List[VSPNormalizedJournalPool] = None
    ports: List[VSPNormalizedPort] = None
    storage_pools: List[VSPNormalizedPool] = None
    quorum_disks: List[VSPNormalizedQuorumDisk] = None
    free_logical_unit_list: VSPNormalizedFreeLun = None
    total_efficiency: TotalEfficiency = None
    system_date_time: StorageSystemDateTime = None
    time_zones_info: TimeZonesInfo = None


@dataclass
class StorageDevice:
    serialNumber: str = None
    resourceId: str = None
    address: str = None
    model: str = None
    microcodeVersion: str = None
    resourceState: str = None
    healthStatus: str = None
    ucpSystems: List[str] = None
    gatewayAddress: str = None


@dataclass
class UCPStorageSystemInfo(SingleBaseClass):
    resourceId: str = None
    name: str = None
    resourceState: str = None
    computeDevices: List[str] = None
    storageDevices: List[StorageDevice] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for key, value in kwargs.items():
            setattr(self, key, value)
        storage_devices = kwargs.get("storageDevices")
        if storage_devices:
            self.storageDevices = [
                StorageDevice(**device) for device in storage_devices
            ]


@dataclass
class UCPStorageSystemsInfo(BaseDataClass):
    data: List[UCPStorageSystemInfo] = None


@dataclass
class DateTimeSpec(SingleBaseClass):
    is_ntp_enabled: bool = None
    ntp_server_names: list = None
    time_zone_id: str = None
    system_time: str = None
    synchronizing_local_time: str = None
    adjusts_daylight_saving_time: bool = None
    synchronizes_now: bool = None


@dataclass
class VSPStorageSystemSpec(SingleBaseClass):
    date_time: DateTimeSpec = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.date_time = DateTimeSpec(**kwargs.get("date_time", {}))


@dataclass
class VSPStorageSystemMonitorSpec(SingleBaseClass):
    query: str = None
    alert_type: str = None
    alert_start_number: int = None
    alert_count: int = None
    include_component_option: bool = False


@dataclass
class ActionCode(SingleBaseClass):
    actionCode: int = None
    possibleFailureParts: str = None
    accLocation: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for key, value in kwargs.items():
            setattr(self, key, value)


@dataclass
class VSPAlertInfo(SingleBaseClass):
    alertIndex: str = None
    alertID: int = None
    occurenceTime: str = None
    referenceCode: int = None
    errorLevel: str = None
    errorSection: str = None
    errorDetail: str = None
    location: str = None
    actionCodes: List[ActionCode] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for key, value in kwargs.items():
            setattr(self, key, value)
        action_codes = kwargs.get("actionCodes")
        if action_codes:
            self.actionCodes = [ActionCode(**ac) for ac in action_codes]


@dataclass
class VSPAlertInfoList(BaseDataClass):
    data: List[VSPAlertInfo] = None


@dataclass
class VSPChannelBoardInfo(SingleBaseClass):
    channelBoardId: int = None
    location: str = None
    clusterNumber: int = None
    channelBoardNumber: int = None
    channelBoardType: str = None
    numOfPorts: str = None
    maxPortSpeed: str = None
    cableMaterial: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for key, value in kwargs.items():
            setattr(self, key, value)


@dataclass
class VSPChannelBoardInfoList(BaseDataClass):
    data: List[VSPChannelBoardInfo] = None
