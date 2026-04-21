from dataclasses import dataclass
from typing import List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class SDSBPfrestSavingEffectOfStorage(SingleBaseClass):
    efficiencyDataReduction: int = None
    totalEfficiency: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class SDSBPfrestStorageClusterInfo(SingleBaseClass):
    storageDeviceId: str = None
    id: str = None
    modelName: str = None
    internalId: str = None
    nickname: str = None
    numberOfTotalVolumes: int = None
    numberOfTotalServers: int = None
    numberOfTotalStorageNodes: int = None
    numberOfReadyStorageNodes: int = None
    numberOfFaultDomains: int = None
    totalPoolRawCapacity: int = None
    totalPoolPhysicalCapacity: int = None
    totalPoolCapacity: int = None
    usedPoolCapacity: int = None
    freePoolCapacity: int = None
    savingEffects: SDSBPfrestSavingEffectOfStorage = None
    softwareVersion: str = None
    statusSummary: str = None
    status: str = None
    writeBackModeWithCacheProtection: str = None
    metaDataRedundancyOfCacheProtectionSummary: str = None
    systemRequirementsFileVersion: str = None
    serviceId: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class SDSBPfrestResourceStatusOfHealthStatus(SingleBaseClass):
    type: str = None
    status: str = None
    protectionDomainId: str = None


@dataclass
class SDSBPfrestHealthStatus(SingleBaseClass):
    resources: List[SDSBPfrestResourceStatusOfHealthStatus] = None


@dataclass
class SDSBPfrestDrive(SingleBaseClass):
    id: str = None
    wwid: str = None
    statusSummary: str = None
    status: str = None
    typeCode: str = None
    serialNumber: str = None
    storageNodeId: str = None
    deviceFileName: str = None
    vendorName: str = None
    firmwareRevision: str = None
    locatorLedStatus: str = None
    driveType: str = None
    driveCapacity: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class SDSBPfrestDriveList(BaseDataClass):
    data: List[SDSBPfrestDrive] = None


@dataclass
class SDSBPfrestPort(SingleBaseClass):
    id: str = None
    protocol: str = None
    type: str = None
    nickname: str = None
    name: str = None
    configuredPortSpeed: str = None
    portSpeed: str = None
    portSpeedDuplex: str = None
    protectionDomainId: str = None
    storageNodeId: str = None
    interfaceName: str = None
    statusSummary: str = None
    status: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class SDSBPfrestPortList(BaseDataClass):
    data: List[SDSBPfrestPort] = None


@dataclass
class SDSBPfrestPool(SingleBaseClass):
    id: str = None
    name: str = None
    protectionDomainId: str = None
    statusSummary: str = None
    status: str = None
    totalCapacity: int = None
    totalRawCapacity: int = None
    usedCapacity: int = None
    freeCapacity: int = None
    totalPhysicalCapacity: int = None
    metaDataPhysicalCapacity: int = None
    reservedPhysicalCapacity: int = None
    usablePhysicalCapacity: int = None
    blockedPhysicalCapacity: int = None
    totalVolumeCapacity: int = None
    provisionedVolumeCapacity: int = None
    otherVolumeCapacity: int = None
    temporaryVolumeCapacity: int = None
    numberOfVolumes: int = None
    redundantPolicy: str = None
    redundantType: str = None
    dataRedundancy: int = None
    storageControllerCapacitiesGeneralStatus: str = None
    rebuildCapacityPolicy: str = None
    rebuildCapacityStatus: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class SDSBPfrestPoolList(BaseDataClass):
    data: List[SDSBPfrestPool] = None


@dataclass
class SDSBHealthStatus(SingleBaseClass):
    type: str = None
    status: str = None
    protectionDomainId: str = None


@dataclass
class SDSBStorageSystemInfo(SingleBaseClass):
    healthStatuses: List[SDSBHealthStatus] = None
    numberOfTotalVolumes: int = None
    numberOfTotalServers: int = None
    numberOfTotalStorageNodes: int = None
    numberOfFaultDomains: int = None
    totalPoolCapacityInMb: int = None
    usedPoolCapacityInMb: int = None
    freePoolCapacityInMb: int = None
    totalEfficiency: int = None
    efficiencyDataReduction: int = None
    numberOfDrives: int = None
    numberOfComputePorts: int = None
    numberOfStoragePools: int = None
    apiVersion: str = None
    productName: str = None
    clusterId: str = None
    clusterName: str = None
    writeBackModeWithCacheProtection: str = None
