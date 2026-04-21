from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class ParityGroupFactSpec:
    parity_group_id: Optional[str] = None


@dataclass
class ParityGroupSpec(SingleBaseClass):
    parity_group_id: Optional[str] = None
    drive_location_ids: Optional[List] = None
    raid_type: Optional[str] = None
    is_encryption_enabled: Optional[bool] = None
    is_copy_back_mode_enabled: Optional[bool] = None
    is_accelerated_compression_enabled: Optional[bool] = None
    clpr_id: Optional[int] = None


@dataclass
class VSPPfrestParityGroup(SingleBaseClass):
    parityGroupId: str = None
    availableVolumeCapacity: int = None
    raidLevel: str = None
    driveTypeName: str = None
    isCopyBackModeEnabled: bool = None
    isEncryptionEnabled: bool = None
    totalCapacity: int = None
    isAcceleratedCompressionEnabled: bool = None
    physicalCapacity: int = None
    # Not used fields
    # numOfLdevs: int = None
    # usedCapacityRate: int = None
    # availableVolumeCapacityInKB: int = None
    # raidType: str = None
    clprId: int = None
    # driveType: str = None
    # availablePhysicalCapacity: int = None
    # spaces: List[] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPPfrestParityGroupList(BaseDataClass):
    data: List[VSPPfrestParityGroup] = None


@dataclass
class VSPPfrestDrives(SingleBaseClass):
    driveLocationId: str = None
    driveTypeName: int = None
    # driveSpeed: int = None
    totalCapacity: int = None
    driveType: bool = None
    usageType: bool = None
    status: int = None
    parityGroupId: bool = None
    serialNumber: str = None


@dataclass
class VSPPfrestDrivesList(BaseDataClass):
    data: List[VSPPfrestDrives] = None


@dataclass
class DrivesFactSpec:
    drive_location_id: Optional[str] = None
    is_spared_drive: Optional[bool] = None


@dataclass
class VSPPfrestParityGroupSpace(SingleBaseClass):
    lbaSize: str = None
    ldevId: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPPfrestExternalParityGroup(SingleBaseClass):
    externalParityGroupId: str = None
    availableVolumeCapacity: int = None
    usedCapacityRate: int = None
    spaces: List[VSPPfrestParityGroupSpace] = None
    # Not used fields
    numOfLdevs: int = None
    emulationType: str = None
    clprId: int = None
    externalProductId: str = None
    availableVolumeCapacityInKB: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPPfrestExternalParityGroupList(BaseDataClass):
    data: List[VSPPfrestExternalParityGroup] = None


@dataclass
class VSPPfrestLdev(SingleBaseClass):
    ldevId: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPPfrestLdevList(BaseDataClass):
    data: List[VSPPfrestLdev] = None


@dataclass
class VSPParityGroup(SingleBaseClass):
    resourceId: str = None
    parityGroupId: str = None
    freeCapacity: str = None
    freeCapacity_mb: float = None
    resourceGroupId: int = None
    totalCapacity: str = None
    totalCapacity_mb: float = None
    ldevIds: List[int] = None
    raidLevel: str = None
    driveType: str = None
    copybackMode: bool = None
    # status: str = None
    isPoolArrayGroup: bool = None
    isAcceleratedCompression: bool = None
    isEncryptionEnabled: bool = None
    clprId: int = None


@dataclass
class VSPParityGroups(BaseDataClass):
    data: List[VSPParityGroup] = None


@dataclass
class VSPParityGroupUAIG(SingleBaseClass):
    resourceId: str = None
    parityGroupId: str = None
    freeCapacity: int = 0
    freeCapacity_mb: int = 0
    resourceGroupId: int = 0
    totalCapacity: int = 0
    totalCapacity_mb: int = 0
    ldevIds: List[int] = None
    raidLevel: str = None
    driveType: str = None
    copybackMode: bool = False
    status: str = None
    isPoolArrayGroup: bool = False
    isAcceleratedCompression: bool = False
    isEncryptionEnabled: bool = False


@dataclass
class VSPParityGroupsUAIG(BaseDataClass):
    data: List[VSPParityGroupUAIG] = None
