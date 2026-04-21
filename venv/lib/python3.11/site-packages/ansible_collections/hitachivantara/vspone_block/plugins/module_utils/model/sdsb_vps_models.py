from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import SingleBaseClass
except ImportError:
    from common_base_models import SingleBaseClass


@dataclass
class VpsDefaultVolumeSettings:
    poolId: Optional[str] = None  # required
    upperLimitForNumberOfVolumes: Optional[int] = -1  # required
    upperLimitForCapacityOfVolumes: Optional[int] = -1  # required
    upperLimitForCapacityOfSingleVolume: Optional[int] = -1
    upperLimitForIopsOfVolume: Optional[int] = -1
    upperLimitForTransferRateOfVolume: Optional[int] = -1
    upperAlertAllowableTimeOfVolume: Optional[int] = -1
    savingSettingOfVolume: Optional[str] = None  # Disabled, Compression
    savingModeOfVolume: Optional[str] = None  # Inline, nullable


@dataclass
class QosParam:
    upperLimitForIopsOfVolume: int
    upperLimitForTransferRateOfVolume: int
    upperAlertAllowableTimeOfVolume: int


@dataclass
class VolumeSettings(SingleBaseClass):
    poolId: str
    upperLimitForNumberOfVolumes: int
    numberOfVolumesCreated: int
    upperLimitForCapacityOfVolumes: int
    capacityOfVolumesCreated: int
    upperLimitForCapacityOfSingleVolume: int
    savingSettingOfVolume: str
    savingModeOfVolume: str
    qosParam: QosParam

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__post_init__()

    def __post_init__(self):
        if self.qosParam:
            self.qosParam = QosParam(**self.qosParam)

    def to_dict(self):
        return asdict(self)


@dataclass
class VpsVolumeSettingsSpec:
    pool_id: Optional[str] = None  # required
    upper_limit_for_number_of_volumes: Optional[int] = None  # required
    upper_limit_for_capacity_of_volumes_mb: Optional[int] = None  # required
    upper_limit_for_capacity_of_single_volume_mb: Optional[int] = None
    upper_limit_for_iops_of_volume: Optional[int] = None
    upper_limit_for_transfer_rate_of_volume_mbps: Optional[int] = None
    upper_alert_allowable_time_of_volume: Optional[int] = None
    capacity_saving: Optional[str] = None  # Disabled, Compression

    def to_dict(self):
        return asdict(self)


@dataclass
class VpsSpec:
    id: Optional[str] = None
    name: Optional[str] = None  # required for rest API create call
    upper_limit_for_number_of_user_groups: Optional[int] = None
    upper_limit_for_number_of_users: Optional[int] = None
    upper_limit_for_number_of_sessions: Optional[int] = None
    upper_limit_for_number_of_servers: Optional[int] = (
        None  # required for rest API create call
    )
    volume_settings: Optional[List[VpsVolumeSettingsSpec]] = None  # required
    upper_limit_for_number_of_volumes: Optional[int] = None  # required
    upper_limit_for_capacity_of_volumes_mb: Optional[int] = None  # required
    upper_limit_for_capacity_of_single_volume_mb: Optional[int] = None
    upper_limit_for_iops_of_volume: Optional[int] = None
    upper_limit_for_transfer_rate_of_volume_mbps: Optional[int] = None
    upper_alert_allowable_time_of_volume: Optional[int] = None
    capacity_saving: Optional[str] = None

    def __init__(self, **kwargs):
        for field in self.__dataclass_fields__.keys():
            setattr(self, field, kwargs.get(field, None))
        self.__post_init__()

    def __post_init__(self):
        if self.volume_settings:
            self.volume_settings = [
                VpsVolumeSettingsSpec(**vs) for vs in self.volume_settings
            ]


@dataclass
class VpsFactSpec:
    id: Optional[str] = None
    name: Optional[str] = None


@dataclass
class SDSBVpsInfo(SingleBaseClass):
    id: str
    name: str
    upperLimitForNumberOfUserGroups: int
    numberOfUserGroupsCreated: int
    upperLimitForNumberOfUsers: int
    numberOfUsersCreated: int
    upperLimitForNumberOfSessions: int
    numberOfSessionsCreated: int
    upperLimitForNumberOfServers: int
    numberOfServersCreated: int
    upperLimitForNumberOfHbas: int
    numberOfHbasCreated: int
    upperLimitForNumberOfVolumeServerConnections: int
    numberOfVolumeServerConnectionsCreated: int
    volumeSettings: VolumeSettings

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__post_init__()

    def __post_init__(self):
        if self.volumeSettings:
            self.volumeSettings = VolumeSettings(**self.volumeSettings)

    def to_dict(self):
        return asdict(self)


@dataclass
class SummaryInformation(SingleBaseClass):
    totalCount: int
    totalUpperLimitForNumberOfUserGroups: int
    totalUpperLimitForNumberOfUsers: int
    totalUpperLimitForNumberOfSessions: int
    totalUpperLimitForNumberOfVolumes: int
    totalUpperLimitForCapacityOfVolumes: int
    totalUpperLimitForNumberOfServers: int
    totalUpperLimitForNumberOfHbas: int
    totalUpperLimitForNumberOfVolumeServerConnections: int

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBVpsListInfo:
    data: List[SDSBVpsInfo] = None
    summaryInformation: SummaryInformation = None

    def __init__(self, data=None, summaryInformation=None):
        self.data = data if data is not None else []
        self.summaryInformation = (
            summaryInformation if summaryInformation is not None else dict()
        )

    def data_to_list(self):
        return {
            "data": [item.to_dict() for item in self.data],
            "summaryInformation": asdict(self.summaryInformation),
        }

    def __setattr__(self, name, value):
        if name == "data" or name == "summaryInformation":
            super().__setattr__(name, value)
        else:
            raise AttributeError("Cannot set attribute directly")
