from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import SingleBaseClass, BaseDataClass
    from ..model.common_base_models import ConnectionInfo

except ImportError:
    from .common_base_models import SingleBaseClass, BaseDataClass
    from model.common_base_models import ConnectionInfo


@dataclass
class VSPRemoteStorageRegistrationFactSpec(SingleBaseClass):

    secondary_connection_info: Optional[ConnectionInfo] = None


@dataclass
class VSPRemoteStorageRegistrationSpec(SingleBaseClass):
    storage_device_id: Optional[str] = None
    rest_server_ip: Optional[str] = None
    rest_server_port: Optional[int] = None
    is_mutual_discovery: Optional[bool] = None
    is_mutual_deletion: Optional[bool] = None
    secondary_connection_info: Optional[ConnectionInfo] = None


@dataclass
class CommunicationMode:
    communicationMode: str = None

    def __init__(self, **kwargs):
        self.communicationMode = kwargs.get("communicationMode")

    def __eq__(self, other):
        if not isinstance(other, CommunicationMode):
            return False
        return self.communicationMode == other.communicationMode

    def __hash__(self):
        return hash(self.communicationMode)


@dataclass
class VSPRemoteStorageSystemsInfoPfrest:
    storageDeviceId: str = None
    dkcType: str = None
    restServerIp: str = None
    restServerPort: int = None
    model: str = None
    serialNumber: int = None
    ctl1Ip: str = None
    ctl2Ip: str = None
    communicationModes: list[CommunicationMode] = None

    def __init__(self, **kwargs):
        self.storageDeviceId = kwargs.get("storageDeviceId")
        self.dkcType = kwargs.get("dkcType")
        self.restServerIp = kwargs.get("restServerIp")
        self.restServerPort = kwargs.get("restServerPort")
        self.model = kwargs.get("model")
        self.serialNumber = kwargs.get("serialNumber")
        if "ctl1Ip" in kwargs:
            self.ctl1Ip = kwargs.get("ctl1Ip")
        if "ctl2Ip" in kwargs:
            self.ctl2Ip = kwargs.get("ctl2Ip")
        if "communicationModes" in kwargs:
            self.communicationModes = [
                CommunicationMode(**cmode) for cmode in kwargs.get("communicationModes")
            ]

    def __eq__(self, other):
        if not isinstance(other, VSPRemoteStorageSystemsInfoPfrest):
            return False
        return (
            self.storageDeviceId == other.storageDeviceId
            and self.serialNumber == other.serialNumber
        )

    def __hash__(self):
        return hash(
            (
                self.storageDeviceId,
                self.dkcType,
                self.restServerIp,
                self.model,
                self.serialNumber,
                self.restServerPort,
                self.ctl1Ip,
                self.ctl2Ip,
            )
        )


@dataclass
class VSPRemoteStorageSystemsInfoPfrestList(BaseDataClass):
    data: List[VSPRemoteStorageSystemsInfoPfrest]


@dataclass
class AllRemoteStorageSystemsInfoPfrest:
    storagesRegisteredInLocal: List[VSPRemoteStorageSystemsInfoPfrest]
    storagesRegisteredInRemote: List[VSPRemoteStorageSystemsInfoPfrest]

    def to_dict(self):
        return asdict(self)
