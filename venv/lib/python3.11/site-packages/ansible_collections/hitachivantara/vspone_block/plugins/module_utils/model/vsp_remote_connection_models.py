from dataclasses import dataclass, field
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class RemotePath(SingleBaseClass):
    cuType: Optional[str] = None
    portType: Optional[str] = None
    pathNumber: Optional[int] = None
    localPortId: Optional[str] = None
    remotePortId: Optional[str] = None
    pathStatus: Optional[str] = None


@dataclass
class VSPRemoteConnection(SingleBaseClass):
    remotepathGroupId: str = None
    remoteStorageDeviceId: str = None
    remoteSerialNumber: str = None
    remoteStorageModel: str = None
    remoteStorageTypeId: str = None
    pathGroupId: int = None
    cuType: str = None
    portType: str = None
    cuStatus: str = None
    minNumOfPaths: int = None
    numOfPaths: int = None
    timeoutValueForRemoteIOInSeconds: int = None
    roundTripTimeInMilliSeconds: int = None
    remotePaths: List[RemotePath] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for key, value in kwargs.items():
            if getattr(self, key) is None:
                setattr(self, key, value)
        self.__post_init__()

    def __post_init__(self, **kwargs):
        if self.remotePaths:
            self.remotePaths = [RemotePath(**x) for x in self.remotePaths]


@dataclass
class VSPRemoteConnections(BaseDataClass):
    data: List[VSPRemoteConnection] = None


@dataclass
class RemotePathSpec(SingleBaseClass):
    local_port: Optional[str] = None
    remote_port: Optional[str] = None


@dataclass
class RemoteConnectionSpec:
    path_group_id: int = None
    remote_paths: List[RemotePathSpec] = field(
        default_factory=list
    )  # Use default_factory
    min_remote_paths: int = None
    remote_io_timeout_in_sec: int = None
    round_trip_in_msec: int = None
    remote_storage_serial_number: str = None
    remote_storage_type_id: str = None
    object_id: str = None
    remote_storage_device_id: str = None

    def __post_init__(self, **kwargs):
        if self.remote_paths:
            self.remote_paths = [RemotePathSpec(**x) for x in self.remote_paths]


@dataclass
class RemoteConnectionFactSpec:
    path_group_id: Optional[int] = None


@dataclass
class RemoteIscsiConnection(SingleBaseClass):
    remoteIscsiPortId: Optional[str] = None
    localPortId: Optional[str] = None
    remoteStorageDeviceId: Optional[str] = None
    remoteSerialNumber: Optional[str] = None
    remoteStorageModel: Optional[str] = None
    remoteStorageTypeId: Optional[str] = None
    remotePortId: Optional[str] = None
    remoteIpAddress: Optional[str] = None
    remoteTcpPort: Optional[int] = None


@dataclass
class RemoteIscsiConnections(BaseDataClass):
    data: List[RemoteIscsiConnection] = None


@dataclass
class RemoteIscsiConnectionSpec(SingleBaseClass):
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    remote_storage_ip_address: Optional[str] = None
    remote_tcp_port: Optional[int] = None
    remote_storage_serial_number: Optional[str] = None
    remote_storage_type_id: Optional[str] = None
    object_id: Optional[str] = None


@dataclass
class RemoteIscsiConnectionFactSpec:
    remote_iscsi_port_id: Optional[str] = None
