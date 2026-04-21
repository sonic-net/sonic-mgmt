from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import convert_keys_to_snake_case
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import convert_keys_to_snake_case


@dataclass
class SDSBRemotePathGroupFactSpec:
    id: Optional[str] = None
    local_storage_controller_id: Optional[str] = None
    remote_serial: Optional[str] = None
    remote_storage_system_type: Optional[str] = None
    path_group_id: Optional[str] = None


@dataclass
class SDSBRemotePathGroupSpec(SingleBaseClass):
    id: Optional[str] = None
    remote_serial: Optional[str] = None
    remote_storage_system_type: Optional[str] = None
    path_group_id: Optional[int] = None
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    remote_io_timeout_in_sec: Optional[int] = None

    comments: Optional[str] = None
    errors: Optional[str] = None

    def __post_init__(self):
        if self.remote_io_timeout_in_sec is not None and not (
            10 <= self.remote_io_timeout_in_sec <= 80
        ):
            raise ValueError("remote_io_timeout_in_sec must be between 10-80.")


@dataclass
class RemotePathGroupSummaryResponse(SingleBaseClass):
    id: Optional[str] = None
    localStorageControllerId: Optional[str] = None
    remoteSerialNumber: Optional[str] = None
    remoteStorageTypeId: Optional[str] = None
    pathGroupId: Optional[int] = None
    protocol: Optional[str] = None
    cuType: Optional[str] = None
    cuStatus: Optional[str] = None
    numberOfPaths: Optional[int] = None
    timeoutValueForRemoteIOInSeconds: Optional[int] = None

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        return camel_dict


@dataclass
class RemotePathGroupSummaryList(BaseDataClass):
    data: List[RemotePathGroupSummaryResponse] = None


@dataclass
class RemotePathResponse(SingleBaseClass):
    protocol: Optional[str] = None
    localPortNumber: Optional[str] = None
    remotePortNumber: Optional[str] = None
    pathStatus: Optional[str] = None

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        return camel_dict


@dataclass
class RemotePathGroupResponse(RemotePathGroupSummaryResponse):
    remotePaths: Optional[List[RemotePathResponse]] = None

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        camel_dict["remote_paths"] = convert_keys_to_snake_case(
            camel_dict["remote_paths"]
        )
        return camel_dict
