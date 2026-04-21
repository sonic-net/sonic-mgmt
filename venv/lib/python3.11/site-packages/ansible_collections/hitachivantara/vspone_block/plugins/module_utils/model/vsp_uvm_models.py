from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import SingleBaseClass, BaseDataClass
except ImportError:
    from .common_base_models import SingleBaseClass, BaseDataClass


@dataclass
class ExternalIscsiFactSpec(SingleBaseClass):
    ports: Optional[List[str]] = None
    external_iscsi_ip_address: Optional[str] = None
    external_tcp_port: Optional[int] = None


@dataclass
class ExternalPathGroupFactSpec(SingleBaseClass):
    external_path_group_id: Optional[int] = None


@dataclass
class ExternalPathGroupSpec(SingleBaseClass):
    external_path_group_id: Optional[int] = None
    port: Optional[str] = None
    iscsi_ip_address: Optional[str] = None
    iscsi_name: Optional[str] = None
    wwn: Optional[str] = None
    tcp_port: Optional[int] = None


@dataclass
class RegisterIscsiNameSpec(SingleBaseClass):
    port: Optional[str] = None
    iscsi_ip_address: Optional[str] = None
    iscsi_name: Optional[str] = None
    wwn: Optional[str] = None
    tcp_port: Optional[int] = None


@dataclass
class ExternalIscsiTarget(SingleBaseClass):
    iscsiIpAddress: str
    tcpPort: int
    iscsiName: str
    authenticationMode: str
    iscsiTargetDirection: str
    chapUserName: str
    isSecretSet: bool
    virtualPortId: int
    isRegistered: bool

    def __init__(self, **kwargs):
        self.iscsiIpAddress = kwargs.get("iscsiIpAddress")
        self.tcpPort = kwargs.get("tcpPort")
        self.iscsiName = kwargs.get("iscsiName")
        self.authenticationMode = kwargs.get("authenticationMode")
        self.iscsiTargetDirection = kwargs.get("iscsiTargetDirection")
        self.chapUserName = kwargs.get("chapUserName")
        self.isSecretSet = kwargs.get("isSecretSet")
        self.virtualPortId = kwargs.get("virtualPortId")
        self.isRegistered = kwargs.get("isRegistered")

    def to_dict(self):
        return asdict(self)


@dataclass
class ExternalIscsiTargets(SingleBaseClass):
    portId: str
    externalIscsiTargets: List[ExternalIscsiTarget]

    def __init__(self, **kwargs):
        self.portId = kwargs.get("portId")
        self.externalIscsiTargets = kwargs.get("externalIscsiTargets", [])

    def to_dict(self):
        return asdict(self)


@dataclass
class ExternalPort(SingleBaseClass):
    portId: str
    externalSerialNumber: str
    externalStorageInfo: str
    externalPathMode: str
    externalIsUsed: bool
    externalWwn: str
    iscsiIpAddress: str
    iscsiName: str
    virtualPortId: int

    def __init__(self, **kwargs):
        self.portId = kwargs.get("portId")
        self.externalSerialNumber = kwargs.get("externalSerialNumber")
        self.externalStorageInfo = kwargs.get("externalStorageInfo")
        self.externalPathMode = kwargs.get("externalPathMode")
        self.externalIsUsed = kwargs.get("externalIsUsed")
        self.externalWwn = kwargs.get("externalWwn")
        self.iscsiIpAddress = kwargs.get("iscsiIpAddress")
        self.iscsiName = kwargs.get("iscsiName")
        self.virtualPortId = kwargs.get("virtualPortId")

    def to_dict(self):
        return asdict(self)


@dataclass
class ExternalPortList(BaseDataClass):
    data: List[ExternalPort]


@dataclass
class ExternalLun(SingleBaseClass):
    externalLun: int
    portId: str
    externalVolumeCapacity: int
    externalVolumeInfo: str
    iscsiIpAddress: str = None
    iscsiName: str = None
    virtualPortId: int = None
    externalWwn: str = None


@dataclass
class ExternalLunList(BaseDataClass):
    data: List[ExternalLun]
