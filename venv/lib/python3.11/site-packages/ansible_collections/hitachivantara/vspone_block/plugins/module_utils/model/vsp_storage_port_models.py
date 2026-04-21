from dataclasses import dataclass, asdict, fields
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class ShortPortInfo(SingleBaseClass):
    portId: Optional[str] = None
    portType: Optional[str] = None
    portAttributes: Optional[List[str]] = None
    portSpeed: Optional[str] = None
    loopId: Optional[str] = None
    fabricMode: Optional[bool] = None
    portConnection: Optional[str] = None
    portSecuritySetting: Optional[bool] = None
    wwn: Optional[str] = None
    portMode: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for field in fields(self):
            if field.name not in kwargs:
                setattr(self, field.name, None)
            if kwargs.get("lunSecuritySetting"):
                self.portSecuritySetting = kwargs.get("lunSecuritySetting")


@dataclass
class ShortPortInfoList(BaseDataClass):
    data: List[ShortPortInfo] = None


@dataclass
class PingInfo(SingleBaseClass):
    receivedPackets: Optional[int] = None
    transmittedPackets: Optional[int] = None


@dataclass
class PortInfo(SingleBaseClass):
    portId: Optional[str] = None
    portType: Optional[str] = None
    portAttributes: Optional[List[str]] = None
    portSpeed: Optional[str] = None
    loopId: Optional[str] = None
    fabricMode: Optional[bool] = None
    portConnection: Optional[str] = None
    portSecuritySetting: Optional[bool] = None
    wwn: Optional[str] = None
    logins: Optional[List] = None
    tcpMtu: Optional[str] = None
    iscsiWindowSize: Optional[str] = None
    keepAliveTimer: Optional[int] = None
    tcpPort: Optional[str] = None
    macAddress: Optional[str] = None
    ipv4Address: Optional[str] = None
    ipv4Subnetmask: Optional[str] = None
    ipv4GatewayAddress: Optional[str] = None
    portMode: Optional[str] = None
    # portAttributes: Optional[List] = None

    def to_dict(self):
        return asdict(self)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for field in fields(self):
            if field.name not in kwargs:
                setattr(self, field.name, None)
            if kwargs.get("lunSecuritySetting"):
                self.portSecuritySetting = kwargs.get("lunSecuritySetting")


@dataclass
class PortsInfo(BaseDataClass):
    data: List[PortInfo] = None


@dataclass
class ExternalIscsiTarget:
    ip_address: Optional[str] = None
    name: Optional[str] = None
    tcp_port: Optional[int] = None


@dataclass
class ChangePortSettingSpec:
    port: Optional[str] = None
    port_attribute: Optional[str] = None
    port_mode: Optional[str] = None
    port_speed: Optional[str] = None
    fabric_mode: Optional[bool] = None
    port_connection: Optional[str] = None
    enable_port_security: Optional[bool] = None
    host_ip_address: Optional[str] = None
    external_iscsi_targets: Optional[List[ExternalIscsiTarget]] = None


@dataclass
class PortFactSpec:
    ports: Optional[List] = None
    query: Optional[List[str]] = None
    external_iscsi_ip_address: Optional[str] = None
    external_iscsi_name: Optional[str] = None
    external_tcp_port: Optional[int] = None
    external_wwn: Optional[str] = None


@dataclass
class PortInfoUAIG:
    portType: str = None
    portId: str = None
    speed: str = None
    resourceGroupId: int = 0
    isSecurityEnabled: bool = False
    attribute: str = None
    connectionType: str = None
    mode: str = None
    iscsiPortIpAddress: str = None


@dataclass
class VSPPortInfoUAIG(SingleBaseClass):
    resourceId: str = None
    type: str = None
    storageId: str = None
    entitlementStatus: str = None
    partnerId: str = None
    subscriberId: str = None
    portInfo: PortInfoUAIG = None

    # tags: List[str] = None
    # fabricOn: bool = False


@dataclass
class VSPPortsInfoUAIG(BaseDataClass):
    data: List[VSPPortInfoUAIG] = None
