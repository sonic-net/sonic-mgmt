from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from .sdsb_port_auth_models import SDSBPortAuthInfo
    from .sdsb_chap_user_models import SDSBChapUserInfo
    from ..common.ansible_common import dicts_to_dataclass_list
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from .sdsb_port_auth_models import SDSBPortAuthInfo
    from .sdsb_chap_user_models import SDSBChapUserInfo
    from common.ansible_common import dicts_to_dataclass_list


@dataclass
class PortFactSpec:
    nicknames: Optional[List[str]] = None
    names: Optional[List[str]] = None


@dataclass
class ComputePortSpec:
    id: Optional[str] = None
    name: Optional[str] = None
    nick_name: Optional[str] = None
    protocol: Optional[str] = None


@dataclass
class Ipv4Information:
    address: str
    subnetMask: str
    defaultGateway: str


@dataclass
class Ipv6Information:
    linklocalAddressMode: str
    linklocalAddress: str
    globalAddressMode: str
    globalAddress1: str
    subnetPrefixLength1: str
    defaultGateway: str


@dataclass
class IsnsServer:
    index: int
    serverName: str
    port: int


@dataclass
class IscsiInformation:
    ipMode: str
    ipv4Information: Ipv4Information
    ipv6Information: Ipv6Information
    delayedAck: bool
    mtuSize: int
    isIsnsClientEnabled: bool
    isnsServers: List[IsnsServer]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "ipv4Information" in kwargs:
            self.ipv4Information = Ipv4Information(**kwargs.get("ipv4Information"))
        if "ipv6Information" in kwargs:
            self.ipv6Information = Ipv4Information(**kwargs.get("ipv6Information"))
        if "isnsServers" in kwargs:
            self.isnsServers = dicts_to_dataclass_list(
                kwargs.get("isnsServers"), IsnsServer
            )


@dataclass
class NvmeTcpInformation:
    ipMode: str
    ipv4Information: Ipv4Information
    ipv6Information: Ipv6Information
    delayedAck: bool
    mtuSize: int
    macAddress: str

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "ipv4Information" in kwargs:
            self.ipv4Information = Ipv4Information(**kwargs.get("ipv4Information"))
        if "ipv6Information" in kwargs:
            self.ipv6Information = Ipv4Information(**kwargs.get("ipv6Information"))


@dataclass
class SDSBComputePortInfo(SingleBaseClass):
    id: str
    protocol: str
    type: str
    name: str
    nickname: str
    configuredPortSpeed: str
    portSpeed: str
    portNumber: str
    protectionDomainId: str
    storageNodeId: str
    interfaceName: str
    statusSummary: str
    status: str
    fcInformation: str
    iscsiInformation: IscsiInformation
    nvmeTcpInformation: NvmeTcpInformation
    portSpeedDuplex: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "portNumber" in kwargs:
            self.portNumber = kwargs.get("portNumber")

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBPortDetailInfo(SingleBaseClass):
    portInfo: SDSBComputePortInfo
    portAuthInfo: SDSBPortAuthInfo
    chapUsersInfo: List[SDSBChapUserInfo]

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBPortDetailInfoList(BaseDataClass):
    data: List[SDSBPortDetailInfo]


@dataclass
class SDSBComputePortsInfo(BaseDataClass):
    data: List[SDSBComputePortInfo]
