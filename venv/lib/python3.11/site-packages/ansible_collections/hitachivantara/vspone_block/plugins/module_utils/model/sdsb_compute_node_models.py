from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class ComputeNodeFactSpec:
    names: Optional[List[str]] = None
    hba_name: Optional[str] = None
    vps_name: Optional[str] = None
    vps_id: Optional[str] = None


# @dataclass
# class ComputePortFactSpec:
#     nicknames: Optional[List[str]] = None
#     names: Optional[List[str]] = None


@dataclass
class ComputeNodeSpec:
    id: Optional[str] = None
    name: Optional[str] = None
    vps_id: Optional[str] = None
    vps_name: Optional[str] = None
    os_type: Optional[str] = None
    state: Optional[str] = None
    iscsi_initiators: Optional[List[str]] = None
    volumes: Optional[List[str]] = None
    host_nqns: Optional[List[str]] = None
    should_delete_all_volumes: Optional[bool] = False


@dataclass
class HBAPorts:
    portId: str
    portName: str


@dataclass
class Path:
    hbaName: str
    portIds: Optional[List[str]] = None
    # protocol: str
    ports: Optional[List[HBAPorts]] = None


@dataclass
class HbaPortIdPair:
    hba_id: str
    port_id: str


@dataclass
class NameIdPair:
    name: str
    id: str


@dataclass
class HbaPathInfo:
    id: str
    serverId: str
    hbaName: str
    hbaId: str
    portId: str
    portName: str
    portNickname: str
    vpsId: str
    vpsName: str


@dataclass
class SDSBComputeNodeInfo:
    id: str = None
    nickname: str = None
    osType: str = None
    totalCapacity: int = -1
    usedCapacity: int = -1
    numberOfPaths: int = 0
    vpsId: str = None
    vpsName: str = None
    numberOfVolumes: int = 0
    # lun: int = -1
    paths: List[Path] = None

    def __init__(self, **kwargs):
        self.id = kwargs.get("id")
        self.nickname = kwargs.get("nickname")
        self.osType = kwargs.get("osType")
        self.totalCapacity = kwargs.get("totalCapacity")
        self.usedCapacity = kwargs.get("usedCapacity")
        self.vpsId = kwargs.get("vpsId")
        self.vpsName = kwargs.get("vpsName")
        if "numberOfVolumes" in kwargs:
            self.numberOfVolumes = kwargs.get("numberOfVolumes")
        if "numberOfPaths" in kwargs:
            self.numberOfPaths = kwargs.get("numberOfPaths")
        # if "lun" in kwargs:
        #     self.lun = kwargs.get("lun")
        if "paths" in kwargs:
            self.paths = [Path(**path) for path in kwargs.get("paths")]

    def to_dict(self):
        return asdict(self)


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


@dataclass
class SDSBComputeNodesInfo(BaseDataClass):
    data: List[SDSBComputeNodeInfo]


@dataclass
class VolumeSummaryInfo:
    id: str
    name: str


@dataclass
class SDSBComputeNodeAndVolumeInfo(SingleBaseClass):
    computeNodeInfo: SDSBComputeNodeInfo
    volumeInfo: List[VolumeSummaryInfo]

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBComputeNodeAndVolumeList(BaseDataClass):
    data: List[SDSBComputeNodeAndVolumeInfo]
