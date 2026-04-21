from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import normalize_ldev_id
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import normalize_ldev_id


@dataclass
class VSPNvmNamespaceSpec(SingleBaseClass):
    ldev_id: Optional[int] = None
    nickname: Optional[str] = None
    paths: Optional[List[str]] = None


@dataclass
class VSPNvmHostNqnSpec(SingleBaseClass):
    nqn: Optional[str] = None
    nickname: Optional[str] = None


@dataclass
class VSPNvmeSubsystemSpec(SingleBaseClass):
    id: Optional[int] = None
    name: Optional[str] = None
    host_mode: Optional[str] = None
    # host_mode_options: Optional[List[int]] = None
    enable_namespace_security: Optional[bool] = True
    ports: Optional[List[str]] = None
    host_nqns: Optional[List[VSPNvmHostNqnSpec]] = None
    namespaces: Optional[List[VSPNvmNamespaceSpec]] = None
    force: Optional[bool] = False
    state: Optional[str] = None

    def __post_init__(self, **kwargs):
        if self.host_nqns:
            self.host_nqns = [VSPNvmHostNqnSpec(**x) for x in self.host_nqns]
        if self.namespaces:
            self.namespaces = [VSPNvmNamespaceSpec(**x) for x in self.namespaces]
            for x in self.namespaces:
                x.ldev_id = normalize_ldev_id(x.ldev_id)


@dataclass
class VSPNvmeSubsystemFactSpec(SingleBaseClass):
    name: Optional[str] = None
    id: Optional[int] = None


@dataclass
class VspNvmeSubsystemInfo(SingleBaseClass):
    nvmSubsystemId: int
    nvmSubsystemName: str
    resourceGroupId: int
    namespaceSecuritySetting: str
    t10piMode: str
    hostMode: str
    virtualNvmSubsystemId: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "virtualNvmSubsystemId" in kwargs:
            self.virtualNvmSubsystemId = kwargs.get("virtualNvmSubsystemId")
            if self.virtualNvmSubsystemId is None:
                self.virtualNvmSubsystemId = -1

    def to_dict(self):
        return asdict(self)


@dataclass
class VspNvmeSubsystemInfoList(BaseDataClass):
    data: List[VspNvmeSubsystemInfo]


@dataclass
class VspOneServerInfo(SingleBaseClass):
    id: str
    nickname: str
    protocol: str
    osType: str
    totalCapacity: int = 0
    usedCapacity: int = 0
    numberOfPaths: int = 0
    isInconsistent: bool = False
    modificationInProgress: bool = False
    isReserved: bool = False
    hasUnalignedOsTypes: bool = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class VspOneServerInfoList(BaseDataClass):
    data: List[VspOneServerInfo]


@dataclass
class VspHostNqnInfo(SingleBaseClass):
    hostNqnId: str
    hostNqn: str
    nvmSubsystemId: int
    hostNqnNickname: str

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class VspHostNqnInfoList(BaseDataClass):
    data: List[VspHostNqnInfo]


@dataclass
class VspNamespaceInfo(SingleBaseClass):
    namespaceObjectId: str
    namespaceId: int
    namespaceNickname: str
    nvmSubsystemId: int
    nvmSubsystemName: str
    ldevId: int
    byteFormatCapacity: str
    blockCapacity: int

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class VspNamespaceInfoList(BaseDataClass):
    data: List[VspNamespaceInfo]


@dataclass
class VspNamespacePathInfo(SingleBaseClass):
    namespacePathId: str
    nvmSubsystemId: int
    hostNqn: str
    namespaceId: int
    ldevId: int

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class VspNamespacePathInfoList(BaseDataClass):
    data: List[VspNamespacePathInfo]


@dataclass
class VspNvmePortInfo(SingleBaseClass):
    nvmSubsystemPortId: str
    nvmSubsystemId: int
    portId: List[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class VspNvmePortInfoList(BaseDataClass):
    data: List[VspNvmePortInfo]


@dataclass
class VspNvmeSubsystemDetailInfo:
    nvmSubsystemInfo: VspNvmeSubsystemInfo
    portInfo: List[VspNvmePortInfo]
    namespacesInfo: List[VspNamespaceInfo]
    namespacePathsInfo: List[VspNamespacePathInfo]
    hostNqnInfo: List[VspHostNqnInfo]

    # def __init__(self, **kwargs):
    #     super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class VspNvmeSubsystemDetailInfoList(BaseDataClass):
    data: List[VspNvmeSubsystemDetailInfo]


@dataclass
class VspNvmePortDisplay(SingleBaseClass):
    portId: str
    portType: str


@dataclass
class VspHostNqnDisplay(SingleBaseClass):
    hostNqn: str
    hostNqnNickname: str


@dataclass
class VspNamespacePathDisplay(SingleBaseClass):
    hostNqn: str
    namespaceId: int
    ldevId: int


@dataclass
class VspNamespaceDisplay(SingleBaseClass):
    namespaceId: int
    namespaceNickname: str
    ldevId: int
    byteFormatCapacity: str
    blockCapacity: int


@dataclass
class VspNvmeSubsystemDisplay(SingleBaseClass):
    nvmSubsystemId: int
    nvmSubsystemName: str
    resourceGroupId: int
    namespaceSecuritySetting: str
    t10piMode: str
    hostMode: str


@dataclass
class NvmSubsystemPort(SingleBaseClass):
    nvmSubsystemId: int
    nvmSubsystemName: str
    portIds: List[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class NvmSubsystemPortList(BaseDataClass):
    data: List[NvmSubsystemPort]


@dataclass
class NvmShorNamespace(SingleBaseClass):
    namespaceId: int
    ldevId: int


@dataclass
class NvmSubsystemById(SingleBaseClass):
    nvmSubsystemId: int = None
    nvmSubsystemName: str = None
    resourceGroupId: int = None
    namespaceSecuritySetting: str = None
    t10piMode: str = None
    hostMode: str = None
    nvmSubsystemNqn: str = None
    namespaces: List[NvmShorNamespace] = None
    portIds: List[str] = None
    virtualNvmSubsystemId: int = -1

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "virtualNvmSubsystemId" in kwargs:
            self.virtualNvmSubsystemId = kwargs.get("virtualNvmSubsystemId")

    def to_dict(self):
        return asdict(self)
