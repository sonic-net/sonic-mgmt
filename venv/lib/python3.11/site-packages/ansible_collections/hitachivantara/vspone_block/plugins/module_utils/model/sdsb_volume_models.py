from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class VolumeFactSpec:
    count: Optional[int] = None
    names: Optional[List[str]] = None
    nicknames: Optional[List[str]] = None
    capacity_saving: Optional[str] = None
    vps_id: Optional[str] = None
    vps_name: Optional[str] = None


@dataclass
class QosParamSpec:
    upper_limit_for_iops: Optional[int] = None
    upper_limit_for_transfer_rate_mb_per_sec: Optional[int] = None
    upper_alert_allowable_time_in_sec: Optional[int] = None


@dataclass
class VolumeSpec:
    id: Optional[str] = None
    name: Optional[str] = None
    nickname: Optional[str] = None
    capacity: Optional[str] = None
    state: Optional[str] = None
    capacity_saving: Optional[str] = None
    pool_name: Optional[str] = None
    compute_nodes: Optional[List[str]] = None
    qos_param: Optional[QosParamSpec] = None
    vps_id: Optional[str] = None
    vps_name: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.qos_param, dict):
            self.qos_param = QosParamSpec(**self.qos_param)


@dataclass
class QosParam(SingleBaseClass):
    upperLimitForIops: int
    upperLimitForTransferRate: int
    upperAlertAllowableTime: int
    upperAlertTime: str = ""


@dataclass
class DataReductionEffects:
    dataReductionRate: int
    dataReductionCapacity: int
    compressedCapacity: int
    reclaimedCapacity: int
    systemDataCapacity: int
    preCapacityDataReductionWithoutSystemData: int
    postCapacityDataReduction: int


@dataclass
class Lun:
    lun: int
    serverId: str


@dataclass
class ComputeNodeSummaryInfo:
    id: str
    name: str


@dataclass
class SDSBVolumeInfo(SingleBaseClass):

    dataReductionEffects: DataReductionEffects
    id: str
    name: str
    nickname: str
    volumeNumber: int
    poolId: str
    poolName: str
    totalCapacity: int
    usedCapacity: int
    numberOfConnectingServers: int
    numberOfSnapshots: int
    protectionDomainId: str
    fullAllocated: bool
    volumeType: str
    statusSummary: str
    status: str
    storageControllerId: str
    snapshotAttribute: str
    snapshotStatus: str
    savingSetting: str
    savingMode: str
    dataReductionStatus: str
    dataReductionProgressRate: str
    vpsId: str
    vpsName: str
    naaId: str
    qosParam: QosParam
    computeNodesInfo: List[ComputeNodeSummaryInfo]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBVolumesInfo(BaseDataClass):
    data: List[SDSBVolumeInfo]


@dataclass
class SDSBVolumeAndComputeNodeInfo(SingleBaseClass):
    volumeInfo: SDSBVolumeInfo
    computeNodeInfo: List[ComputeNodeSummaryInfo]

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBVolumeAndComputeNodeList(BaseDataClass):
    data: List[SDSBVolumeAndComputeNodeInfo]
