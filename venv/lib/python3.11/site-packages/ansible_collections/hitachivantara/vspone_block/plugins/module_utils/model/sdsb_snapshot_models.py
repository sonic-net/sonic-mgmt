from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class QosParam(SingleBaseClass):
    upperAlertAllowableTime: Optional[int] = None
    upperAlertTime: Optional[int] = None
    upperLimitForIops: Optional[int] = None
    upperLimitForTransferRate: Optional[int] = None


@dataclass
class SnapShotResponseModel(SingleBaseClass):
    """
    Base class for snapshot models.
    """

    isWrittenInSvol: Optional[bool] = None
    qosParam: Optional[QosParam] = None
    snapshotConcordanceRate: Optional[int] = None
    snapshotProgressRate: Optional[int] = None
    snapshotStatus: Optional[str] = None
    snapshotTimestamp: Optional[str] = None
    snapshotType: Optional[str] = None
    snapshotVolumeId: Optional[str] = None
    snapshotVolumeName: Optional[str] = None
    snapshotVolumeNickname: Optional[str] = None
    status: Optional[str] = None
    statusSummary: Optional[str] = None
    vpsId: Optional[str] = None
    vpsName: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "qosParam" in kwargs:
            self.qosParam = (
                QosParam(**kwargs.get("qosParam")) if kwargs.get("qosParam") else None
            )


@dataclass
class SnapShotsResponseModel(BaseDataClass):
    data: List[SnapShotResponseModel] = None


@dataclass
class MasterVolumeResponseModel(SingleBaseClass):
    """
    Model for master volume response.
    """

    masterVolumeId: Optional[str] = None
    vpsId: Optional[str] = None
    vpsName: Optional[str] = None
    qosParam: Optional[QosParam] = None


@dataclass
class QosSpec(SingleBaseClass):
    """
    Quality of Service specification for snapshots.
    """

    upper_limit_for_iops: Optional[int] = None
    upper_limit_for_transfer_rate: Optional[int] = None
    upper_alert_allowable_time: Optional[int] = None


@dataclass
class SDSBSnapshotSpec(SingleBaseClass):
    """
    Base class for snapshot specifications.
    """

    name: Optional[str] = None
    master_volume_name: Optional[str] = None
    master_volume_id: Optional[str] = None
    snapshot_volume_name: Optional[str] = None
    snapshot_volume_id: Optional[str] = None
    operation_type: Optional[str] = None
    vps_id: Optional[str] = None
    vps_name: Optional[str] = None
    qos: Optional[QosSpec] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "qos" in kwargs:
            self.qos = QosSpec(**kwargs.get("qos")) if kwargs.get("qos") else None


@dataclass
class SDSBSnapshotFactsSpec(SingleBaseClass):
    """
    Base class for snapshot specifications.
    """

    name: Optional[str] = None
    master_volume_name: Optional[str] = None
    master_volume_id: Optional[str] = None
    snapshot_volume_name: Optional[str] = None
    snapshot_volume_id: Optional[str] = None
    vps_id: Optional[str] = None
    vps_name: Optional[str] = None
