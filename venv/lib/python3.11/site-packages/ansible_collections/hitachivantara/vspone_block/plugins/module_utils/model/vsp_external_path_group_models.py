from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import SingleBaseClass

except ImportError:
    from .common_base_models import SingleBaseClass


@dataclass
class ExternalFcPath(SingleBaseClass):
    port: Optional[str] = None
    external_wwn: Optional[str] = None


@dataclass
class ExternalIscsiTargetPath(SingleBaseClass):
    port: Optional[str] = None
    external_iscsi_ip_address: Optional[str] = None
    external_iscsi_name: Optional[str] = None


@dataclass
class ExternalPathGroupSpec:
    external_path_group_id: Optional[int] = None
    external_fc_paths: Optional[List[ExternalFcPath]] = None
    external_iscsi_target_paths: Optional[List[ExternalIscsiTargetPath]] = None

    def __init__(self, **kwargs):
        for field in self.__dataclass_fields__.keys():
            setattr(self, field, kwargs.get(field, None))
        self.__post_init__()

    def __post_init__(self):
        if self.external_fc_paths:
            self.external_fc_paths = [
                ExternalFcPath(**fcp) for fcp in self.external_fc_paths
            ]
        if self.external_iscsi_target_paths:
            self.external_iscsi_target_paths = [
                ExternalIscsiTargetPath(**istp)
                for istp in self.external_iscsi_target_paths
            ]


@dataclass
class ExternalPathGroupFactSpec:
    external_path_group_id: Optional[int] = None
