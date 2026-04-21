from dataclasses import dataclass
from typing import Optional

try:
    from .common_base_models import SingleBaseClass
except ImportError:
    from common_base_models import SingleBaseClass


@dataclass
class WarningThresholdSettingSpec(SingleBaseClass):
    remaining_days: Optional[int] = None
    total_pool_capacity_rate: Optional[int] = None


@dataclass
class LicenseManagementSpec(SingleBaseClass):
    warning_threshold_setting: Optional[WarningThresholdSettingSpec] = None
    allow_over_capacity: Optional[bool] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__post_init__()

    def __post_init__(self):
        if self.warning_threshold_setting:
            self.warning_threshold_setting = WarningThresholdSettingSpec(
                **self.warning_threshold_setting
            )
