from dataclasses import dataclass
from typing import Optional


@dataclass
class SDSBCapacityManagementSettingsFactSpec:
    storage_controller_id: Optional[str] = None


@dataclass
class SDSBCapacityManagementSettingsSpec:
    id: Optional[str] = None
    is_detailed_logging_mode: Optional[bool] = None

    def is_empty(self):
        if self.id is None and self.is_detailed_logging_mode is None:
            return True
        else:
            return False
