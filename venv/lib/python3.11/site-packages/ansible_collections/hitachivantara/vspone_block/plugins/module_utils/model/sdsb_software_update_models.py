from dataclasses import dataclass
from typing import Optional


@dataclass
class SDSBSoftwareUpdateSpec:
    should_stop_software_update: Optional[bool] = None
    is_software_downgrade: Optional[bool] = None
    software_update_file: Optional[str] = None

    # def is_empty(self):
    #     if self.id is None and self.is_detailed_logging_mode is None:
    #         return True
    #     else:
    #         return False
