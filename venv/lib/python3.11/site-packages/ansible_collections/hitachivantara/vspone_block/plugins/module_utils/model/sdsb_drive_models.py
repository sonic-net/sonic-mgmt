from dataclasses import dataclass
from typing import Optional


@dataclass
class SDSBDriveFactSpec:
    """Block Drives Facts Specification"""

    id: Optional[str] = None
    status_summary: Optional[str] = None
    status: Optional[str] = None
    storage_node_id: Optional[str] = None
    locator_led_status: Optional[str] = None


@dataclass
class SDSBDriveSpec:
    """Block Drives Facts Specification"""

    id: Optional[str] = None
    should_drive_locator_led_on: Optional[bool] = None
