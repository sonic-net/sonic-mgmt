from dataclasses import dataclass
from typing import Optional


@dataclass
class SDSBEstimatedCapacityFactSpec:
    id: Optional[str] = None
    name: Optional[str] = None
    number_of_storage_nodes: Optional[int] = None
    number_of_drives: Optional[int] = None
    number_of_tolerable_drive_failures: Optional[int] = None
    query: Optional[str] = None
