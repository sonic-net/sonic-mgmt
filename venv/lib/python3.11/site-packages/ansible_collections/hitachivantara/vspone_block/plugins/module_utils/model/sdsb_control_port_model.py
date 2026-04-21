from dataclasses import dataclass
from typing import Optional


@dataclass
class SDSBControlPortSpec:

    storage_node_id: Optional[str] = None
    storage_node_name: Optional[str] = None
    id: Optional[str] = None
