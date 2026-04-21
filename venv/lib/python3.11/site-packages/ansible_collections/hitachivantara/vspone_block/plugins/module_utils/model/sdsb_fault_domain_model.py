from dataclasses import dataclass
from typing import Optional


@dataclass
class SDSBFaultDomainSpec:
    """Block Drives Facts Specification"""

    id: Optional[str] = None
    name: Optional[str] = None
