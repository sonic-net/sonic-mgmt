from dataclasses import dataclass
from typing import Optional


@dataclass
class EventLogFactSpec:
    """Event Log Facts Specification"""

    severity: Optional[str] = None
    severity_ge: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    max_events: Optional[int] = None
    id: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    max_events: Optional[int] = None
