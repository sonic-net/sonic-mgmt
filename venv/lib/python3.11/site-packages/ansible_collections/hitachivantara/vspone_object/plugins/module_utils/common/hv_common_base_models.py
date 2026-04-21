from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class APIGRequestModel():
    module_name: Optional[str] = None
    operation_name: Optional[str] = None
    site: Optional[str] = None
    # storage_model: Optional[str] = None
    # storage_serial: Optional[int] = None
    # storage_type: Optional[int] = None
    # connection_type: Optional[int] = None
    operation_status: Optional[int] = None
    process_time: Optional[float] = None
    region: Optional[str] = None
    cluster_name: Optional[str] = None
    serial: Optional[str] = None

    def to_dict(self):
        return asdict(self)
