from dataclasses import dataclass
from typing import Optional


@dataclass
class SDSBRemoteIscsciPortFactSpec:
    id: Optional[str] = None
    local_port: Optional[str] = None
    remote_serial: Optional[str] = None
    remote_storage_system_type: Optional[str] = None
    remote_port: Optional[str] = None


@dataclass
class SDSBRemoteIscsciPortSpec:
    id: Optional[str] = None
    local_port: Optional[str] = None
    remote_serial: Optional[str] = None
    remote_storage_system_type: Optional[str] = None
    remote_port: Optional[str] = None
    remote_ip_address: Optional[str] = None
    remote_tcp_port: Optional[int] = None

    def is_empty(self):
        if self.id is None and self.is_detailed_logging_mode is None:
            return True
        else:
            return False
