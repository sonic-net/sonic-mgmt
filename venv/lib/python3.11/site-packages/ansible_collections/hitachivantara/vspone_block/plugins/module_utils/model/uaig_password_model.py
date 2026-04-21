from dataclasses import dataclass
from typing import Optional


@dataclass
class PasswordSpec:
    password: Optional[str] = None
