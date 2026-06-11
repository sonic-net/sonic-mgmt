"""Port specification expansion utilities.

Supports formats described in test plan:
- Individual: "Ethernet0"
- Range: "Ethernet4:13" (stop exclusive)
- Range with step: "Ethernet0:97:4"
- List: "Ethernet16,Ethernet20,Ethernet24"
- Mixed: "Ethernet28:33,Ethernet36,Ethernet40:45"

All resulting ports must match the SONiC logical naming pattern: Ethernet<integer>.
"""

import re
from .exceptions import PortSpecError

PORT_PATTERN = re.compile(r"^(Ethernet)(\d+)$")


class PortSpecExpander:
    """Expand port specification strings into individual port names.

    Usage:
        PortSpecExpander.expand("Ethernet0") -> ["Ethernet0"]
        PortSpecExpander.expand("Ethernet4:13") -> [Ethernet4..Ethernet12]
    """

    @staticmethod
    def _validate_port_name(port_name):
        if not PORT_PATTERN.match(port_name):
            raise PortSpecError(f"Invalid port name '{port_name}' (expected pattern Ethernet<int>)")

    @classmethod
    def _expand_range(cls, token):
        # token examples: Ethernet4:13 , Ethernet0:97:4
        match = re.match(r"^(Ethernet)(\d+):(\d+)(?::(\d+))?$", token)
        if not match:
            raise PortSpecError(f"Invalid range specification '{token}'")
        base_prefix, start_str, stop_str, step_str = match.groups()
        start = int(start_str)
        stop = int(stop_str)
        step = int(step_str) if step_str else 1
        if step <= 0:
            raise PortSpecError(f"Step must be > 0 in '{token}'")
        if start >= stop:
            return []  # empty range is allowed -> produces no ports
        return [f"{base_prefix}{i}" for i in range(start, stop, step)]

    @classmethod
    def _expand_single(cls, token):
        cls._validate_port_name(token)
        return [token]

    @classmethod
    def expand(cls, spec):
        if not spec or not spec.strip():
            raise PortSpecError("Empty port specification")
        tokens = [token.strip() for token in spec.split(',') if token.strip()]
        port_set = set()
        for token in tokens:
            if ':' in token:
                expanded_ports = cls._expand_range(token)
            else:
                expanded_ports = cls._expand_single(token)
            port_set.update(expanded_ports)
        return sorted(port_set, key=lambda port: int(port.replace('Ethernet', '')))
