"""
Validation result classes and issue definitions
Each validator gets a range of 1000 issue IDs:
- Base Validator: 0-999
- Testbed Validator: 1000-1999
- IP Address Validator: 2000-2999
- Console Validator: 3000-3999
- PDU Validator: 4000-4999
- Topology Validator: 5000-5999
- Device Name Validator: 6000-6999
- VLAN Validator: 7000-7999
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class ValidationSeverity(Enum):
    """Validation result severity levels"""
    IGNORE = "ignore"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationIssueDefinition:
    """Definition of a validation issue with unique ID and metadata"""
    issue_id: str
    keyword: str
    severity: ValidationSeverity
    description: str = ""

    def __post_init__(self):
        # Validate issue ID format (e.g., E1001, I1000)
        if not self.issue_id or len(self.issue_id) < 5:
            raise ValueError(f"Invalid issue ID format: {self.issue_id}")


class ValidationIssueRegistry:
    """Registry for all validation issue definitions"""

    def __init__(self):
        self._issues: Dict[str, ValidationIssueDefinition] = {}
        self._severities: Dict[str, ValidationSeverity] = {}
        self._validator_ranges: Dict[str, range] = {
            'base': range(0, 1000),
            'testbed': range(1000, 2000),
            'ip_address': range(2000, 3000),
            'console': range(3000, 4000),
            'pdu': range(4000, 5000),
            'topology': range(5000, 6000),
            'device_info': range(6000, 7000),
            'vlan': range(7000, 8000),
        }

    def register_issue(
        self, validator_name: str, issue_id: str, keyword: str, description: str = "",
        severity: ValidationSeverity = ValidationSeverity.ERROR
    ) -> None:
        """Register a validation issue definition"""
        if issue_id in self._issues:
            raise ValueError(f"Issue ID {issue_id} already registered")

        # Validate issue ID is in validator's range
        if validator_name in self._validator_ranges:
            issue_num = int(issue_id[1:])  # Remove E/I prefix
            validator_range = self._validator_ranges[validator_name]
            if issue_num not in validator_range:
                raise ValueError(f"Issue ID {issue_id} not in range {validator_range} for validator {validator_name}")

        # Create the issue definition
        issue_def = ValidationIssueDefinition(issue_id, keyword, severity, description)
        self._issues[issue_id] = issue_def

    def get_issue(self, issue_id: str) -> Optional[ValidationIssueDefinition]:
        """Get issue definition by ID"""
        return self._issues.get(issue_id)

    def get_all_issues(self) -> Dict[str, ValidationIssueDefinition]:
        """Get all registered issues"""
        return self._issues.copy()

    def set_severity(self, issue_id: str, severity: ValidationSeverity) -> None:
        """Set severity for a specific issue ID"""
        self._severities[issue_id] = severity

    def get_severity(self, issue_id: str) -> Optional[ValidationSeverity]:
        """Get severity for an issue (with custom severities applied)"""
        if issue_id in self._severities:
            return self._severities[issue_id]

        issue_def = self._issues.get(issue_id)
        return issue_def.severity if issue_def else None

    def configure_severities(self, severities: Dict[str, str]) -> None:
        """Configure severities from string mapping"""
        self._severities.clear()
        for issue_id, severity_str in severities.items():
            try:
                severity = ValidationSeverity(severity_str.lower())
                self._severities[issue_id] = severity
            except ValueError:
                # Invalid severity string, skip this severity
                continue


@dataclass
class ValidationIssue:
    """Represents a single validation issue"""
    issue_id: str
    message: str
    source: str
    group_name: str
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Get issue definition from registry
        self._issue_def = _issue_registry.get_issue(self.issue_id)
        if not self._issue_def:
            raise ValueError(f"Unknown issue ID: {self.issue_id}")

    @property
    def severity(self) -> ValidationSeverity:
        """Get severity (with custom severities applied)"""
        severity = _issue_registry.get_severity(self.issue_id)
        return severity if severity else self._issue_def.severity

    @property
    def keyword(self) -> str:
        """Get keyword from issue definition"""
        return self._issue_def.keyword

    @property
    def description(self) -> str:
        """Get description from issue definition"""
        return self._issue_def.description

    def __str__(self):
        base_msg = f"[{self.issue_id}] {self.keyword}: {self.message}"
        if self.details:
            detail_str = ", ".join([f"{k}={v}" for k, v in self.details.items()])
            return f"{base_msg} ({detail_str})"
        return base_msg

    def __hash__(self):
        """Make ValidationIssue hashable for deduplication"""
        return hash((self.issue_id, self.message, self.source))

    def __eq__(self, other):
        """Define equality for deduplication"""
        if not isinstance(other, ValidationIssue):
            return False
        return (self.issue_id == other.issue_id and
                self.message == other.message and
                self.source == other.source)


@dataclass
class ValidationResult:
    """Comprehensive validation result with detailed information"""
    validator_name: str
    group_name: str
    success: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0

    @property
    def errors(self) -> List[ValidationIssue]:
        """Get all error-level issues"""
        return [
            issue for issue in self.issues
            if issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL]
        ]

    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get all warning-level issues"""
        return [issue for issue in self.issues if issue.severity == ValidationSeverity.WARNING]

    @property
    def infos(self) -> List[ValidationIssue]:
        """Get all info-level issues"""
        return [issue for issue in self.issues if issue.severity == ValidationSeverity.INFO]

    @property
    def error_count(self) -> int:
        """Get count of error-level issues"""
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        """Get count of warning-level issues"""
        return len(self.warnings)

    @property
    def info_count(self) -> int:
        """Get count of info-level issues"""
        return len(self.infos)

    def add_issue(self, issue_id: str, details: Dict[str, Any] = None):
        """Add a validation issue using issue ID and details"""
        if details is None:
            details = {}

        # Get severity (with custom severities applied)
        severity = _issue_registry.get_severity(issue_id)

        # Handle IGNORE severity - skip entirely
        if severity == ValidationSeverity.IGNORE:
            return

        # Get issue definition to form the message
        issue_def = _issue_registry.get_issue(issue_id)
        if not issue_def:
            raise ValueError(f"Unknown issue ID: {issue_id}")

        # Use the description from issue definition as the base message
        message = issue_def.description

        issue = ValidationIssue(issue_id, message, self.validator_name, self.group_name, details)
        self.issues.append(issue)

        # Update success status based on severity
        if issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL]:
            self.success = False


# Global registry instance
_issue_registry = ValidationIssueRegistry()


def get_issue_registry() -> ValidationIssueRegistry:
    """Get the global issue registry"""
    return _issue_registry


def _def_issue(
    validator_name: str, issue_id: str, keyword: str, description: str = "",
    severity: ValidationSeverity = ValidationSeverity.ERROR
):
    """Helper function to register issue definitions"""
    _issue_registry.register_issue(validator_name, issue_id, keyword, description, severity)


def register_all_issues():
    """Register all issue definitions with the global registry"""

    # Base Validator Issues (0-999)
    _def_issue('base', 'E0001', 'validation_exception', 'Unexpected validation error')
    _def_issue('base', 'E0002', 'missing_testbed_data', 'No testbed data available', ValidationSeverity.WARNING)
    _def_issue(
        'base', 'E0003', 'missing_connection_graph', 'No connection graph data available', ValidationSeverity.WARNING
    )
    _def_issue('base', 'E0004', 'missing_groups_data', 'No groups data available')

    # Testbed Validator Issues (1000-1999)
    _def_issue(
        'testbed', 'E1001', 'bad_config_data_in_graph',
        'Bad testbed configuration data in connection graph - infra issue, '
        'check conn_graph_facts.py for errors'
    )
    _def_issue('testbed', 'E1002', 'missing_conf_name', 'Testbed configuration missing conf-name field')
    _def_issue('testbed', 'E1003', 'duplicate_name', 'Duplicate testbed name found')
    _def_issue('testbed', 'E1004', 'missing_topology_file', 'Topology file not found for testbed')

    # IP Address Validator Issues (2000-2999)
    _def_issue('ip_address', 'E2001', 'conflict_ip', 'IP address conflict detected')
    _def_issue('ip_address', 'E2002', 'reserved_ip', 'Reserved IP address found', ValidationSeverity.WARNING)
    _def_issue('ip_address', 'E2003', 'invalid_ip_format', 'Invalid IP address format')
    _def_issue('ip_address', 'E2004', 'inconsistent_ip', 'Device has inconsistent IP addresses across sources')
    _def_issue(
        'ip_address', 'E2005', 'ipv4_ipv6_mismatch', 'IPv6 address last 4 bytes do not match IPv4 address',
        ValidationSeverity.INFO
    )

    # Console Validator Issues (3000-3999)
    _def_issue(
        'console', 'E3001', 'duplicate_config_groups',
        'Device has console configuration in multiple groups', ValidationSeverity.WARNING
    )
    _def_issue('console', 'E3002', 'missing_console', 'Device has no console connection configured')
    _def_issue(
        'console', 'E3003', 'bad_console_data_in_graph',
        'Bad console connection data in connection graph - possible infra issue, check conn_graph_facts.py for errors'
    )
    _def_issue('console', 'E3004', 'missing_console_port', 'Console connection missing ConsolePort information')
    _def_issue('console', 'E3005', 'console_port_conflict', 'Console port is used by multiple devices')
    _def_issue('console', 'E3006', 'missing_required_field', 'Console connection missing required field')
    _def_issue('console', 'E3007', 'invalid_console_server', 'Console points to non-existent server')
    _def_issue(
        'console', 'E3008', 'invalid_server_type', 'Console server has unexpected type',
        ValidationSeverity.WARNING
    )
    _def_issue('console', 'E3009', 'empty_console_port', 'Console connection has empty port')
    _def_issue(
        'console', 'E3010', 'empty_optional_field', 'Console connection has empty optional field',
        ValidationSeverity.WARNING
    )

    # PDU Validator Issues (4000-4999)
    _def_issue(
        'pdu', 'E4001', 'duplicate_config_groups',
        'Device has PDU configuration in multiple groups', ValidationSeverity.WARNING
    )
    _def_issue('pdu', 'E4002', 'missing_pdu', 'Device has no PDU connections configured')
    _def_issue(
        'pdu', 'E4003', 'bad_pdu_data_in_graph',
        'Bad PDU connection data in connection graph - possible infra issue, check conn_graph_facts.py for errors'
    )
    _def_issue(
        'pdu', 'E4004', 'no_power_redundancy',
        'Device has only one PSU connection - no power redundancy', ValidationSeverity.WARNING
    )
    _def_issue(
        'pdu', 'E4005', 'bad_psu_data_in_graph',
        'Bad PSU configuration data in connection graph - possible infra issue, check conn_graph_facts.py for errors'
    )
    _def_issue(
        'pdu', 'E4006', 'bad_feed_data_in_graph',
        'Bad feed configuration data in connection graph - possible infra issue, check conn_graph_facts.py for errors'
    )
    _def_issue('pdu', 'E4007', 'pdu_port_conflict', 'PDU outlet is used by multiple devices')
    _def_issue('pdu', 'E4008', 'missing_required_field', 'PDU connection missing required field')
    _def_issue('pdu', 'E4009', 'invalid_pdu_device', 'PDU points to non-existent device')
    _def_issue('pdu', 'E4010', 'invalid_pdu_type', 'PDU device has unexpected type', ValidationSeverity.WARNING)
    _def_issue('pdu', 'E4011', 'empty_pdu_port', 'PDU connection has empty port')
    _def_issue('pdu', 'E4012', 'invalid_feed_id', 'PDU feed ID is not valid')

    # Topology Validator Issues (5000-5999)
    _def_issue('topology', 'E5001', 'parse_error', 'Failed to process topology file')
    _def_issue('topology', 'E5002', 'missing_template', 'Template file not found for swrole')
    _def_issue('topology', 'E5003', 'duplicate_vm_offset', 'VM offset is used by multiple VMs')
    _def_issue('topology', 'E5004', 'duplicate_vlan', 'VLAN ID is used by multiple sources')
    _def_issue('topology', 'E5005', 'duplicate_interface', 'Interface appears multiple times in vlan_config')
    _def_issue('topology', 'E5006', 'interface_count_exceed', 'Interface count exceeds prefix capacity')
    _def_issue('topology', 'E5007', 'invalid_prefix_format', 'Invalid prefix format in vlan_config')
    _def_issue('topology', 'E5008', 'invalid_ip_format', 'Invalid bp_interface IPv4 address format')
    _def_issue('topology', 'E5009', 'multiple_subnets', 'bp_interface IPs span multiple subnets')
    _def_issue('topology', 'E5010', 'conflict_ip', 'bp_interface IP address conflict')
    _def_issue('topology', 'E5011', 'missing_topology_dir', 'Topology vars directory not found')
    _def_issue('topology', 'E5012', 'yaml_parse_error', 'Invalid YAML in topology file')
    _def_issue('topology', 'E5013', 'missing_topology_file', 'Topology file not found')
    _def_issue('topology', 'E5014', 'missing_swrole_template_file', 'Template file not found for swrole')

    # Device Info Validator Issues (6000-6999)
    _def_issue(
        'device_info', 'E6001', 'missing_devices_section',
        'No devices section found in connection graph', ValidationSeverity.WARNING
    )
    _def_issue(
        'device_info', 'E6002', 'bad_devices_data_in_graph',
        'Bad devices section data in connection graph - possible infra issue, check conn_graph_facts.py for errors'
    )
    _def_issue('device_info', 'E6003', 'empty_device_name', 'Empty or whitespace-only device name found')
    _def_issue('device_info', 'E6004', 'conflict_device_name', 'Conflicting device name found')
    _def_issue('device_info', 'E6005', 'invalid_characters', 'Device name contains invalid characters')
    _def_issue('device_info', 'E6006', 'device_name_too_long', 'Device name exceeds maximum length')
    _def_issue('device_info', 'E6007', 'empty_hwsku', 'Device has empty or missing HwSku field')

    # VLAN Validator Issues (7000-7999)
    _def_issue('vlan', 'E7001', 'missing_dut_devices', 'No DUT devices found in topology')
    _def_issue(
        'vlan', 'E7002', 'bad_vlan_data_in_graph',
        'Bad VLAN configuration data in connection graph - possible infra issue, check conn_graph_facts.py for errors'
    )
    _def_issue('vlan', 'E7003', 'duplicate_vlan', 'VLAN IDs are duplicated on multiple ports')
    _def_issue('vlan', 'E7004', 'vlan_mapping_missing', 'VLAN IDs are not mapped to peer links')
    _def_issue('vlan', 'E7005', 'vlan_mapping_extra', 'VLAN IDs from peer links not configured on device')
    _def_issue('vlan', 'E7006', 'invalid_vlan_format', 'Invalid VLAN format')
    _def_issue('vlan', 'E7007', 'invalid_vlan_range_order', 'Invalid VLAN range - start greater than end')
    _def_issue('vlan', 'E7008', 'vlan_out_of_range', 'VLAN ID not in valid range')
    _def_issue('vlan', 'E7011', 'invalid_vlan_list_type', 'VLAN list must be a list')
    _def_issue('vlan', 'E7012', 'invalid_vlan_type', 'VLAN ID must be an integer')


# Register all issues when this module is imported
register_all_issues()
