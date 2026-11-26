class PortSpecError(ValueError):
    """Raised for any invalid port specification."""


"""Custom exceptions for transceiver onboarding infra."""


class DutInfoError(Exception):
    """Issues related to dut_info.json parsing or validation."""


class AttributeMergeError(Exception):
    """Raised when attribute merging encounters irrecoverable errors."""


class TemplateValidationError(Exception):
    """Raised for critical template validation failures (e.g., missing required attributes)."""
