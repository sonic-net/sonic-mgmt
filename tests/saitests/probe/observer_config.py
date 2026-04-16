"""
Observer Configuration - Type-safe configuration using dataclass

Provides type-safe configuration for ProbingObserver instances.
Prevents field name typos and provides IDE autocomplete support.
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ObserverConfig:
    """
    Type-safe configuration for ProbingObserver

    This dataclass ensures compile-time field validation and prevents
    configuration errors through IDE autocomplete and type checking.

    Attributes:
        probe_target: Target type being probed (e.g., "pfc_xoff", "ingress_drop")
        algorithm_name: Name of the probing algorithm
        strategy: Algorithm strategy description
        check_column_title: Check column title (e.g., "PfcXoff", "IngDrop")
        context_template: Optional template for iteration context info
            (e.g., " [{probe_target} upper bound: {window_upper}]")
        completion_template: Template string for completion message
        completion_format_type: Format type for completion message ("value" or "range")
        table_column_mapping: Mapping of table columns to data fields
    """

    probe_target: str
    algorithm_name: str
    strategy: str
    check_column_title: str
    context_template: Optional[str] = None
    completion_template: Optional[str] = None
    completion_format_type: str = "value"
    table_column_mapping: Optional[Dict[str, Optional[str]]] = None

    def __post_init__(self):
        """Initialize default values for mutable fields"""
        if self.table_column_mapping is None:
            self.table_column_mapping = {}
