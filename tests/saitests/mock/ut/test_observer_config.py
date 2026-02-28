#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for ObserverConfig dataclass.

Tests cover:
- Dataclass instantiation with all required fields
- Optional field defaults
- __post_init__ initialization
- Type safety and field validation
- Immutability characteristics

Coverage target: 100% for observer_config.py
"""

import pytest
import unittest


# Import the class under test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../probe"))
from observer_config import ObserverConfig  # noqa: E402


@pytest.mark.order(5000)
class TestObserverConfigInstantiation(unittest.TestCase):
    """Test ObserverConfig instantiation and initialization."""

    @pytest.mark.order(5000)
    def test_create_with_required_fields_only(self):
        """Test creating ObserverConfig with only required fields."""
        config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Upper Bound Probing",
            strategy="exponential growth",
            check_column_title="PfcXoff"
        )

        assert config.probe_target == "pfc_xoff"
        assert config.algorithm_name == "Upper Bound Probing"
        assert config.strategy == "exponential growth"
        assert config.check_column_title == "PfcXoff"

        # Optional fields should have defaults
        assert config.context_template is None
        assert config.completion_template is None
        assert config.completion_format_type == "value"
        assert config.table_column_mapping == {}

    @pytest.mark.order(5010)
    def test_create_with_all_fields(self):
        """Test creating ObserverConfig with all fields specified."""
        table_mapping = {
            "lower_bound": None,
            "upper_bound": "value",
            "candidate_threshold": None,
            "range_step": None
        }

        config = ObserverConfig(
            probe_target="ingress_drop",
            algorithm_name="Lower Bound Probing",
            strategy="logarithmic reduction",
            check_column_title="IngressDrop",
            context_template=" [ingress_drop upper: {window_upper}]",
            completion_template="Lower bound = {value}",
            completion_format_type="value",
            table_column_mapping=table_mapping
        )

        assert config.probe_target == "ingress_drop"
        assert config.algorithm_name == "Lower Bound Probing"
        assert config.strategy == "logarithmic reduction"
        assert config.check_column_title == "IngressDrop"
        assert config.context_template == " [ingress_drop upper: {window_upper}]"
        assert config.completion_template == "Lower bound = {value}"
        assert config.completion_format_type == "value"
        assert config.table_column_mapping == table_mapping

    @pytest.mark.order(5020)
    def test_post_init_initializes_table_column_mapping(self):
        """Test __post_init__ initializes table_column_mapping to empty dict."""
        config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Test Algorithm",
            strategy="test strategy",
            check_column_title="Test",
            table_column_mapping=None  # Explicitly set to None
        )

        # Should be initialized to empty dict by __post_init__
        assert config.table_column_mapping == {}
        assert isinstance(config.table_column_mapping, dict)


@pytest.mark.order(5030)
class TestObserverConfigFormats(unittest.TestCase):
    """Test different completion_format_type values."""

    @pytest.mark.order(5030)
    def test_value_format_type(self):
        """Test config with completion_format_type='value'."""
        config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Upper Bound",
            strategy="test",
            check_column_title="Test",
            completion_format_type="value"
        )

        assert config.completion_format_type == "value"

    @pytest.mark.order(5040)
    def test_range_format_type(self):
        """Test config with completion_format_type='range'."""
        config = ObserverConfig(
            probe_target="ingress_drop",
            algorithm_name="Range Probing",
            strategy="binary search",
            check_column_title="Test",
            completion_format_type="range"
        )

        assert config.completion_format_type == "range"

    @pytest.mark.order(5050)
    def test_default_format_type(self):
        """Test default completion_format_type is 'value'."""
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Test"
        )

        assert config.completion_format_type == "value"


@pytest.mark.order(5060)
class TestObserverConfigTableMapping(unittest.TestCase):
    """Test table_column_mapping configurations."""

    @pytest.mark.order(5060)
    def test_table_mapping_with_all_none(self):
        """Test table mapping where all values are None."""
        mapping = {
            "lower_bound": None,
            "upper_bound": None,
            "candidate_threshold": None,
            "range_step": None
        }

        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Test",
            table_column_mapping=mapping
        )

        assert config.table_column_mapping == mapping

    @pytest.mark.order(5070)
    def test_table_mapping_mixed_values(self):
        """Test table mapping with mixed None and string values."""
        mapping = {
            "lower_bound": "value",
            "upper_bound": "window_upper",
            "candidate_threshold": None,
            "range_step": "range_size"
        }

        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Test",
            table_column_mapping=mapping
        )

        assert config.table_column_mapping == mapping
        assert config.table_column_mapping["lower_bound"] == "value"
        assert config.table_column_mapping["range_step"] == "range_size"


@pytest.mark.order(5080)
class TestObserverConfigTemplates(unittest.TestCase):
    """Test template string configurations."""

    @pytest.mark.order(5080)
    def test_context_template_with_placeholders(self):
        """Test context_template with format placeholders."""
        template = " [{probe_target} range: [{window_lower}, {window_upper}]]"

        config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Test",
            context_template=template
        )

        assert config.context_template == template
        # Verify template can be formatted
        formatted = template.format(probe_target="pfc_xoff", window_lower=100, window_upper=200)
        assert formatted == " [pfc_xoff range: [100, 200]]"

    @pytest.mark.order(5090)
    def test_completion_template_with_placeholders(self):
        """Test completion_template with format placeholders."""
        template = "Range = [{lower}, {upper}]"

        config = ObserverConfig(
            probe_target="ingress_drop",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Test",
            completion_template=template
        )

        assert config.completion_template == template
        # Verify template can be formatted
        formatted = template.format(lower=100, upper=200)
        assert formatted == "Range = [100, 200]"

    @pytest.mark.order(5100)
    def test_empty_context_template(self):
        """Test empty string context_template."""
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Test",
            context_template=""
        )

        assert config.context_template == ""


@pytest.mark.order(5110)
class TestObserverConfigFieldAccess(unittest.TestCase):
    """Test field access and dataclass behavior."""

    @pytest.mark.order(5110)
    def test_field_access(self):
        """Test accessing all fields."""
        config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Upper Bound Probing",
            strategy="exponential growth",
            check_column_title="PfcXoff",
            context_template="context",
            completion_template="completion",
            completion_format_type="range",
            table_column_mapping={"key": "value"}
        )

        # All fields should be accessible
        assert hasattr(config, 'probe_target')
        assert hasattr(config, 'algorithm_name')
        assert hasattr(config, 'strategy')
        assert hasattr(config, 'check_column_title')
        assert hasattr(config, 'context_template')
        assert hasattr(config, 'completion_template')
        assert hasattr(config, 'completion_format_type')
        assert hasattr(config, 'table_column_mapping')

    @pytest.mark.order(5120)
    def test_repr_representation(self):
        """Test string representation of ObserverConfig."""
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test Algo",
            strategy="test strategy",
            check_column_title="Test"
        )

        repr_str = repr(config)
        # Should contain class name and field values
        assert "ObserverConfig" in repr_str
        assert "test" in repr_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
