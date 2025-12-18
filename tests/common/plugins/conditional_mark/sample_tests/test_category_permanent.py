"""
Sample tests to demonstrate permanent skip category.
These tests are skipped due to fundamental limitations that won't change.
"""


def test_feature_not_supported_on_vs():
    """Test that requires hardware features not available on VS platform."""
    assert True, "This test should be skipped on VS platform"


def test_topology_specific_feature():
    """Test that only works on specific topologies."""
    assert True, "This test should be skipped on certain topologies"


def test_asic_hardware_limitation():
    """Test that requires specific ASIC capabilities."""
    assert True, "This test should be skipped on unsupported ASICs"


class TestPermanentSkips:
    """Test class demonstrating permanent skips."""

    def test_platform_limitation(self):
        """Test that has platform-specific limitations."""
        assert True, "This test should be skipped on certain platforms"

    def test_feature_not_applicable(self):
        """Test for feature that doesn't apply to all configurations."""
        assert True, "This test should be skipped where feature not applicable"
