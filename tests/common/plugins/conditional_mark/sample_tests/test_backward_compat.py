"""
Sample tests to demonstrate backward compatibility.
These tests use the old format without categories.
"""


def test_legacy_skip_no_category():
    """Test using old skip format without category."""
    assert True, "This test uses legacy skip format"


def test_legacy_xfail():
    """Test using old xfail format."""
    assert True, "This test uses legacy xfail format"


def test_no_skip():
    """Test that should always run."""
    assert True, "This test should always pass"


class TestBackwardCompatibility:
    """Test class for backward compatibility."""

    def test_old_format_skip(self):
        """Test with old format skip."""
        assert True, "Old format skip"

    def test_should_run(self):
        """Test that should run normally."""
        assert True, "This test runs normally"
