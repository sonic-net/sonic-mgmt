"""
Sample tests to demonstrate temporary skip category.
These tests are skipped temporarily due to bugs or ongoing work.
"""


def test_bug_fix_in_progress():
    """Test that's temporarily disabled due to a bug being fixed."""
    assert True, "This test should be skipped until bug is fixed"


def test_infrastructure_issue():
    """Test that's skipped due to testbed/infrastructure problems."""
    assert True, "This test should be skipped during infrastructure maintenance"


def test_new_feature_under_development():
    """Test for feature currently under development."""
    assert True, "This test should be skipped while feature is being developed"


def test_expired_skip():
    """Test with an expired skip date - should run or fail based on expiry_action."""
    assert True, "This test has expired skip and should now run"


class TestTemporarySkips:
    """Test class demonstrating temporary skips."""

    def test_known_issue(self):
        """Test with known issue being addressed."""
        assert True, "This test should be skipped temporarily"

    def test_flaky_test(self):
        """Test that's temporarily disabled due to flakiness."""
        assert True, "This test should be skipped until stabilized"

    def test_soon_to_expire(self):
        """Test with skip that will expire soon."""
        assert True, "This test skip expires in a few days"
