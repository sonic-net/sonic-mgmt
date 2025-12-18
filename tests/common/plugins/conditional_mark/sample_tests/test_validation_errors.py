"""
Sample tests to demonstrate validation errors.
These tests have intentional configuration errors to test validation.
"""


def test_invalid_category():
    """Test with invalid category name."""
    assert True, "This should cause validation error - invalid category"


def test_missing_expiry_for_temporary():
    """Test with temporary category but missing expiry_date."""
    assert True, "This should cause validation error - missing expiry"


def test_expiry_on_permanent():
    """Test with permanent category but has expiry_date."""
    assert True, "This should cause validation error - permanent with expiry"


def test_expiry_too_far():
    """Test with expiry date beyond max_expiry_days."""
    assert True, "This should cause validation error - expiry too far in future"


def test_invalid_date_format():
    """Test with invalid date format."""
    assert True, "This should cause validation error - invalid date format"
