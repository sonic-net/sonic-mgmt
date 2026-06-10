import pytest


pytestmark = [
    pytest.mark.topology("ptp-256", "m0"),
]


def test_dom_data_during_interface_state_changes():
    """Reserve Advanced TC1 for DOM data checks during interface state changes.

    Returns:
        None.
    """
    # Step 1: Reserved for baseline capture, shutdown/startup actions, and bidirectional DOM checks.
    # Step 2: Kept as explicit skip until full advanced workflow is implemented.
    pytest.skip("DOM advanced interface state test is not implemented yet")
