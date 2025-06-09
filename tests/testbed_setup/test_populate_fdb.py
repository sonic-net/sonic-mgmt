import pytest


pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx')
]


def test_populate_fdb(populate_fdb):
    """
        Populates DUT FDB entries

        Args:
            request: pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    pass
