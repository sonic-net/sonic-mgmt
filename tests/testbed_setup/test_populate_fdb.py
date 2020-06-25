import pytest

from common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]

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
