import time

import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_bgp_facts():
    print("start to sleep 2 hours...")
    time.sleep(2 * 60 * 60)
    print("end to sleep 2 hours.")
