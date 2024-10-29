import time

import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_sleep_2_hours():
    print("start sleep 2 hours...")
    time.sleep(7200)
    print("end sleep 2 hours.")
