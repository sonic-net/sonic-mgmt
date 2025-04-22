import logging
import time

import pytest

from tests.common.helpers.parallel_new import parallel_run

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


# Dummy target that raises an exception
def task_that_fails(x):
    time.sleep(1)
    if x % 2 == 0:
        raise RuntimeError(f"Failed on {x}")
    else:
        logger.info(f"Success on {x}")


def test_summy():
    failures = parallel_run(task_that_fails, list(range(5)))
    if failures:
        print("\nSummary of failures:")
        for name, info in failures.items():
            print(f"{name} failed with {info['exception']}\n{info['traceback']}")
