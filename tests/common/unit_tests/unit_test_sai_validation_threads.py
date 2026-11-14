import queue
from datetime import timedelta

from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.sai_validation import sonic_internal


def test_wait_for_all_futures_supports_safe_thread_pool_executor():
    executor = SafeThreadPoolExecutor(max_workers=2)
    results = {
        executor.submit(lambda value: value, "subscription"): "subscription_thread",
        executor.submit(lambda value: value, "cancel"): "cancel_thread",
    }

    sonic_internal.wait_for_all_futures(results, timeout=timedelta(seconds=1))

    assert all(result.ready() for result in results)
    assert {result.get() for result in results} == {"subscription", "cancel"}
    executor.shutdown(wait=True)


def test_wait_until_keys_match_uses_event_queue():
    event_queue = queue.Queue()
    event_queue.put({
        "value": {
            "default|default|10.0.0.1": {
                "state": "Up",
            },
        },
    })

    matched, _ = sonic_internal._wait_until_keys_match(
        event_queue,
        prefix="default|default|",
        hashes=["10.0.0.1"],
        key="state",
        expected_value="Up",
    )

    assert matched
