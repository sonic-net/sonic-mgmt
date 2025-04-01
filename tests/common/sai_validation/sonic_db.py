import logging
import concurrent.futures
import queue
import threading
import time

from datetime import timedelta
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor

import tests.common.sai_validation.sonic_internal as sonic_internal

logger = logging.getLogger(__name__)
ORIGIN = 'sonic-db'


class GnmiSubscriptionMode(IntEnum):
    ONCE = 0
    STREAM = 1
    POLL = 2


def start_db_monitor(executor: ThreadPoolExecutor,
                     gnmi_conn,
                     key_pattern: str,
                     event_queue: queue.Queue):
    stop_event = threading.Event()
    future = executor.submit(sonic_internal.run_subscription,
                             key_pattern, gnmi_conn, ORIGIN,
                             GnmiSubscriptionMode.STREAM, False,
                             stop_event, event_queue)
    return stop_event, future


def stop_db_monitor(stop_event: threading.Event, future: concurrent.futures.Future):
    """
    stop_db_monitor stops the thread started by 'start_db_monitor'
    function. The function returns immediately.
    """
    stop_event.set()
    logger.debug('stop_db_monitor called; stop event set')
    # wait for the thread to complete. Re-raises an exceptions
    future.result()


def wait_for_n_keys(event_queue: queue.Queue, n: int, timeout: timedelta = None) -> list:
    """
    Waits for n keys to arrive in the queue, with an optional timedelta timeout.

    Args:
        event_queue: The queue to read events from.
        n: The number of keys to wait for.
        timeout: The maximum time to wait (datetime.timedelta). If the value is None,
                it will wait indefinitely.

    Returns:
        A list of the received events.

    Raises:
        TimeoutError: If the timeout is reached before n keys arrive.
    """
    received_events = []
    start_time = time.time()
    timeout_seconds = timeout.total_seconds() if timeout else None

    while len(received_events) < n:
        try:
            if timeout_seconds:
                remaining_time = timeout_seconds - (time.time() - start_time)
                if remaining_time <= 0:
                    raise TimeoutError(f"Timeout reached waiting for {n} keys.")
                event = event_queue.get(timeout=remaining_time)
            else:
                event = event_queue.get(timeout=None)  # Block indefinitely

            received_events.append(event)

        except queue.Empty:
            if timeout_seconds is None:
                continue  # if no timeout, keep waiting.
            else:
                raise TimeoutError(f"Timeout reached waiting for {n} keys.")

    return received_events


def wait_until_condition(event_queue: queue.Queue,
                         prefix: str,
                         condition_cb,
                         timeout: timedelta):
    """
    wait_until_condition accepts the 'q' from 'start_subscribe',
    the 'prefix', 'keys', and a callback function of signature
    `cb(key, value) -> bool`. The function checks on the specified
    keys (format: {prefix}{keys[0]}, {prefix}{keys[1]...})
    until the callback returns true for all the keys in the list
    or the function times-out. Whichever comes first.
    """
    if condition_cb is None:
        raise Exception('callback not set')
    return


def wait_until_keys_match(event_queue: queue.Queue, prefix: str,
                          hashes: list, key: str, value: str,
                          timeout: timedelta):
    """
    A convinience wrapper over wait_until_condition.
    wait_until_keys_match waits until all the given hashes'
    have the 'key' with the expected value 'value'. Example -

    BFD_SESSION_TABLE|default|default|101.0.0.11: {'state', 'Up', ... }
    BFD_SESSION_TABLE|default|default|101.0.0.35: {'state', 'Down', ... }
    BFD_SESSION_TABLE|default|default|101.0.0.28: {'state', 'Up', ... }

    prefix: BFD_SESSION_TABLE|default|default|
    hashes: neighbor ips ["101.0.0.11", "101.0.0.35",...]
    key: key of the hash table (from example above like 'state')
    value: value of the key (from example above like 'Up' or 'Down' etc.)
    """
    pass
