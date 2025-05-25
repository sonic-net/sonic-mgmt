import logging
import concurrent.futures
import queue
import threading
import time
import pathlib

from datetime import timedelta
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor

import tests.common.sai_validation.sonic_internal as sonic_internal
import tests.common.sai_validation.gnmi_client as gnmi_client

logger = logging.getLogger(__name__)
ORIGIN = 'sonic-db'


class GnmiSubscriptionMode(IntEnum):
    ONCE = 0
    STREAM = 1
    POLL = 2


class MonitorContext:
    """
    MonitorContext is a context type that holds
    information required to stop gNMI subscription
    and cancel the thread.
    """
    def __init__(self, path, gnmi_conn, stop_event, subscription_thread, cancel_thread, disabled=False):
        self.gnmi_connection = gnmi_conn
        self.sai_validation_disabled = disabled
        self.stop_event = stop_event
        self.subscription_thread = subscription_thread
        self.cancel_thread = cancel_thread
        self.path = path


def start_db_monitor(executor: ThreadPoolExecutor,
                     gnmi_conn,
                     path: str,
                     event_queue: queue.Queue):
    if gnmi_conn is None:
        logger.debug("gNMI connection is None, disabling SAI validation.")
        return MonitorContext(None, None, None, None, None, disabled=True)

    logger.debug(f"Starting gNMI subscribe for path: {path}")
    call = gnmi_client.new_subscribe_call(gnmi_conn, [path], GnmiSubscriptionMode.STREAM)
    stop_event = threading.Event()
    subscription_thread = executor.submit(sonic_internal.run_subscription,
                                          call, stop_event, event_queue)
    cancel_thread = executor.submit(sonic_internal.cancel_on_event, call, stop_event)
    logger.debug("DB monitor started successfully.")
    ctx = MonitorContext(path, gnmi_conn, stop_event, subscription_thread, cancel_thread)
    return ctx


def stop_db_monitor(ctx: MonitorContext):
    """
    stop_db_monitor stops the thread started by 'start_db_monitor'
    function. The function returns immediately.
    """
    if ctx.sai_validation_disabled:
        logger.debug("SAI validation is disabled")
        return
    logger.debug("Stopping DB monitor.")
    ctx.stop_event.set()
    logger.debug("Stop event set for DB monitor.")
    futures = {
        ctx.cancel_thread: "cancel_thread",
        ctx.subscription_thread: "subscription_thread"
    }
    sonic_internal.wait_for_all_futures(futures, timeout=timedelta(seconds=5))
    logger.debug("DB monitor stopped successfully.")


def wait_for_n_keys(ctx: MonitorContext, filter_path: str, event_queue: queue.Queue, n: int, timeout: timedelta = None):
    """
    Waits for n keys to arrive in the queue, with an optional timedelta timeout.

    Args:
        ctx: The context returned by start_db_monitor.
        filter_path: The path to filter the keys. (Required if path contains larger subset of keys)
        event_queue: The queue to read events from.
        n: The number of keys to wait for.
        timeout: The maximum time to wait (datetime.timedelta). If the value is None,
                it will wait indefinitely.

    Returns:
        A list of the received events.
        If SAI validation is disabled it returns empty events of the expected size

    Raises:
        TimeoutError: If the timeout is reached before n keys arrive.
    """
    if ctx.sai_validation_disabled:
        logger.debug("SAI validation is disabled, skipping wait for keys.")
        empty_events = {}
        for i in range(n):
            empty_events[i] = None
        return empty_events

    logger.debug(f"Waiting for {n} keys with timeout: {timeout}")
    received_events = {}
    start_time = time.time()
    timeout_seconds = timeout.total_seconds() if timeout else None

    while len(received_events) < n:
        try:
            if timeout_seconds:
                remaining_time = timeout_seconds - (time.time() - start_time)
                if remaining_time <= 0:
                    logger.error(f"Timeout reached waiting for {n} keys.")
                    raise TimeoutError(f"Timeout reached waiting for {n} keys.")
                event = event_queue.get(timeout=remaining_time)
            else:
                logger.debug("Timer has expired, returning current received events")
                break

            # NOTE gNMI events are being sent in parts. Multiple events are sent
            # for a single key with data distributed across events. The final event
            # for a key will have all the data. Consolidate the results here.
            logger.debug(f"Received event: {event}")
            if event.get('type') != 'update':
                logger.debug("Event type is not 'update', skipping.")
                continue
            ev_map = event.get('value')
            for key_oid, value in ev_map.items():
                if key_oid not in received_events:
                    if filter_path is None or key_oid.startswith(filter_path):
                        received_events[key_oid] = value
                else:
                    if len(value) >= len(received_events[key_oid]):
                        received_events[key_oid] = value
        except queue.Empty:
            if timeout_seconds is None:
                logger.debug("Queue is empty, but no timeout is set. Continuing to wait.")
                continue  # if no timeout, keep waiting.
            else:
                logger.error(f"Timeout reached waiting for {n} keys.")
                raise TimeoutError(f"Timeout reached waiting for {n} keys.")

    logger.debug('Receive complete, fetching incomplete events')

    max_fields = 0
    for key_oid, value in received_events.items():
        if len(value) > max_fields:
            max_fields = len(value)

    logger.debug(f"Max fields for filter path {filter_path} is {max_fields}")

    for key_oid, value in received_events.items():
        if len(value) < max_fields:
            logger.debug(f"Key {key_oid} could have incomplete data perform gNMI get.")
            # treating the gNMI path as PosixPath
            p1 = pathlib.Path(ctx.path)
            p2 = pathlib.Path(key_oid)
            str_path = str(p1.joinpath(p2))
            response = get_key(ctx.gnmi_connection, str_path)
            if response:
                if response[0] and len(response[0]) > len(received_events[key_oid]):
                    logger.debug(f"Updating key {key_oid} with gNMI get response.")
                    received_events[key_oid] = response[0]

    logger.debug(f"Successfully received {len(received_events)} keys.")
    return received_events


def wait_until_condition(ctx: MonitorContext,
                         event_queue: queue.Queue,
                         prefix: str,
                         keys: list,
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
    if ctx.sai_validation_disabled:
        logger.debug("SAI validation is disabled, skipping wait until condition.")
        return True, 0.0
    executor = ThreadPoolExecutor(max_workers=3)
    future = executor.submit(sonic_internal._wait_until_condition,
                             event_queue=event_queue,
                             prefix=prefix,
                             keys=keys,
                             condition_cb=condition_cb)
    try:
        logger.debug(f'Wait until condition for {timeout.total_seconds()} seconds')
        completed, actual_time = future.result(timeout=timeout.total_seconds())
        return completed, actual_time
    except concurrent.futures.TimeoutError:
        logger.debug('wait_until_condition has timed out; cancelling the future')
        future.cancel()
        return False, 0.0
    except concurrent.futures.CancelledError:
        logger.debug('wait_until_condition has been cancelled')
        return False, 0.0
    except Exception as e:
        logger.error(f'wait_until_condition has failed with exception {e}')
        future.cancel()
        return False, 0.0
    finally:
        executor.shutdown(wait=False)


def wait_until_keys_match(ctx: MonitorContext,
                          event_queue: queue.Queue, prefix: str,
                          hashes: list, key: str, value: str,
                          timeout: timedelta):
    """
    Waits until all specified keys within a set of hash entries match a given value.

    This function monitors an event queue for updates related to a set of hash entries,
    identified by a common prefix and a list of hash identifiers. It waits until,
    for each hash entry, a specific key within the entry's data matches the expected
    value.

    For example, if the event queue contains updates like:

    'BFD_SESSION_TABLE|default|default|101.0.0.11: {'state': 'Up', ... }'
    'BFD_SESSION_TABLE|default|default|101.0.0.35: {'state': 'Down', ... }'
    'BFD_SESSION_TABLE|default|default|101.0.0.28: {'state': 'Up', ... }'

    You can use this function to wait until all specified neighbor IP addresses
    (hashes) have a 'state' (key) equal to 'Up' (value).

    Args:
        event_queue: The queue to monitor for update events.
        prefix: The common prefix for the hash entries (e.g., 'BFD_SESSION_TABLE|default|default|').
        hashes: A list of hash identifiers (e.g., neighbor IPs ['101.0.0.11', '101.0.0.35', ...]).
        key: The key within the hash entry's data to check (e.g., 'state').
        value: The expected value for the specified key (e.g., 'Up', 'Down').
        timeout: The maximum time to wait for the condition to be met.
    """
    if ctx.sai_validation_disabled:
        logger.debug("SAI validation is disabled, skipping wait until keys match.")
        return True, 0.0
    executor = ThreadPoolExecutor(max_workers=3)
    future = executor.submit(sonic_internal._wait_until_keys_match,
                             event_queue,
                             prefix,
                             hashes,
                             key,
                             value)
    try:
        logger.debug(f'Waiting for {timeout.total_seconds()} seconds')
        completed, actual_time = future.result(timeout=timeout.total_seconds())
        return completed, actual_time
    except concurrent.futures.TimeoutError:
        logger.debug('wait_until_keys_match has timed out; cancelling the future')
        future.cancel()
        return False, 0.0
    except concurrent.futures.CancelledError:
        logger.debug('wait_until_keys_match has been cancelled')
        return False, 0.0
    except Exception as e:
        logger.error(f'wait_until_keys_match has failed with exception {e}')
        future.cancel()
        return False, 0.0
    finally:
        executor.shutdown(wait=False)


def get_key(gnmi_connection, path):
    if gnmi_connection is None:
        logger.debug("gNMI connection is None, cannot get key.")
        return None
    logger.debug(f"Getting value for path {path}")
    try:
        gnmi_path = gnmi_client.get_gnmi_path(path)
        response = gnmi_client.get_request(gnmi_connection, gnmi_path)
        logger.debug(f"Response from gNMI get request: {response}")
        return response
    except Exception as e:
        logger.error(f"Error getting path: {e}")
        return None


def check_key(gnmi_connection, path, key_name, expected_value):
    if gnmi_connection is None:
        logger.debug("gNMI connection is None, cannot check key.")
        return True
    logger.debug(f"Checking path {path} for key {key_name} with expected value {expected_value}")
    try:
        response = get_key(gnmi_connection, path)
        if response and response[0].get(key_name) == expected_value:
            return True
        else:
            return False
    except Exception as e:
        logger.error(f"Error checking path: {e}")
        return False
