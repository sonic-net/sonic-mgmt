import logging
import queue
import threading
import time
import concurrent.futures
from datetime import timedelta

from tests.common.sai_validation import gnmi_client as gnmi_client


logger = logging.getLogger(__name__)


def run_subscription(call, stop_event: threading.Event, event_queue: queue.Queue):
    gnmi_client.subscribe_gnmi(call=call,
                               stop_event=stop_event,
                               event_queue=event_queue)


def cancel_on_event(call, stop_event: threading.Event):
    stop_event.wait()
    if call:
        call.cancel()
        logger.debug("cancelled gRPC stream")


def wait_for_all_futures(futures, timeout: timedelta):
    """
    Waits for all futures to complete within the specified timeout.
    """
    total_seconds = timeout.total_seconds()
    try:
        done, not_done = concurrent.futures.wait(futures, timeout=total_seconds)
        if not not_done:
            logger.debug("All tasks completed within the timeout.")
        else:
            logger.debug("Some tasks did not complete within the timeout.")

        for future in done:
            try:
                result = future.result()
                logger.debug(f"Task {futures[future]} completed: {result}")
            except Exception as e:
                logger.debug(f"Task {futures[future]} raised an exception: {e}")

        for future in not_done:
            logger.debug(f"Task {futures[future]} not completed.")
    except concurrent.futures.TimeoutError:
        logger.debug(f"Timeout occurred after {timeout} seconds.")
        for future in futures:
            if future not in done:
                logger.debug(f"Task {futures[future]} not completed.")


def _wait_until_condition(event_queue: queue.Queue,
                          prefix: str,
                          keys: list,
                          condition_cb):
    start_time = time.perf_counter()
    keys_cp = []
    if prefix:
        keys_cp = [f'{prefix}{k}' for k in keys]
    else:
        keys_cp = keys.copy()
    logger.debug(f'wait until condition is true for keys {keys_cp}')
    while len(keys_cp) > 0:
        try:
            gnmi_message = event_queue.get(timeout=0.25)
            logger.debug(f'Received message from event_queue: {gnmi_message}')
        except queue.Empty:
            logger.debug("event_queue is empty, continuing to wait...")
            continue
        kv_map = gnmi_message.get('value')
        if not kv_map:
            continue
        for k, v in kv_map.items():
            # k: key matching the DB key
            # v: value
            res = condition_cb(k, v)
            logger.debug(f"condition_cb with k={k}, v={v}, res={res}")
            if res:
                # sometimes multiple events are sent for the same key
                # so check to ensure remove doesn't fail with errors.
                if k in keys_cp:
                    logger.debug(f'Removing {k} from keys_cp = {keys_cp}')
                    keys_cp.remove(k)

    end_time = time.perf_counter()
    return len(keys_cp) == 0, (end_time - start_time)


def _wait_until_keys_match(q: queue.Queue,
                           prefix: str,
                           hashes: list,
                           key: str,
                           expected_value: str):

    return _wait_until_condition(q=q, prefix=prefix, keys=hashes,
                                 condition_cb=lambda k, v: v.get(key) == expected_value)
