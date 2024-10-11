import redis
import logging
import queue
import time
import threading

from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class _SonicDBContext:
    def __init__(self, executor: ThreadPoolExecutor,
                 q: queue.Queue, future: Future,
                 stop_flag: threading.Event):
        self.executor = executor
        self.q = q
        self.future = future
        self.stop_flag = stop_flag


def _wait_until_condition(q: queue.Queue,
                          prefix: str,
                          keys: list,
                          condition_cb):
    start_time = time.perf_counter()
    keys_cp = [f'{prefix}{k}' for k in keys]
    logger.debug(f'wait until condition is true for keys {keys_cp}')
    while len(keys_cp) > 0:
        try:
            tup = q.get(timeout=0.25)
            logger.debug(f'Received message from q: {tup}')
        except queue.Empty:
            continue
        k, v = tup
        if condition_cb(k, v):
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


def _publish_to_queue(redis_conn: redis.Redis,
                      key_pattern: str,
                      q: queue.Queue,
                      stop_flag: threading.Event):
    db_num = redis_conn.connection_pool.connection_kwargs.get('db')
    if db_num is None:
        raise Exception('cannot determine database number')
    pubsub = redis_conn.pubsub()
    keyspace_str = f'__keyspace@{db_num}__:'
    pattern = f'{keyspace_str}{key_pattern}'
    logger.debug(f'Subscribing to keyspace events {pattern}')
    pubsub.psubscribe(pattern)
    while not stop_flag.is_set():
        message = pubsub.get_message(timeout=0.25)  # 250ms
        if message is None:
            continue
        logger.debug(f'Recieved message from pubsub {message}')
        if message['type'] == 'pmessage':
            if message['pattern'] == pattern:
                key = message['channel'][len(keyspace_str):]
                val = None
                op = message['data']
                if op == 'hset':
                    val = redis_conn.hgetall(key)
                if op == 'set':
                    val = redis_conn.get(key)
                tup = (key, val)
                q.put(tup)
                logger.debug(f'Wrote {tup} to queue')

    logger.debug('Closing pubsub')
    pubsub.close()


def _wait_for_n_keys(redis_conn: redis.Redis, n: int, key_pattern: str):
    start_time = time.perf_counter()
    db_num = redis_conn.connection_pool.connection_kwargs.get('db')
    if db_num is None:
        raise Exception('cannot determine database number')
    pubsub = redis_conn.pubsub()
    keyspace_str = f'__keyspace@{db_num}__:'
    pattern = f'{keyspace_str}{key_pattern}'
    pubsub.psubscribe(pattern)
    events = {}
    logger.debug(f'__wait_for_n_keys {n} keys with pattern {pattern}')
    n_events = 0
    for message in pubsub.listen():
        if message['type'] == 'pmessage':
            if message['pattern'] == pattern:
                key = message['channel'][len(keyspace_str):]
                val = redis_conn.hgetall(key)
                if key not in events:
                    events[key] = val
                    n_events += 1
                if n_events == n:
                    break
    pubsub.close()
    logger.debug(f'Received {n_events} events. Closing pubsub')
    end_time = time.perf_counter()
    return events, (end_time - start_time)
