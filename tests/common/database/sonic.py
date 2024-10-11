import redis
import logging
import concurrent.futures
import queue
import threading

from datetime import timedelta
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor

import tests.common.database.sonic_internal as sonic_internal

logger = logging.getLogger(__name__)


class SonicDBInstance(IntEnum):
    APPL_DB = 0
    ASIC_DB = 1
    COUNTERS_DB = 2
    CONFIG_DB = 4
    FLEX_COUNTER_DB = 5
    STATE_DB = 6


# Each SONiC Redis database has different key separators
# defined here -
# https://github.com/sonic-net/sonic-buildimage/blob/master/dockers/docker-database/database_config.json.j2
# The map below is based on this
key_separator_per_db = {
    SonicDBInstance.APPL_DB: ':',
    SonicDBInstance.ASIC_DB: ':',
    SonicDBInstance.COUNTERS_DB: ':',
    SonicDBInstance.CONFIG_DB: '|',
    SonicDBInstance.FLEX_COUNTER_DB: ':',
    SonicDBInstance.STATE_DB: '|'
}


def start_db_monitor(executor: ThreadPoolExecutor,
                     redis_conn: redis.Redis,
                     n: int,
                     key_pattern: str) -> concurrent.futures.Future:
    """
    start_db_monitor starts a thread that waits for 'n' key changes
    specified by the 'key_pattern'. The function returns immediately
    with a handle to the future (thread).
    """
    future = executor.submit(sonic_internal._wait_for_n_keys, redis_conn, n, key_pattern)
    logger.debug(f'Submission for wait_for_n_keys complete returning {future}')
    return future


def await_monitor(future: concurrent.futures.Future, timeout: timedelta):
    """
    await_monitor waits for the thread started by 'start_db_monitor' function
    It waits for the duration of the 'timeout' value for the thread to complete
    and times out if the thread if it runs beyond the specified value.
    """
    events = None
    time_spent = None
    try:
        events, time_spent = future.result(timeout=timeout.total_seconds())
    except concurrent.futures.TimeoutError:
        logger.error('Monitor timedout waiting for keys')
    return events, time_spent


def start_subscribe(redis_conn: redis.Redis, key_pattern: str):
    """
    start_subscribe returns a 'queue.Queue' and a context
    (opaque to the caller). The function creates a producer thread
    that monitors the database for changes based on the specified key_pattern
    and adds those events to the queue.
    """
    executor = ThreadPoolExecutor(max_workers=3)
    q = queue.Queue()
    stop_flag = threading.Event()
    future = executor.submit(sonic_internal._publish_to_queue,
                             redis_conn, key_pattern, q, stop_flag)
    ctx = sonic_internal._SonicDBContext(executor, q, future, stop_flag)
    logger.debug('Subscription started')
    return q, ctx


def stop_subscribe(ctx: sonic_internal._SonicDBContext):
    """
    stop_subscribe stops the thread, the subscription
    for the key_pattern and deletes the queue.
    """
    ctx.stop_flag.set()
    ctx.executor.shutdown(wait=False)
    del ctx.q
    logger.debug('Subscription stopped')


def wait_until_condition(q: queue.Queue,
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
    executor = ThreadPoolExecutor(max_workers=3)
    future = executor.submit(sonic_internal._wait_until_condition,
                             q=q,
                             prefix=prefix,
                             keys=keys,
                             condition_cb=condition_cb)
    try:
        logger.debug(f'Wait until condition for {timeout.total_seconds()} seconds')
        completed, actual_time = future.result(timeout=timeout.total_seconds())
        return completed, actual_time
    except concurrent.futures.TimeoutError:
        logger.debug('wait_until_condition has timed out')
    finally:
        executor.shutdown(wait=False)


def wait_until_keys_match(q: queue.Queue, prefix: str,
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
    executor = ThreadPoolExecutor(max_workers=3)
    future = executor.submit(sonic_internal._wait_until_keys_match,
                             q,
                             prefix,
                             hashes,
                             key,
                             value)
    try:
        logger.debug(f'Waiting for {timeout.total_seconds()} seconds')
        completed, actual_time = future.result(timeout=timeout.total_seconds())
        return completed, actual_time
    except concurrent.futures.TimeoutError:
        logger.debug('wait_until_keys_match has timed out')
    finally:
        executor.shutdown(wait=False)


def check_hash_key(redis_conn: redis.Redis, hash_table, key_name, expected_value):
    actual = redis_conn.hget(hash_table, key_name)
    logger.debug(f'check_hash_key table = {hash_table},'
                 f' key = {key_name}, expected = {expected_value}, actual = {actual}')
    return actual == expected_value


class SonicDB:

    def __init__(self, host: str, port: int, db_id: SonicDBInstance, max_conns=3):
        self.host = host
        self.port = port
        self.db_id = int(db_id)
        self.pool = redis.ConnectionPool(host=self.host,
                                         port=self.port,
                                         db=self.db_id,
                                         max_connections=max_conns,
                                         decode_responses=True)
        self.r = redis.Redis(connection_pool=self.pool)
        if self.r.ping() is False:
            raise Exception(f'Ping failed: unable to connect to Redis {self.host}:{self.port} db={self.db}')
        logger.info('sonic db ping successful')

    def connection(self):
        redis_conn = redis.Redis(connection_pool=self.pool)
        cfg = redis_conn.config_get()
        self.flag_notify_keyspace_events = cfg.get('notify-keyspace-events')
        # subscribe to Keyspace events (K) if it is not already
        if 'K' not in self.flag_notify_keyspace_events:
            raise Exception('Keyspace notifications must be enabled')
        return redis_conn
