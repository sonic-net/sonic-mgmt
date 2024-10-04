import redis
import logging
import concurrent.futures
import time

from datetime import timedelta
from enum import IntEnum

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


def start_db_monitor(executor: concurrent.futures.ThreadPoolExecutor,
                     redis_conn: redis.Redis,
                     n: int,
                     key_pattern: str) -> concurrent.futures.Future:
    logger.debug('Begin start_monitor')
    logger.debug('submitting pattern to get_n_keys')
    future = executor.submit(get_n_keys, redis_conn, n, key_pattern)
    logger.debug(f'submission complete returning {future}')
    return future


def await_monitor(future: concurrent.futures.Future, timeout: timedelta):
    events = None
    time_spent = None
    try:
        events, time_spent = future.result(timeout=timeout.total_seconds())
    except concurrent.futures.TimeoutError:
        logger.error('Monitor timedout waiting for keys')
    return events, time_spent


# psubscribe message format
# {
#  'type': 'psubscribe',
#  'pattern': None,
#  'channel': '__keyspace@1__:ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*',
#  'data': 1
# }
# pmessage format
# {
#  'type': 'pmessage',
#  'pattern': '__keyspace@1__:ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*',
#  'channel': '__keyspace@1__:ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:oid:0x21000000000000',
#  'data': 'hset'
# }
def get_n_keys(redis_conn: redis.Redis, n: int, key_pattern: str):
    start_time = time.perf_counter()
    logger.debug(f'Using {redis_conn} waiting for {n} keys with pattern {key_pattern}')
    db_num = redis_conn.connection_pool.connection_kwargs.get('db')
    if db_num is None:
        raise Exception('cannot determine database number')
    logger.debug(f'database number {db_num}')
    pubsub = redis_conn.pubsub()
    keyspace_str = f'__keyspace@{db_num}__:'
    pattern = f'{keyspace_str}{key_pattern}'
    pubsub.psubscribe(pattern)
    logger.debug(f'psubscribe setup with pattern {pattern}')
    events = {}
    logger.debug('listening for messages on pubsub')
    n_events = 0
    for message in pubsub.listen():
        logger.debug(f'received message {message}')
        if message['type'] == 'pmessage':
            if message['pattern'] == pattern:
                key = message['channel'][len(keyspace_str):]
                val = redis_conn.hgetall(key)
                events[key] = val
                n_events += 1
                if n_events == n:
                    break
    pubsub.close()
    logger.debug(f'Received {n_events} events. Closing pubsub')
    end_time = time.perf_counter()
    return events, (end_time - start_time)


class SonicDB:

    def __init__(self, host: str, port: int, db_id: SonicDBInstance, max_conns=3):
        self.host = host
        self.port = port
        self.db_id = int(db_id)
        # holds a backup of the current notification flags
        self.pool = redis.ConnectionPool(host=self.host,
                                         port=self.port,
                                         db=self.db_id,
                                         max_connections=max_conns,
                                         decode_responses=True)
        logger.info(f'sonic db connection pool created {self.pool}')
        self.r = redis.Redis(connection_pool=self.pool)
        if self.r.ping() is False:
            raise Exception(f'Ping failed: unable to connect to Redis {self.host}:{self.port} db={self.db}')
        logger.info('sonic db ping successful')

    def connection(self):
        redis_conn = redis.Redis(connection_pool=self.pool)
        logger.info(f'returning one connection from the pool {redis_conn}')
        cfg = redis_conn.config_get()
        self.flag_notify_keyspace_events = cfg.get('notify-keyspace-events')
        # subscribe to Keyspace events (K) if it is not already
        if 'K' not in self.flag_notify_keyspace_events:
            redis_conn.config_set('notify-keyspace-events', self.flag_notify_keyspace_events + 'K')
        logger.info(f'sonic db connection pubsub notification flags {self.flag_notify_keyspace_events}')
        return redis_conn
