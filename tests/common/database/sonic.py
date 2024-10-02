import redis
from enum import IntEnum
import logging
import time

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
def wait_for_key(redis_conn: redis.Redis, key_name):
    start_time = time.perf_counter()
    logger.info(f'wait_for_key called on {redis_conn} with key {key_name}')
    db_num = redis_conn.connection_pool.connection_kwargs.get('db')
    if db_num is None:
        raise Exception('cannot determine database number')
    logger.info(f'database number {db_num}')
    pubsub = redis_conn.pubsub()
    keyspace_str = f'__keyspace@{db_num}__:'
    pattern = f'{keyspace_str}{key_name}*'
    pubsub.psubscribe(pattern)
    logger.info('psubscribe setup with pattern {pattern}')
    event = None
    logger.info('listening for messages on pubsub')
    for message in pubsub.listen():
        logger.info(f'received message {message}')
        if message['type'] == 'pmessage':
            if message['pattern'] == pattern:
                event = message
                break
    pubsub.close()
    logger.info(f'pubsub closed. event {event}')
    key = event['channel'][len(keyspace_str):]
    val = redis_conn.hgetall(key)
    logger.info(f'key = {key}, value = {val}')
    end_time = time.perf_counter()
    return val, (end_time - start_time)


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
