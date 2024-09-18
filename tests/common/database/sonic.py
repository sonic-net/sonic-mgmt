import redis
from enum import Enum


class RedisDB(Enum):
    APPL_DB = 0
    ASIC_DB = 1
    COUNTERS_DB = 2
    CONFIG_DB = 4
    FLEX_COUNTER_DB = 5
    STATE_DB = 6


class SonicDB:

    def __init__(self, host: str, port: int, db_id: RedisDB):
        self.conn = None
        self.host = host
        self.port = port
        self.db_id = db_id
        self.pubsub = None
        # holds a backup of the current notification flags
        self.flag_notify_keyspace_events = None
        self.pubsub_channels = []

    def new_connection(self):
        self.conn = redis.Redis(host=self.host, port=self.port, db=self.db_id, decode_responses=True)
        if self.conn.ping() is False:
            raise Exception(f'Ping failed: unable to connect to Redis {self.host}:{self.port} db={self.db}')
        cfg = self.conn.config_get()
        self.flag_notify_keyspace_events = cfg.get('notify-keyspace-events')
        # subscribe to Keyspace events (K) if it is not already
        if 'K' not in self.flag_notify_keyspace_events:
            self.conn.config_set('notify-keyspace-events', self.flag_notify_keyspace_events + 'K')
        self.pubsub = self.conn.pubsub()

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
    def wait_for_key(self, key_name: str, redis_op: str):
        pattern = f'__keyspace@1__:{key_name}*'
        self.pubsub.psubscribe()
        event = None
        for message in self.pubsub.listen():
            if message['type'] == 'pmessage':
                if message['pattern'] == pattern:
                    event = message
        self.pubsub.punsubscribe(pattern)
        return event
