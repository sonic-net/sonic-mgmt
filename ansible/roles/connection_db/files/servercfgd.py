#!/usr/bin/env python3
import hashlib
import itertools
import logging
import redis
import sys
import time
import xml.etree.ElementTree as ET

from socketserver import ThreadingMixIn
from xmlrpc.server import SimpleXMLRPCServer


class _LoggerWriter(object):

    def __init__(self, writer):
        self.writer = writer

    def write(self, message):
        for line in message.splitlines():
            line = line.strip()
            if line:
                self.writer(line)

    def flush(self):
        pass


logging.basicConfig(
    filename='/tmp/servercfgd.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s'
)

logger = logging.getLogger('servercfgd')
sys.stderr = _LoggerWriter(logger.debug)
sys.stdout = _LoggerWriter(logger.info)


class ThreadedSimpleXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    pass


DB_PROVISON_LOCK = "LOCK:db_provision"
REDIS_DB_CONN_POOL = None


def get_db_conn():
    global REDIS_DB_CONN_POOL
    if not REDIS_DB_CONN_POOL:
        REDIS_DB_CONN_POOL = redis.ConnectionPool(
            host='127.0.0.1', port=6379, decode_responses=True
        )
    return redis.Redis(connection_pool=REDIS_DB_CONN_POOL)


def init_connection_db():
    """Initialize the connection db."""
    logging.info('Initialize connection db')
    conn = get_db_conn()
    conn.hset('DB_META', mapping={'ServerState': 'down'})


def provision_connection_db(conn_graph_file_data, enforce_provision=False):
    """
    Provision connection db based on devices and links in connection graph.
    TODO: refactor the steps to add switch, add physical link to Lua scripts.

    @param conn_graph_file_data: connection graph xml file content
    @enforce_provision: True to provision even with dated connection graph file
    """
    def _convert_vlan_str_to_lst(vlan_str):
        vlans = []
        for vlan_range in vlan_str.split(','):
            if vlan_range.isdigit():
                vlans.append(int(vlan_range))
            elif '-' in vlan_range:
                start, end = [int(_.strip()) for _ in vlan_range.split('-')[:2]]
                vlans.extend(list(range(start, end + 1)))
            else:
                raise ValueError('Unable to convert %s' % vlan_str)
        return vlans

    def _cleanup_db(pipe):
        keys = [_ for _ in itertools.chain(conn.keys('*_TABLE*'), conn.keys('*_LIST*'), conn.keys('*_SET*'))]
        if keys:
            pipe.delete(*keys)

    conn_graph_file_hash = hashlib.md5(conn_graph_file_data.encode()).hexdigest()
    graph_xml_root = ET.fromstring(conn_graph_file_data)

    logging.info("Provision connection db based on connection graph file: %s", conn_graph_file_hash)

    conn = get_db_conn()
    lock = redis.lock.Lock(conn, DB_PROVISON_LOCK)

    if not lock.acquire(blocking=True, blocking_timeout=10):
        raise RuntimeError('Failed to acquire db provision lock.')

    try:
        conn.hset('DB_META', mapping={'server_state': 'provisioning'})

        hashes = conn.zrange('DB_CONNECTION_GRAPH_VERSIONS', 0, -1)
        logging.debug('DB_CONNECTION_GRAPH_VERSIONS: %s' % hashes)
        if not enforce_provision and conn_graph_file_hash in hashes:
            raise ValueError('Dated connection graph file to provision connection_db')
        conn.zadd(
            'DB_CONNECTION_GRAPH_VERSIONS',
            mapping={conn_graph_file_hash: time.time()}
        )
        conn.zremrangebyrank('DB_CONNECTION_GRAPH_VERSIONS', 0, -21)

        pipe = conn.pipeline(transaction=True)
        _cleanup_db(pipe)

        sonic_devs = []
        for device in graph_xml_root.iter('Device'):
            device = device.attrib
            devtype = device['Type']
            device_meta = {'HwSku': device['HwSku']}
            if 'FanoutLeaf' in devtype:
                device_meta['type'] = 'leaf_fanout'
                device_table = 'SWITCH_TABLE:' + device['Hostname']
            elif 'FanoutRoot' in devtype:
                device_meta['type'] = 'root_fanout'
                device_table = 'SWITCH_TABLE:' + device['Hostname']
            elif devtype == 'DevSonic':
                device_meta['type'] = 'dev_sonic'
                device_meta['ProvisionStatus'] = 'not_provisioned'
                device_table = 'SWITCH_TABLE:' + device['Hostname']
                sonic_devs.append(device['Hostname'])
            elif devtype == 'Server':
                device_table = 'SERVER_TABLE:' + device['Hostname']
            else:
                raise ValueError('Unsupported device: %s' % device)
            pipe.hset(device_table, mapping=device_meta)
        if sonic_devs:
            pipe.sadd('DUT_LIST', *sonic_devs)

        phy_conn = {}
        for link in graph_xml_root.iter('DeviceInterfaceLink'):
            link = link.attrib
            pipe.sadd('PORT_LIST:' + link['StartDevice'], link['StartPort'])
            pipe.sadd('PORT_LIST:' + link['EndDevice'], link['EndPort'])
            endport0 = link['StartDevice'] + ':' + link['StartPort']
            endport1 = link['EndDevice'] + ':' + link['EndPort']
            phy_conn[endport0] = endport1
            phy_conn[endport1] = endport0
            pipe.hset(
                'PORT_TABLE:' + endport0,
                mapping={
                    'BandWidth': link['BandWidth'],
                    'PhyPeerPort': endport1
                }
            )
            pipe.hset(
                'PORT_TABLE:' + endport1,
                mapping={
                    'BandWidth': link['BandWidth'],
                    'PhyPeerPort': endport0
                }
            )

        used_vlans = []
        for device in graph_xml_root.iter('DevicesL2Info'):
            devinfo = device.attrib
            for intf in device.iter('InterfaceVlan'):
                intfinfo = intf.attrib
                endport0 = devinfo['Hostname'] + ':' + intfinfo['portname']
                endport1 = phy_conn[endport0]
                pipe.hset(
                    'PORT_TABLE:' + endport0,
                    mapping={'VlanType': intfinfo['mode']}
                )
                pipe.hset(
                    'PORT_TABLE:' + endport1,
                    mapping={'VlanType': intfinfo['mode']}
                )
                if intfinfo['vlanids']:
                    vlans = _convert_vlan_str_to_lst(intfinfo['vlanids'])
                    pipe.sadd('VLAN_LIST:' + endport0, *vlans)
                    pipe.sadd('VLAN_LIST:' + endport1, *vlans)
                    used_vlans.extend(vlans)
        if used_vlans:
            pipe.sadd('USED_VLANID_SET', *used_vlans)
        pipe.execute()
    except Exception:
        logging.exception("Provision db failed, mark db as 'down'.")
        conn.hset('DB_META', mapping={'server_state': 'down'})
        raise
    else:
        logging.info("Provision done, mark db as 'active'.")
        conn.hset('DB_META', mapping={'server_state': 'active'})
    finally:
        lock.release()


if __name__ == '__main__':
    print('Starting servercfgd...')
    with ThreadedSimpleXMLRPCServer(
        ('0.0.0.0', 10033),
        logRequests=True,
        allow_none=True
    ) as server:
        server.register_introspection_functions()

        server.register_function(init_connection_db)
        server.register_function(provision_connection_db)

        try:
            server.serve_forever()
        except Exception as e:
            print('\nException %s received, exiting...' % repr(e))
            sys.exit(0)
