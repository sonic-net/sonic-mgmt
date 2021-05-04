#!/usr/bin/env python3
import hashlib
import json
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
DB_SCRIPTS = {}


def _get_db_conn():
    global REDIS_DB_CONN_POOL
    if not REDIS_DB_CONN_POOL:
        REDIS_DB_CONN_POOL = redis.ConnectionPool(
            host='127.0.0.1', port=6379, decode_responses=True
        )
    return redis.Redis(connection_pool=REDIS_DB_CONN_POOL)


def register_script(script_name, script_content):
    """Register Lua script to connection_db."""
    logging.info('Register script %s', script_name)
    conn = _get_db_conn()
    conn.script_load(script_content)
    script = conn.register_script(script_content)
    script.name = script_name
    DB_SCRIPTS[script_name] = script


def get_scripts():
    """Return the script name to SHA1 hash mapping."""
    return {name: script.sha for name, script in DB_SCRIPTS.items()}


def init_connection_db():
    """Initialize the connection db."""
    logging.info('Initialize connection db')
    conn = _get_db_conn()
    db_state = conn.hget('DB_META', 'DBState')
    if db_state and db_state != 'down':
        raise RuntimeError('Connection db had been initialized')
    conn.hset('DB_META', mapping={'DBState': 'down'})


def provision_connection_db(conn_graph_file_data, enforce_provision=False):
    """
    Provision connection db based on devices and links in connection graph.

    @param conn_graph_file_data: connection graph xml file content
    @param enforce_provision: True to provision even with dated connection graph file
    """

    def _convert_vlan_str_to_lst(vlan_str):
        vlans = []
        if not vlan_str:
            return vlans
        for vlan_range in vlan_str.split(','):
            if vlan_range.isdigit():
                vlans.append(int(vlan_range))
            elif '-' in vlan_range:
                start, end = [int(_.strip()) for _ in vlan_range.split('-')[:2]]
                vlans.extend(list(range(start, end + 1)))
            else:
                raise ValueError('Unable to convert %s' % vlan_str)
        return vlans

    conn_graph_file_hash = hashlib.md5(conn_graph_file_data.encode()).hexdigest()
    graph_xml_root = ET.fromstring(conn_graph_file_data)

    logging.info("Provision connection db based on connection graph file: %s", conn_graph_file_hash)

    conn = _get_db_conn()
    lock = redis.lock.Lock(conn, DB_PROVISON_LOCK)

    if not lock.acquire(blocking=True, blocking_timeout=10):
        raise RuntimeError('Failed to acquire db provision lock.')

    try:
        conn.hset('DB_META', mapping={'server_state': 'provisioning'})

        hashes = conn.zrange('DB_CONNECTION_GRAPH_VERSIONS', 0, -1)
        logging.debug('DB_CONNECTION_GRAPH_VERSIONS: %s', hashes)
        if not enforce_provision and conn_graph_file_hash in hashes:
            raise ValueError('Dated connection graph file to provision connection_db')

        pipe = conn.pipeline(transaction=True)
        DB_SCRIPTS['cleanup'](args=['*_TABLE*', '*_LIST*', '*_SET*'], client=pipe)

        devices = {}
        for device in graph_xml_root.iter('Device'):
            device = device.attrib
            devices[device['Hostname']] = device

        # collect management IP from DevicesL3Info
        for device in graph_xml_root.iter('DevicesL3Info'):
            devinfo = device.attrib
            for mgmt_iface in device.iter('ManagementIPInterface'):
                ifaceinfo = mgmt_iface.attrib
                if ifaceinfo['Name'] == 'ManagementIp':
                    devices[devinfo['Hostname']]['ManagementIp'] = ifaceinfo['Prefix']

        for devname, device in devices.items():
            devtype = device['Type']
            device = json.dumps(device)
            if devtype == 'Server':
                device_table = 'SERVER_TABLE' + ':' + devname
                DB_SCRIPTS['add_server'](keys=[device_table], args=[device], client=pipe)
            else:
                device_table = 'SWITCH_TABLE' + ':' + devname
                DB_SCRIPTS['add_switch'](keys=[device_table, 'DUT_LIST'], args=[device], client=pipe)

        vlans = {}
        for device in graph_xml_root.iter('DevicesL2Info'):
            hostname = device.attrib['Hostname']
            vlans.setdefault(hostname, {})
            for iface in device.iter('InterfaceVlan'):
                ifaceinfo = iface.attrib
                vlans[hostname][ifaceinfo['portname']] = (
                    ifaceinfo['mode'],
                    _convert_vlan_str_to_lst(ifaceinfo['vlanids'])
                )

        for link in graph_xml_root.iter('DeviceInterfaceLink'):
            link = link.attrib
            sd, sp = link['StartDevice'], link['StartPort']
            ed, ep = link['EndDevice'], link['EndPort']
            start_dev_port_list = 'PORT_LIST' + ':' + sd
            end_dev_port_list = 'PORT_LIST' + ':' + ed
            start_dev_port_table = 'PORT_TABLE' + ':' + sd + ':' + sp
            end_dev_port_table = 'PORT_TABLE' + ':' + ed + ':' + ep
            if sp in vlans.get(sd, {}):
                vlan_mode = vlans[sd][sp][0]
            elif ep in vlans.get(ed, {}):
                vlan_mode = vlans[ed][ep][0]
            else:
                raise ValueError('No vlan mode set for link: %s' % link)

            DB_SCRIPTS['add_phy_link'](
                keys=[
                    start_dev_port_list,
                    start_dev_port_table,
                    end_dev_port_list,
                    end_dev_port_table
                ],
                args=[
                    sd,
                    sp,
                    ed,
                    ep,
                    link['BandWidth'],
                    vlan_mode
                ],
                client=pipe
            )

        for device in vlans:
            for port in vlans[device]:
                vlan_list_name = 'VLAN_LIST' + ':' + device + ':' + port
                DB_SCRIPTS['update_vlanid'](
                    keys=[
                        'USED_VLANIDPOOL_SET',
                        vlan_list_name
                    ],
                    args=vlans[device][port][1],
                    client=pipe
                )

        pipe.zadd(
            'DB_CONNECTION_GRAPH_VERSIONS',
            mapping={conn_graph_file_hash: time.time()}
        )
        # trim the hashes to keep only 20 entries
        pipe.zremrangebyrank('DB_CONNECTION_GRAPH_VERSIONS', 0, -21)
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

        server.register_function(register_script)
        server.register_function(get_scripts)
        server.register_function(init_connection_db)
        server.register_function(provision_connection_db)

        try:
            server.serve_forever()
        except Exception as e:
            print('\nException %s received, exiting...' % repr(e))
            sys.exit(0)
