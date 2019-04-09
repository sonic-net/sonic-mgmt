#!/usr/bin/python

import time
import binascii

from scapy.all import Ether
from scapy.all import sendp

SEND_TIMEOUT = 30
PORT_RANGE = 32

LLDP_MAC = '01:80:c2:00:00:0e'
LLDP_ETHERTYPE = 0x88cc

TLV_TYPE_CHASSIS_ID = '\x02\x07\x04'

TLV_TYPE_PORT_ID = '\x04\x0a\x05'
TLV_VALUE_PORT_ID = 'Ethernet1'

TLV_TYPE_TIME_TO_LIVE = '\x06\x02'
TLV_VALUE_TIME_TO_LIVE = '\x00\x78'

TLV_TYPE_SYSTEM_NAME = '\x0a\x0a'

TLV_TYPE_SYSTEM_DESCRIPTION = '\x0c\x46'
TLV_VALUE_SYSTEM_DESCRIPTION = 'Arista Networks EOS version 4.16.6M running on an Arista Networks vEOS'

ETHERNET_ARISTA_MAP = {
    'et0':  'ARISTA01T2',
    'et1':  'ARISTA02T2',
    'et2':  'ARISTA03T2',
    'et3':  'ARISTA04T2',
    'et4':  'ARISTA05T2',
    'et5':  'ARISTA06T2',
    'et6':  'ARISTA07T2',
    'et7':  'ARISTA08T2',
    'et8':  'ARISTA09T2',
    'et9':  'ARISTA10T2',
    'et10': 'ARISTA11T2',
    'et11': 'ARISTA12T2',
    'et12': 'ARISTA13T2',
    'et13': 'ARISTA14T2',
    'et14': 'ARISTA15T2',
    'et15': 'ARISTA16T2',
    'et16': 'ARISTA01T0',
    'et17': 'ARISTA02T0',
    'et18': 'ARISTA03T0',
    'et19': 'ARISTA04T0',
    'et20': 'ARISTA05T0',
    'et21': 'ARISTA06T0',
    'et22': 'ARISTA07T0',
    'et23': 'ARISTA08T0',
    'et24': 'ARISTA09T0',
    'et25': 'ARISTA10T0',
    'et26': 'ARISTA11T0',
    'et27': 'ARISTA12T0',
    'et28': 'ARISTA13T0',
    'et29': 'ARISTA14T0',
    'et30': 'ARISTA15T0',
    'et31': 'ARISTA16T0'
}

LLDP_PAYLOAD = '{TLV_TYPE_CHASSIS_ID}{TLV_VALUE_CHASSIS_ID}' + \
'{TLV_TYPE_PORT_ID}{TLV_VALUE_PORT_ID}' + \
'{TLV_TYPE_TIME_TO_LIVE}{TLV_VALUE_TIME_TO_LIVE}' + \
'{TLV_TYPE_SYSTEM_NAME}{TLV_VALUE_SYSTEM_NAME}' + \
'{TLV_TYPE_SYSTEM_DESCRIPTION}{TLV_VALUE_SYSTEM_DESCRIPTION}' + \
'\x0e\x04\x00\x14\x00\x14\x10\x0c\x05\x01\x0a\xd5\x56\x3d\x02\x00' + \
'\x0f\x3e\x59\x00\xfe\x06\x00\x80\xc2\x01\x00\x00\xfe\x09\x00\x12' + \
'\x0f\x03\x01\x00\x00\x00\x00\xfe\x06\x00\x12\x0f\x04\x24\x14\x00' + \
'\x00'


def get_mac(iface):
    with open('/sys/class/net/{}/address'.format(iface)) as mac:
        return mac.read().strip()


def get_payload(iface):
    return LLDP_PAYLOAD.format(
        TLV_TYPE_CHASSIS_ID=TLV_TYPE_CHASSIS_ID,
        TLV_VALUE_CHASSIS_ID=binascii.unhexlify(get_mac(iface).replace(':', '')),
        TLV_TYPE_PORT_ID=TLV_TYPE_PORT_ID,
        TLV_VALUE_PORT_ID=TLV_VALUE_PORT_ID,
        TLV_TYPE_TIME_TO_LIVE=TLV_TYPE_TIME_TO_LIVE,
        TLV_VALUE_TIME_TO_LIVE=TLV_VALUE_TIME_TO_LIVE,
        TLV_TYPE_SYSTEM_NAME=TLV_TYPE_SYSTEM_NAME,
        TLV_VALUE_SYSTEM_NAME=ETHERNET_ARISTA_MAP[iface],
        TLV_TYPE_SYSTEM_DESCRIPTION=TLV_TYPE_SYSTEM_DESCRIPTION,
        TLV_VALUE_SYSTEM_DESCRIPTION=TLV_VALUE_SYSTEM_DESCRIPTION
    )


def create_lldp(iface):
    print 'Creating LLDP: dst=' + LLDP_MAC + ', src=' + get_mac(iface)

    pkt = Ether(dst=LLDP_MAC, src=get_mac(iface), type=LLDP_ETHERTYPE)
    pkt = pkt / get_payload(iface)

    return pkt


def main():
    while True:
        for iface in ['et{}'.format(i) for i in xrange(PORT_RANGE)]:
            lldp = create_lldp(iface)
            sendp(lldp, iface=iface)
            print 'Sent LLDP: iface = ' + iface

        time.sleep(SEND_TIMEOUT)


if __name__ == '__main__':
    main()
