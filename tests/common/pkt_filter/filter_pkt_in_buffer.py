from collections import OrderedDict

import sys
import time
import json
import copy

import ptf.mask as mask
import ptf.packet as packet

if sys.version_info.major > 2:
    NATIVE_TYPE = (int, float, bool, list, dict, tuple, set, str, bytes, type(None))
else:
    NATIVE_TYPE = (int, float, long, bool, list, dict, tuple, set, str, bytes, unicode, type(None))     # noqa F821


def _parse_layer(layer):
    """
    Convert packet layer to dictionary

    Args:
        layer: Layer of packet

    Returns:
        Field dictionary
    """
    fields = {}

    if not hasattr(layer, 'fields_desc'):
        return None

    for field in layer.fields_desc:
        value = getattr(layer, field.name)
        if isinstance(value, type(None)):
            value = None

        if not isinstance(value, NATIVE_TYPE):
            value = _parse_layer(value)

        fields[field.name] = str(value)

    return {layer.name: fields}


def convert_pkt_to_dict(pkt):
    """
    Convert scapy packet to dictionary

    Args:
        pkt: Scapy packet

    Returns:
        Packet dictionary
    """
    packet_dict = OrderedDict()
    counter = 0

    while True:
        layer = pkt.getlayer(counter)
        if not layer:
            break

        layer_dict = _parse_layer(layer)
        if layer_dict:
            packet_dict.update(layer_dict)

        counter += 1

    return packet_dict


class FilterPktBuffer(object):
    """
    FilterPktBuffer class for finding of packets in the buffer of PTF
    """
    def __init__(self, ptfadapter, exp_pkt, dst_port_numbers, match_fields=None, ignore_fields=None):
        """
        Initialize an object for finding packets in the buffer

        Args:
            ptfadapter: PTF adapter
            exp_pkt: Expected packet
            dst_port_numbers: Destination port numbers
            match_fields: List of packet fields that should be matched
            ignore_fields: List of packet fields that should be ignored
        """
        self.received_pkt = None
        self.received_pkt_diff = []
        self.ptfadapter = ptfadapter
        self.pkt = exp_pkt
        self.dst_port_numbers = [dst_port_numbers] if not isinstance(dst_port_numbers, list) else dst_port_numbers
        self.matched_index = {port_number: 0 for port_number in self.dst_port_numbers}

        if match_fields is None:
            match_fields = []
        self.match_fields = match_fields

        if ignore_fields is None:
            ignore_fields = []
        self.ignore_fields = ignore_fields

        self.masked_exp_pkt = mask.Mask(self.pkt)
        self.pkt_dict = convert_pkt_to_dict(self.pkt)

        self.__ignore_fields()

    def __ignore_fields(self):
        """
        Ignore fields of packet
        """
        for field, value in self.ignore_fields:
            self.masked_exp_pkt.set_do_not_care_scapy(getattr(packet, field), value)

    def __remove_ignore_fields(self, pkt_dict):
        """
        Remove ignored fields from packet dictionary

        Args:
            pkt_dict: Packet dictionary

        Returns:
            Packet dictionary without ignored fields
        """
        pkt_dict = copy.deepcopy(pkt_dict)

        for field, value in self.ignore_fields:
            if pkt_dict.get(field):
                pkt_dict[field].pop(value)

        return pkt_dict

    def __find_pkt_in_buffer(self, dst_port_number):
        """
        Find expected packet in buffer by using matched fields

        Returns:
            Received packet
        """
        time.sleep(3)
        common_buffer = self.ptfadapter.dataplane.packet_queues
        packet_buffer = common_buffer[(0, dst_port_number)][:]
        matched_index = 0
        received_pkt = None

        for pkt in packet_buffer:
            packet_dict = convert_pkt_to_dict(packet.Ether(pkt[0]))

            for field, value in self.match_fields:
                try:
                    if packet_dict[field][value] != self.pkt_dict[field][value]:
                        break
                except KeyError:
                    break
            else:
                matched_index += 1
                received_pkt = packet.Ether(pkt[0])

        if received_pkt:
            return ({dst_port_number: matched_index}, received_pkt)

        return (None, None)

    def __diff_between_dict(self, rcv_pkt_dict, exp_pkt_dict, path=''):
        """
        Find the difference between received packet dictionary and expected packet dictionary

        Args:
            rcv_pkt_dict: Received packet dictionary
            exp_pkt_dict: Expected packet dictionary
            path: Path to values of fields

        Returns:
            List of packet fields
        """
        for field in rcv_pkt_dict:
            if field not in exp_pkt_dict:
                self.received_pkt_diff.append("{}{}={}".format(path and path + ' ', field, rcv_pkt_dict[field]))
            elif isinstance(rcv_pkt_dict[field], dict):
                if path == "":
                    path = field
                else:
                    path = path + " " + field
                self.__diff_between_dict(rcv_pkt_dict[field], exp_pkt_dict[field], path)
                path = ""
            elif rcv_pkt_dict[field] != exp_pkt_dict[field]:
                self.received_pkt_diff.append("{}{}={}".format(path + ' ', field, rcv_pkt_dict[field]))

        return self.received_pkt_diff

    def _diff_between_pkt(self, received_pkt):
        """
        Get the difference between received packet and expected packet

        Args:
            received_pkt: Received packet

        Returns:
            Difference between received packet and expected packet
        """
        received_pkt = convert_pkt_to_dict(received_pkt)
        received_pkt = self.__remove_ignore_fields(received_pkt)

        masked_pkt = self.__remove_ignore_fields(self.pkt_dict)

        return self.__diff_between_dict(received_pkt, masked_pkt)

    def filter_pkt_in_buffer(self):
        """
        Filter expected packet in buffer

        Returns:
            Bool value or difference between received packet and expected packet
        """
        for dst_port in self.dst_port_numbers:
            matched_index, received_pkt = self.__find_pkt_in_buffer(dst_port)

            if received_pkt:
                self.received_pkt = received_pkt
                self.matched_index.update(matched_index)

        if self.received_pkt:
            return self.masked_exp_pkt.pkt_match(self.received_pkt) or self._diff_between_pkt(self.received_pkt)

        return False

    def show_packet(self, pkt_type='expected'):
        """
        Show packet structure without ignored fields

        Args:
            pkt_type: Type of packet (expected or received)
        """
        if pkt_type == 'received' and self.received_pkt:
            received_pkt = convert_pkt_to_dict(self.received_pkt)
            print(('Received packet:\n{}'.format(json.dumps(self.__remove_ignore_fields(received_pkt), indent=4))))
        elif pkt_type == 'expected':
            print(('Expected packet:\n{}'.format(json.dumps(self.__remove_ignore_fields(self.pkt_dict), indent=4))))
        elif pkt_type == 'received':
            print('Received packet not available')
        else:
            print('Specify the package type ("received" or "expected")')
