import dtel_event
from infra import *


class DTelReportSession(object):
    def __init__(self,
                 switch,
                 dst_ip_list,
                 src_ip=None,
                 udp_port=None,
                 truncate_size=None):
        # Attributes
        self.switch = switch
        self._dst_ip_list = None
        self._src_ip = None
        self._udp_port = None
        self._truncate_size = None
        self.dtel_events = []
        # Properties
        DTelReportSession.dst_ip_list.fset(self, dst_ip_list)
        DTelReportSession.src_ip.fset(self, src_ip)
        DTelReportSession.udp_port.fset(self, udp_port)
        DTelReportSession.truncate_size.fset(self, truncate_size)
        # Append
        self.switch.dtel_report_sessions.append(self)

    def create_dtel_event(self, event_type=None, dscp_value=None):
        if event_type is None:
            raise ValueError('Need to provide event_type')
        if dscp_value is None:
            raise ValueError('Need to provide dscp_value')
        return dtel_event.DTelEvent(self, event_type, dscp_value)

    def delete(self):
        self.switch.dtel_report_sessions.remove(self)

    @property
    def dst_ip_list(self):
        return self._dst_ip_list

    @dst_ip_list.setter
    def dst_ip_list(self, value):
        self._dst_ip_list = check_ip_address(value)

    @property
    def src_ip(self):
        return self._src_ip

    @src_ip.setter
    def src_ip(self, value):
        if value:
            self._src_ip = check_ip_address(value)
        else:
            self._src_ip = self.switch.management_ip

    @property
    def udp_port(self):
        return self._udp_port

    @udp_port.setter
    def udp_port(self, value):
        if value < 0 or value >= 2**16:
            raise ValueError('Invalid port number')
        self._udp_port = int(value)

    @property
    def truncate_size(self):
        return self._truncate_size

    @truncate_size.setter
    def truncate_size(self, value):
        if value < 0:
            raise ValueError('Truncate size must be grater than 0')
        self._truncate_size = int(value)