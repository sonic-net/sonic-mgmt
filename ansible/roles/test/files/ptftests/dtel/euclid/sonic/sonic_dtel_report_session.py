from dtel import dtel_report_session
import sonic_dtel_event
from dtel.infra import *


class SONiCDTelReportSession(dtel_report_session.DTelReportSession, FrozenClass):
    def __init__(self,
                 switch,
                 dst_ip_list,
                 src_ip=None,
                 udp_port=None,
                 truncate_size=None):
        super(SONiCDTelReportSession, self).__init__(
            switch,
            dst_ip_list,
            src_ip=src_ip,
            udp_port=udp_port,
            truncate_size=truncate_size)
        session_id = self.switch.generate_id('DTEL_REPORT_SESSION|REPORT_SESSION')
        self.hashname = 'REPORT_SESSION' + session_id
        if not isinstance(dst_ip_list, list):
            dst_ip_list = [dst_ip_list]
        redis_dst_ip_list = dst_ip_list[0]
        for dst_ip in dst_ip_list[1:]:
            redis_dst_ip_list += ';' + dst_ip
        keys = ['SRC_IP', 'DST_IP_LIST', 'VRF', 'TRUNCATE_SIZE', 'UDP_DEST_PORT']
        values = [dtel_report_session.DTelReportSession.src_ip.fget(self),
                  redis_dst_ip_list,
                  'default',
                  dtel_report_session.DTelReportSession.truncate_size.fget(self),
                  dtel_report_session.DTelReportSession.udp_port.fget(self)]
        self.switch.redis_write('DTEL_REPORT_SESSION',
                                self.hashname,
                                keys,
                                values)
        self._freeze()

    def create_dtel_event(self, event_type=None, dscp_value=None):
        if event_type is None:
            raise ValueError('Need to provide event_type')
        if dscp_value is None:
            raise ValueError('Need to provide dscp_value')
        return sonic_dtel_event.SONiCDTelEvent(self, event_type, dscp_value)

    def delete(self):
        self.switch.redis_delete('DTEL_REPORT_SESSION', self.hashname)
        super(SONiCDTelReportSession, self).delete()

    @property
    def dst_ip_list(self):
        value = self.switch.redis_read('DTEL_REPORT_SESSION', self.hashname, 'DST_IP_LIST')
        value.split(';')
        dtel_report_session.DTelReportSession.dst_ip_list.fset(self, value)
        return dtel_report_session.DTelReportSession.dst_ip_list.fget(self)

    @dst_ip_list.setter
    def dst_ip_list(self, value):
        dtel_report_session.DTelReportSession.dst_ip_list.fset(self, value)
        if not isinstance(value, list):
            value = [value]
        redis_dst_ip_list = value[0]
        for dst_ip in value[1:]:
            redis_dst_ip_list += ';' + dst_ip
        self.switch.redis_write('DTEL_REPORT_SESSION', self.hashname, 'DST_IP_LIST', redis_dst_ip_list)

    @property
    def src_ip(self):
        value = self.switch.redis_read('DTEL_REPORT_SESSION', self.hashname, 'SRC_IP')
        dtel_report_session.DTelReportSession.src_ip.fset(self, value)
        return dtel_report_session.DTelReportSession.src_ip.fget(self)

    @src_ip.setter
    def src_ip(self, value):
        dtel_report_session.DTelReportSession.src_ip.fset(self, value)
        self.switch.redis_write('DTEL_REPORT_SESSION', self.hashname, 'SRC_IP', value)

    @property
    def udp_port(self):
        value = int(self.switch.redis_read('DTEL_REPORT_SESSION', self.hashname, 'UDP_DEST_PORT'))
        dtel_report_session.DTelReportSession.udp_port.fset(self, value)
        return dtel_report_session.DTelReportSession.udp_port.fget(self)

    @udp_port.setter
    def udp_port(self, value):
        dtel_report_session.DTelReportSession.udp_port.fset(self, value)
        self.switch.redis_write('DTEL_REPORT_SESSION', self.hashname, 'UDP_DEST_PORT', value)

    @property
    def truncate_size(self):
        value = int(self.switch.redis_read('DTEL_REPORT_SESSION', self.hashname, 'TRUNCATE_SIZE'))
        dtel_report_session.DTelReportSession.truncate_size.fset(self, value)
        return dtel_report_session.DTelReportSession.truncate_size.fget(self)

    @truncate_size.setter
    def truncate_size(self, value):
        dtel_report_session.DTelReportSession.truncate_size.fset(self, value)
        self.switch.redis_write('DTEL_REPORT_SESSION', self.hashname, 'TRUNCATE_SIZE', value)
