from dtel import dtel_queue_report
from dtel.infra import *


class SONiCDTelQueueReport(dtel_queue_report.DTelQueueReport, FrozenClass):
    def __init__(self, switch=None, port=None, queue_id=None, depth_threshold=None,
                 latency_threshold=None, breach_quota=None, report_tail_drop=None):
        if switch is None:
            raise ValueError('Need to provide switch')
        if port is None:
            raise ValueError('Need to provide port')
        if queue_id is None:
            raise ValueError('Need to provide queue_id')

        super(SONiCDTelQueueReport, self).__init__(switch=switch,
                                                   port=port,
                                                   queue_id=queue_id,
                                                   depth_threshold=depth_threshold,
                                                   latency_threshold=latency_threshold,
                                                   breach_quota=breach_quota,
                                                   report_tail_drop=report_tail_drop)
        # qid = self.switch.generate_id('DTEL_QUEUE_REPORT|QueueReport')
        # self.hashname = 'QueueReport' + qid
        self.hashname = 'Ethernet' + str(self.port) + '|' + str(queue_id)
        port_str = 'PORT|Ethernet' + str(self.port)
        keys = ['PORT', 'QUEUE_ID', 'QUEUE_DEPTH_THRESHOLD',
                'QUEUE_LATENCY_THRESHOLD', 'THRESHOLD_BREACH_QUOTA', 'REPORT_TAIL_DROP']
        values = [port_str, queue_id, depth_threshold,
                  latency_threshold, breach_quota, report_tail_drop]
        self.switch.redis_write('DTEL_QUEUE_REPORT',
                                self.hashname,
                                keys,
                                values)
        self._freeze()

    def delete(self):
        self.switch.redis_delete('DTEL_QUEUE_REPORT', self.hashname)
        super(SONiCDTelQueueReport, self).delete()

    @property
    def depth_threshold(self):
        value = int(self.switch.redis_read('DTEL_QUEUE_REPORT', self.hashname, 'QUEUE_DEPTH_THRESHOLD'))
        dtel_queue_report.DTelQueueReport.depth_threshold.fset(self, value)
        return dtel_queue_report.DTelQueueReport.depth_threshold.fget(self)

    @depth_threshold.setter
    def depth_threshold(self, value):
        dtel_queue_report.DTelQueueReport.depth_threshold.fset(self, value)
        self.switch.redis_write('DTEL_QUEUE_REPORT', self.hashname, 'QUEUE_DEPTH_THRESHOLD', value)

    @property
    def latency_threshold(self):
        value = int(self.switch.redis_read('DTEL_QUEUE_REPORT', self.hashname, 'QUEUE_LATENCY_THRESHOLD'))
        dtel_queue_report.DTelQueueReport.latency_threshold.fset(self, value)
        return dtel_queue_report.DTelQueueReport.latency_threshold.fget(self)

    @latency_threshold.setter
    def latency_threshold(self, value):
        dtel_queue_report.DTelQueueReport.latency_threshold.fset(self, value)
        self.switch.redis_write('DTEL_QUEUE_REPORT', self.hashname, 'QUEUE_LATENCY_THRESHOLD', value)

    @property
    def breach_quota(self):
        value = int(self.switch.redis_read('DTEL_QUEUE_REPORT', self.hashname, 'THRESHOLD_BREACH_QUOTA'))
        dtel_queue_report.DTelQueueReport.breach_quota.fset(self, value)
        return dtel_queue_report.DTelQueueReport.breach_quota.fget(self)

    @breach_quota.setter
    def breach_quota(self, value):
        dtel_queue_report.DTelQueueReport.breach_quota.fset(self, value)
        self.switch.redis_write('DTEL_QUEUE_REPORT', self.hashname, 'THRESHOLD_BREACH_QUOTA', value)

    @property
    def report_tail_drop(self):
        value = int(self.switch.redis_read('DTEL_QUEUE_REPORT', self.hashname, 'REPORT_TAIL_DROP'))
        dtel_queue_report.DTelQueueReport.report_tail_drop.fset(self, value)
        return dtel_queue_report.DTelQueueReport.report_tail_drop.fget(self)

    @report_tail_drop.setter
    def report_tail_drop(self, value):
        dtel_queue_report.DTelQueueReport.report_tail_drop.fset(self, value)
        self.switch.redis_write('DTEL_QUEUE_REPORT', self.hashname, 'REPORT_TAIL_DROP', value)
