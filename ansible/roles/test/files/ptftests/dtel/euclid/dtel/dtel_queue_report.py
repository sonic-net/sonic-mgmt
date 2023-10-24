from infra import *


class DTelQueueReport(object):
    def __init__(self, switch=None, port=None, queue_id=None, depth_threshold=None,
                 latency_threshold=None, breach_quota=None, report_tail_drop=None):
        if switch is None:
            raise ValueError('Need to provide switch')
        if port is None:
            raise ValueError('Need to provide port')
        if queue_id is None:
            raise ValueError('Need to provide queue_id')

        # Attributes
        self.switch = switch
        self._port = None
        self._queue_id = None
        self._depth_threshold = None
        self._latency_threshold = None
        self._breach_quota = None
        self._report_tail_drop = None
        # Properties
        DTelQueueReport.port.fset(self, port)
        DTelQueueReport.queue_id.fset(self, queue_id)
        DTelQueueReport.depth_threshold.fset(self, depth_threshold)
        DTelQueueReport.latency_threshold.fset(self, latency_threshold)
        DTelQueueReport.breach_quota.fset(self, breach_quota)
        DTelQueueReport.report_tail_drop.fset(self, report_tail_drop)
        # Append
        self.switch.dtel_queue_reports.append(self)

    def delete(self):
        self.switch.dtel_queue_reports.remove(self)

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        if self._port is None:
            self._port = fpport_to_swport(value)
        else:
            raise ValueError("Changing the port of a queue report is not allowed")

    @property
    def queue_id(self):
        return self._queue_id

    @queue_id.setter
    def queue_id(self, value):
        if self._queue_id is None:
            if value < 0 or value > 7:
                raise ValueError('queue_id must be a integer between 0 and 7')
            self._queue_id = value
        else:
            raise ValueError('Changing the queue_id of a queue report is not allowed')

    @property
    def depth_threshold(self):
        return self._depth_threshold

    @depth_threshold.setter
    def depth_threshold(self, value):
        if value < 0 or value >= 2**32:
            raise ValueError('depth_threshold must be a uint32')
        self._depth_threshold = value

    @property
    def latency_threshold(self):
        return self._latency_threshold

    @latency_threshold.setter
    def latency_threshold(self, value):
        if value < 0 or value >= 2**32:
            raise ValueError('latency_threshold must be a uint32')
        self._latency_threshold = value

    @property
    def breach_quota(self):
        return self._breach_quota

    @breach_quota.setter
    def breach_quota(self, value):
        if value < 0 or value >= 2**32:
            raise ValueError('breach_quota must be a uint32')
        self._breach_quota = value

    @property
    def report_tail_drop(self):
        return self._report_tail_drop

    @report_tail_drop.setter
    def report_tail_drop(self, value):
        if not isinstance(value, bool):
            raise TypeError('report_tail_drop must be a boolean')
        self._report_tail_drop = value
