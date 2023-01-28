import pprint

class HDDThresholdExceeded(Exception):
    """Raised when HDD consumption on DUT exceed threshold"""
    def __repr__(self):
        return pprint.pformat(self.message)


class RAMThresholdExceeded(Exception):
    """Raised when RAM consumption on DUT exceed threshold"""
    def __repr__(self):
        return pprint.pformat(self.message)


class CPUThresholdExceeded(Exception):
    """Raised when CPU consumption on DUT exceed threshold"""
    def __repr__(self):
        return pprint.pformat(self.message)
