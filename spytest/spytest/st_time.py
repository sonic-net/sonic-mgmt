import datetime

from utilities.common import time_diff

def get_timestamp(ms=True, this=None):
    if not this:
        this = datetime.datetime.utcnow()
    if ms:
        return this.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
    else:
        return this.strftime('%Y-%m-%d %H:%M:%S')

def get_timenow():
    return datetime.datetime.utcnow()

def get_elapsed(start, fmt=False, add=0, end=None):
    end = end or get_timenow()
    return time_diff(start, end, fmt, add)

def parse(s, fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.datetime.strptime(s, fmt)

def diff(s, fmt="%Y-%m-%d %H:%M:%S"):
    return get_elapsed(parse(s, fmt))
