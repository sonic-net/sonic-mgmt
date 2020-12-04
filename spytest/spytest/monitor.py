from spytest.framework import get_work_area as getwa

def start(dut, name, **kwargs):
    largs = [name]
    for k,v in kwargs.items():
        largs.extend([k,v])
    return getwa().net._apply_remote(dut, "service-start", largs)

def stop(dut, name):
    return getwa().net._apply_remote(dut, "service-stop", [name])

def get(dut, name):
    return getwa().net._apply_remote(dut, "service-get", [name])

