def is_nokia_device(dut):
    return ('nokia' in dut.facts["hwsku"].lower())
