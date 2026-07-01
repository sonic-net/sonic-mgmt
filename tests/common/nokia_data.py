def is_nokia_device(dut):
    return ('nokia' in dut.facts["hwsku"].lower())


NO_QOS_HWSKUS = ['Nokia-7215-C1']
