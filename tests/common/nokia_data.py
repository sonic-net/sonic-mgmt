def is_nokia_device(dut):
    return ('nokia' in dut.facts["hwsku"].lower())


NO_QOS_HWSKUS = ['Nokia-7215-C1', 'Nokia-IXR7220-H6-O256']
