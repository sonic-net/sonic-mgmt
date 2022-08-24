def is_innovium_device(dut):
    return dut.facts["asic_type"] == "innovium"
