def is_broadcom_device(dut):
    return dut.facts["asic_type"] == "broadcom"
