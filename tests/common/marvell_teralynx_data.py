def is_marvell_teralynx_device(dut):
    return dut.facts["asic_type"] == "marvell-teralynx"
