def is_marvell_prestera_device(dut):
    return dut.facts["asic_type"] == "marvell-prestera"


NO_QOS_HWSKUS = ['Nokia-7215', 'Nokia-M0-7215',
                 'Nokia-7215-A1-G48S4', 'Nokia-7215-A1-MGX-G48S4']
