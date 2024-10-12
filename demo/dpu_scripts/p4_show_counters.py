import time
import p4runtime_sh.shell as p4sh
import logging
from p4_utils import init_p4runtime_shell
from tabulate import tabulate


eni_id = 0


class CounterDef:
    def __init__(self, id: str, name: str, category: str = "", type: str = "packet"):
        self.id = id
        self.name = name
        self.category = category
        self.type = type

    def read(self):
        logging.debug(f"Reading counter {self.id}")
        return p4sh.CounterEntry(self.id).read()


global_counter_defs = [
    CounterDef("port_rx", "RX"),
    CounterDef("port_rx_discards", "RX_DROP"),
    CounterDef("port_rx_errors", "RX_ERR"),
    CounterDef("port_tx", "TX"),
    CounterDef("vip_miss_drop", "VIP_MISS"),
    CounterDef("eni_miss_drop", "ENI_MISS"),
]

eni_counter_defs = [
    CounterDef("eni_rx", "RX", "Overall"),
    CounterDef("eni_outbound_rx", "OUT_RX", "Overall"),
    CounterDef("eni_inbound_rx", "IN_RX", "Overall"),
    CounterDef("eni_tx", "TX", "Overall"),
    CounterDef("eni_outbound_tx", "OUT_TX", "Overall"),
    CounterDef("eni_inbound_tx", "IN_TX", "Overall"),
    CounterDef("outbound_routing_group_disabled_drop", "ROUTE_TABLE_DISABLED", "Outbound"),
    CounterDef("outbound_routing_group_miss_drop", "ROUTE_TABLE_MISS", "Outbound"),
    CounterDef("outbound_routing_entry_miss_drop", "ROUTE_MISS", "Outbound"),
    CounterDef("outbound_ca_pa_entry_miss_drop", "MAP_MISS", "Outbound"),
]


def dump_global_counters():
    global_counters = {
        "headers": [],
        "rows": [[]],
    }

    for counter_def in global_counter_defs:
        c = counter_def.read()

        global_counters["headers"].append(counter_def.name)

        for _, cv in enumerate(c):
            if counter_def.type == "packet":
                global_counters["rows"][0].append(cv.packet_count)
            elif counter_def.type == "byte":
                global_counters["rows"][0].append(cv.byte_count)

    output_table(global_counters, "Global")


def dump_eni_counters(eni_id: int):
    eni_counters = {}

    for counter_def in eni_counter_defs:
        c = counter_def.read()

        if counter_def.category not in eni_counters:
            eni_counters[counter_def.category] = {
                "headers": ["ENI"],
                "rows": [[str(eni_id)]],
            }

        eni_counters[counter_def.category]["headers"].append(counter_def.name)

        for index, cv in enumerate(c):
            if index != eni_id:
                continue

            if counter_def.type == "packet":
                eni_counters[counter_def.category]["rows"][0].append(cv.packet_count)
            elif counter_def.type == "byte":
                eni_counters[counter_def.category]["rows"][0].append(cv.byte_count)

    for category, counters in eni_counters.items():
        output_table(counters, category)


def output_table(counters, category):
    table = tabulate(counters["rows"], headers=counters["headers"], tablefmt="simple_grid")
    print(f"{category} counters:")
    print(table)
    print("")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # p4sh.global_options["verbose"] = False

    init_p4runtime_shell()

    while True:
        print("===== Current Time: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + " =====")
        print("")

        dump_global_counters()
        dump_eni_counters(eni_id)
        time.sleep(1)
