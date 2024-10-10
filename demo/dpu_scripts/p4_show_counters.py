import time
import p4runtime_sh.shell as p4sh
import logging
from p4_utils import init_p4runtime_shell
from tabulate import tabulate


eni_id = 0


class CounterDef:
    def __init__(self, id: str, name: str, category: str = "Traffic", type: str = "packet"):
        self.id = id
        self.name = name
        self.category = category
        self.type = type

    def read(self):
        logging.debug(f"Reading counter {self.id}")
        return p4sh.CounterEntry(self.id).read()


eni_counter_defs = [
    CounterDef("eni_rx", "RX"),
    CounterDef("eni_tx", "TX"),
    CounterDef("eni_outbound_rx", "OUT_RX"),
    CounterDef("eni_outbound_tx", "OUT_TX"),
    CounterDef("eni_inbound_rx", "IN_RX"),
    CounterDef("eni_inbound_tx", "IN_TX"),
    CounterDef("eni_miss_drop", "ENI_MISS"),
    CounterDef("outbound_routing_group_disabled_drop", "ROUTE_TABLE_DISABLED"),
    CounterDef("outbound_routing_group_miss_drop", "ROUTE_TABLE_MISS"),
    CounterDef("outbound_routing_entry_miss_drop", "ROUTE_MISS"),
    CounterDef("outbound_ca_pa_entry_miss_drop", "MAP_MISS"),
]


def dump_counters(eni_id: int):
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

    return eni_counters


def output_counters(eni_counters):
    for category, counters in eni_counters.items():
        table = tabulate(counters["rows"], headers=counters["headers"], tablefmt="fancy_grid")

        print(f"{category} counters:")
        print(table)
        print("")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # p4sh.global_options["verbose"] = False

    init_p4runtime_shell()

    while True:
        eni_counters = dump_counters(eni_id)
        output_counters(eni_counters)
        time.sleep(1)
