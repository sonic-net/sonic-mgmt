import argparse
import csv
import json
from typing import Dict, List, Tuple
import os


def get_abs_path(filename):
    csv_dir = os.environ.get("PYTHONPATH", "")
    return os.path.join(csv_dir, filename)


def read_csv(file_path: str) -> List[Dict[str, str]]:
    """
    Reads a CSV file and returns a list of dictionaries representing the rows.
    """
    with open(get_abs_path(file_path), mode="r") as file:
        reader = csv.DictReader(file)
        return [row for row in reader]


def build_switch_to_l1_mapping(
    switch_l1_config_data: List[Dict[str, str]],
) -> Dict[Tuple[str, str], str]:
    """
    Creates a mapping from (switch, switch port) to L1 switch port.
    """
    mapping = {}
    for row in switch_l1_config_data:
        switch = row["StartDevice"]
        switch_port = row["StartPort"]
        l1_port = row["EndPort"]
        mapping[(switch, switch_port)] = l1_port
    return mapping


def build_traffic_gen_to_l1_mapping(
    tgen_l1_config_data: List[Dict[str, str]],
) -> Dict[Tuple[str, str], List[str]]:
    """
    Creates a mapping from (traffic generator, generator port) to L1 switch port.
    """
    mapping = {}
    for row in tgen_l1_config_data:
        traffic_gen = row["StartDevice"]
        traffic_gen_port = row["StartPort"]
        l1_port = row["EndPort"]
        if (traffic_gen, traffic_gen_port) not in mapping:
            mapping[(traffic_gen, traffic_gen_port)] = []
        mapping[(traffic_gen, traffic_gen_port)].append(l1_port)
    return mapping


def generate_l1_port_connections(
    switch_tgen_config_data: List[Dict[str, str]],
    switch_to_l1: Dict[Tuple[str, str], str],
    traffic_gen_to_l1: Dict[Tuple[str, str], List[str]],
    tgen_l1_config_data: List[Dict[str, str]],
    switch_name: str,
    num_ports: int,
) -> Dict[str, str]:
    """
    Generates the final mapping of L1 switch ports to be connected.
    """
    l1_connections = {"l1_switches": set(), "ports_to_connect": {}}
    for row in switch_tgen_config_data:
        if row["StartDevice"] != switch_name:
            continue
        if num_ports and len(l1_connections["ports_to_connect"]) >= num_ports:
            break
        switch = row["StartDevice"]
        switch_port = row["StartPort"]
        traffic_gen = row["EndDevice"]
        traffic_gen_port = row["EndPort"]

        l1_port_switch = switch_to_l1.get((switch, switch_port))
        l1_ports_traffic_gen = traffic_gen_to_l1.get(
            (traffic_gen, traffic_gen_port), []
        )

        if l1_port_switch and l1_ports_traffic_gen:
            for l1_row in tgen_l1_config_data:
                if (
                    l1_row["StartDevice"] == traffic_gen
                    and l1_row["StartPort"] == traffic_gen_port
                ):
                    l1_connections["l1_switches"].add(l1_row["EndDevice"])
            l1_connections["ports_to_connect"][l1_port_switch] = l1_ports_traffic_gen[
                -1
            ]

    return l1_connections


def runner(
    switch_name: str,
    num_ports: int,
    switch_tgen_config: str,
    switch_l1_config: str,
    tgen_l1_config: str,
) -> None:
    """
    Main function to read config files and generate L1 switch port connections.
    """
    switch_tgen_config_data = read_csv(switch_tgen_config)
    switch_l1_config_data = read_csv(switch_l1_config)
    tgen_l1_config_data = read_csv(tgen_l1_config)

    switch_to_l1 = build_switch_to_l1_mapping(switch_l1_config_data)
    traffic_gen_to_l1 = build_traffic_gen_to_l1_mapping(tgen_l1_config_data)

    l1_connections = generate_l1_port_connections(
        switch_tgen_config_data,
        switch_to_l1,
        traffic_gen_to_l1,
        tgen_l1_config_data,
        switch_name,
        num_ports,
    )

    l1_connections["l1_switches"] = list(l1_connections["l1_switches"])
    if len(l1_connections["ports_to_connect"]) < num_ports:
        raise ValueError(
            f"Requested {num_ports} ports, but only {len(l1_connections['ports_to_connect'])} were found."
        )
    print(json.dumps(l1_connections, indent=4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate L1 switch port connections based on configurations."
    )
    parser.add_argument(
        "switch_name",
        type=str,
        help="Name of the switch to connect to the traffic generator",
    )
    parser.add_argument("num_ports", type=int, help="Number of ports to connect")

    args = parser.parse_args()

    runner(
        switch_name=args.switch_name,
        num_ports=args.num_ports,
        switch_tgen_config="sonic_tgen_links.csv",
        switch_l1_config="sonic_l1_to_dut_links.csv",
        tgen_l1_config="sonic_l1_to_tgen_links.csv",
    )
