import json
import argparse

def generate_kea_dhcp4_config(vlan_interface, start_subnet, end_subnet,
                              second_octet_base=160, third_octet_base=21):
    """
    Generates a Kea DHCPv4 config with dynamically calculated subnets.

    Subnet calculation supports rollover:
    Example:
        start_subnet=21, end_subnet=300
        192.160.21.x → 192.161.65.x  (automatically increments 2nd octet)
    """

    config = {
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": [vlan_interface]
            },
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket"
            },
            "lease-database": {
                "type": "memfile",
                "persist": True,
                "name": "/tmp/kea-lease.csv",
                "lfc-interval": 3600
            },
            "subnet4": [],
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output_options": [
                        {
                            "output": "/tmp/kea-dhcp.log",
                            "pattern": "%-5p %m\n"
                        }
                    ],
                    "severity": "INFO",
                    "debuglevel": 0
                }
            ]
        }
    }

    # Calculate subnets dynamically
    for offset, vlan_id in enumerate(range(start_subnet, end_subnet + 1)):

        # rollover logic same as your relay code
        third_octet = (third_octet_base + offset) % 256
        second_octet = second_octet_base + ((third_octet_base + offset) // 256)

        subnet_ip = f"192.{second_octet}.{third_octet}.0/24"
        pool_start = f"192.{second_octet}.{third_octet}.60"
        pool_end   = f"192.{second_octet}.{third_octet}.69"
        router_ip  = f"192.{second_octet}.{third_octet}.1"

        entry = {
            "subnet": subnet_ip,
            "pools": [
                { "pool": f"{pool_start} - {pool_end}" }
            ],
            "option-data": [
                { "name": "routers", "data": router_ip },
                { "name": "dhcp-server-identifier", "data": "192.160.20.100" },
                { "name": "domain-name-servers", "data": "8.8.8.8, 8.8.4.4" },
                { "name": "domain-name", "data": "yourdomain.local" }
            ],
            "valid-lifetime": 3600
        }

        config["Dhcp4"]["subnet4"].append(entry)

    return config


def main():
    parser = argparse.ArgumentParser(description="Generate KEA DHCP4 config")
    parser.add_argument("--iface", required=True, help="Interface name (ex: Vlan20)")
    parser.add_argument("--start", type=int, required=True, help="Start subnet/VLAN")
    parser.add_argument("--end", type=int, required=True, help="End subnet/VLAN")
    parser.add_argument("--outfile", default="kea-dhcp4.conf", help="Output file")

    args = parser.parse_args()

    config_data = generate_kea_dhcp4_config(
        vlan_interface=args.iface,
        start_subnet=args.start,
        end_subnet=args.end
    )

    with open(args.outfile, "w") as f:
        json.dump(config_data, f, indent=4)

    print(f"Generated {args.outfile} successfully!")


if __name__ == "__main__":
    main()
