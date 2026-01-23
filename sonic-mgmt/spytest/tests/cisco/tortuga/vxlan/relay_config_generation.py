import json
import argparse

def generate_vlan_config_specific(scale, client_interface, relay, relay_interface):
    config = {
        "VLAN": {},
        "VLAN_INTERFACE": {},
        "VLAN_MEMBER": {}
    }

    # -------------------------------------------------------
    # VLAN 20 (only in relay mode)
    # -------------------------------------------------------
    if relay:
        vlan_id_20 = 20
        vlan_name_20 = f"Vlan{vlan_id_20}"

        # VLAN entry
        config["VLAN"][vlan_name_20] = {
            "vlanid": str(vlan_id_20)
        }

        # VLAN_INTERFACE
        config["VLAN_INTERFACE"][vlan_name_20] = {}
        config["VLAN_INTERFACE"][f"{vlan_name_20}|192.160.20.1/24"] = {}

        # VLAN_MEMBER (relay interface)
        config["VLAN_MEMBER"][f"{vlan_name_20}|{relay_interface}"] = {
            "tagging_mode": "tagged"
        }

    # -------------------------------------------------------
    # VLAN 21 → VLAN(20 + scale)
    # -------------------------------------------------------
    start_vlan = 21
    end_vlan = 20 + scale
    dhcp_server_ip = "192.160.20.100"

    third_octet_base = 21
    second_octet_base = 160

    for vlan_id in range(start_vlan, end_vlan + 1):
        vlan_name = f"Vlan{vlan_id}"
        offset = vlan_id - start_vlan

        # IP for relay mode
        if relay:
            third_octet = (third_octet_base + offset) % 256
            second_octet = second_octet_base + ((third_octet_base + offset) // 256)
            ip_addr = f"192.{second_octet}.{third_octet}.1/24"

        # VLAN section
        if relay:
            config["VLAN"][vlan_name] = {
                "dhcp_servers": [dhcp_server_ip],
                "vlanid": str(vlan_id)
            }
        else:
            config["VLAN"][vlan_name] = {
                "vlanid": str(vlan_id)
            }

        # VLAN_INTERFACE only in relay
        if relay:
            config["VLAN_INTERFACE"][vlan_name] = {}
            config["VLAN_INTERFACE"][f"{vlan_name}|{ip_addr}"] = {}

        # VLAN_MEMBER (always uses client_interface)
        config["VLAN_MEMBER"][f"{vlan_name}|{client_interface}"] = {
            "tagging_mode": "tagged"
        }

    # Remove VLAN_INTERFACE if relay disabled
    if not relay:
        config.pop("VLAN_INTERFACE", None)

    return config


# ---------------- ARGPARSE ---------------- #

def main():
    parser = argparse.ArgumentParser(description="Generate VLAN relay config")

    parser.add_argument(
        "--dhcp-relay-scale",
        required=True,
        type=int,
        help="Number of VLANs after VLAN20"
    )

    parser.add_argument(
        "--relay-client-interface",
        required=True,
        type=str,
        help="Client interface for VLAN21+ (eg: Ethernet1_3)"
    )

    parser.add_argument(
        "--relay",
        action="store_true",
        help="Enable DHCP relay mode"
    )

    parser.add_argument(
        "--relay-server-interface",
        type=str,
        help="Relay interface (required only if --relay is set)"
    )

    args = parser.parse_args()

    # Validation
    if args.relay and not args.relay_server_interface:
        parser.error("--relay-server-interface is required when --relay is used")

    print("Generating VLAN config:")
    print(f"  scale               = {args.dhcp_relay_scale}")
    print(f"  client_interface    = {args.relay_client_interface}")
    print(f"  relay_enabled       = {args.relay}")
    print(f"  relay_interface     = {args.relay_server_interface}")

    # Generate config
    config = generate_vlan_config_specific(
        args.dhcp_relay_scale,
        args.relay_client_interface,
        args.relay,
        args.relay_server_interface
    )

    with open("vlan_config_specific.json", "w") as f:
        json.dump(config, f, indent=4)

    print("Config generated → vlan_config_specific.json")


if __name__ == "__main__":
    main()

