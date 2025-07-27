"""
IpAddressValidator - Validates IP address uniqueness between devices and testbeds.
"""

import ipaddress
from .base_validator import GlobalValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("ip_address")
class IpAddressValidator(GlobalValidator):
    """Validates that no IP address conflicts exist between devices and testbeds"""

    def __init__(self, config=None):
        super().__init__(
            name="ip_address",
            description="Validates that no IP address conflicts exist between devices and testbeds",
            category="networking"
        )
        self.config = config or {}

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate that IP addresses are unique across devices and testbeds using global context

        Args:
            context: ValidatorContext containing testbed and connection graph data
        """
        testbed_info = context.get_testbeds()

        # Collect all IP addresses from all groups
        ip_addresses = self._collect_all_ip_addresses_globally(context, testbed_info)

        # Validate IP addresses
        self._validate_collected_ip_addresses(ip_addresses)

        # Add metadata (handle both old and new format)
        if ip_addresses and len(list(ip_addresses.values())[0]) == 4:
            # New format with group info: (source_type, source_name, ip_type, group_name)
            self.result.metadata.update({
                "total_ips": len(ip_addresses),
                "device_ips": len([ip for ip, info in ip_addresses.items() if info[0] == "device"]),
                "testbed_ips": len([ip for ip, info in ip_addresses.items() if info[0] == "testbed"]),
                "ipv4_count": len([ip for ip, info in ip_addresses.items() if info[2] == "ipv4"]),
                "ipv6_count": len([ip for ip, info in ip_addresses.items() if info[2] == "ipv6"]),
                "groups_with_devices": len(set([info[3] for ip, info in ip_addresses.items() if info[0] == "device"]))
            })
        else:
            # Old format: (source_type, source_name, ip_type)
            self.result.metadata.update({
                "total_ips": len(ip_addresses),
                "device_ips": len([ip for ip, info in ip_addresses.items() if info[0] == "device"]),
                "testbed_ips": len([ip for ip, info in ip_addresses.items() if info[0] == "testbed"]),
                "ipv4_count": len([ip for ip, info in ip_addresses.items() if info[2] == "ipv4"]),
                "ipv6_count": len([ip for ip, info in ip_addresses.items() if info[2] == "ipv6"])
            })

        if self.result.success and ip_addresses:
            self.logger.info(
                f"IP address validation summary: {len(ip_addresses)} unique IP addresses validated across all groups"
            )

    def _collect_all_ip_addresses_globally(self, context: ValidatorContext, testbed_info):
        """
        Collect all IP addresses from all groups in the global context

        Args:
            context: ValidatorContext with global data
            testbed_info: Testbed information

        Returns:
            dict: Dictionary mapping IP addresses to their source information
        """
        ip_addresses = {}  # ip -> (source_type, source_name, ip_type, group_name)

        # Collect device management IPs from all connection graphs
        all_conn_graphs = context.get_all_connection_graphs()
        for group_name, conn_graph in all_conn_graphs.items():
            self._collect_device_ips_with_group(conn_graph, group_name, ip_addresses)

        # Collect testbed PTF IPs (these are shared across groups)
        self._collect_testbed_ips_with_group(testbed_info, ip_addresses)

        return ip_addresses

    def _collect_device_ips_with_group(self, conn_graph, group_name, ip_addresses):
        """Collect device management IPs from connection graph with group information"""
        if not conn_graph or 'devices' not in conn_graph:
            return

        for device_name, device_info in conn_graph['devices'].items():
            if not isinstance(device_info, dict):
                continue

            mgmt_ip = device_info.get('ManagementIp')
            if mgmt_ip:
                ip_addr, ip_type = self._extract_ip_address(mgmt_ip)
                if ip_addr:
                    self._add_ip_address_with_group(
                        ip_addr, "device", device_name, ip_type, group_name,
                        ip_addresses
                    )

    def _collect_testbed_ips_with_group(self, testbed_info, ip_addresses):
        """Collect testbed PTF IPs with group information"""
        if not testbed_info:
            return

        for testbed in testbed_info:
            if not isinstance(testbed, dict):
                continue

            testbed_name = testbed.get('conf-name', 'unknown')

            if 'ixia' in testbed['topo'] or 'tgen' in testbed['topo'] or 'nut' in testbed['topo']:
                # Skip testbeds with Ixia/Tgen/NUT as their PTF IPs can be shared
                continue

            # Check PTF IPv4 address
            ptf_ip = testbed.get('ptf_ip')
            if ptf_ip:
                ip_addr, ip_type = self._extract_ip_address(ptf_ip)
                if ip_addr:
                    self._add_ip_address_with_group(
                        ip_addr, "testbed", f"{testbed_name}:ptf_ip", ip_type, "testbed",
                        ip_addresses
                    )

            # Check PTF IPv6 address
            ptf_ipv6 = testbed.get('ptf_ipv6')
            if ptf_ipv6:
                ip_addr, ip_type = self._extract_ip_address(ptf_ipv6)
                if ip_addr:
                    self._add_ip_address_with_group(
                        ip_addr, "testbed", f"{testbed_name}:ptf_ipv6", ip_type, "testbed",
                        ip_addresses
                    )

    def _add_ip_address_with_group(self, ip_addr, source_type, source_name, ip_type, group_name, ip_addresses):
        """Add IP address to tracking dict with group information and check for conflicts"""
        if ip_addr in ip_addresses:
            existing_source = ip_addresses[ip_addr]
            existing_source_type, existing_source_name, existing_ip_type, existing_group_name = existing_source

            # Check if this is the same device appearing in multiple groups (shared device)
            if (source_type == "device" and existing_source_type == "device" and
                    source_name == existing_source_name and group_name != existing_group_name):
                # This is a shared device across groups - not a conflict
                self.logger.debug(
                    f"Shared device detected: {source_name} appears in groups {existing_group_name} and {group_name}"
                )
                return

            # This is a real IP conflict
            self.result.add_issue(
                'E2001',
                {
                    "ip_address": ip_addr,
                    "source1_type": existing_source_type,
                    "source1_name": existing_source_name,
                    "source1_group": existing_group_name,
                    "source2_type": source_type,
                    "source2_name": source_name,
                    "source2_group": group_name
                }
            )
        else:
            ip_addresses[ip_addr] = (source_type, source_name, ip_type, group_name)

    def _collect_all_ip_addresses(self, conn_graph, testbed_info):
        """
        Collect all IP addresses from devices and testbeds

        Args:
            conn_graph: Connection graph data
            testbed_info: Testbed information

        Returns:
            dict: Dictionary mapping IP addresses to their source information
        """
        ip_addresses = {}  # ip -> (source_type, source_name, ip_type)

        # Collect device management IPs from connection graph
        self._collect_device_ips(conn_graph, ip_addresses)

        # Collect testbed PTF IPs
        self._collect_testbed_ips(testbed_info, ip_addresses)

        return ip_addresses

    def _validate_collected_ip_addresses(self, ip_addresses):
        """
        Validate properties of collected IP addresses

        Args:
            ip_addresses: Dictionary of IP addresses and their source information
        """
        self._validate_ip_addresses(ip_addresses)

    def _collect_device_ips(self, conn_graph, ip_addresses):
        """Collect device management IPs from connection graph"""
        if not conn_graph or 'devices' not in conn_graph:
            return

        for device_name, device_info in conn_graph['devices'].items():
            if not isinstance(device_info, dict):
                continue

            mgmt_ip = device_info.get('ManagementIp')
            if mgmt_ip:
                ip_addr, ip_type = self._extract_ip_address(mgmt_ip)
                if ip_addr:
                    self._add_ip_address(
                        ip_addr, "device", device_name, ip_type,
                        ip_addresses
                    )

    def _collect_testbed_ips(self, testbed_info, ip_addresses):
        """Collect testbed PTF IPs"""
        if not testbed_info:
            return

        for testbed in testbed_info:
            if not isinstance(testbed, dict):
                continue

            testbed_name = testbed.get('conf-name', 'unknown')

            if 'ixia' in testbed['topo'] or 'tgen' in testbed['topo'] or 'nut' in testbed['topo']:
                # Skip testbeds with Ixia/Tgen/NUT as their PTF IPs can be shared
                continue

            # Check PTF IPv4 address
            ptf_ip = testbed.get('ptf_ip')
            if ptf_ip:
                ip_addr, ip_type = self._extract_ip_address(ptf_ip)
                if ip_addr:
                    self._add_ip_address(
                        ip_addr, "testbed", f"{testbed_name}:ptf_ip", ip_type,
                        ip_addresses
                    )

            # Check PTF IPv6 address
            ptf_ipv6 = testbed.get('ptf_ipv6')
            if ptf_ipv6:
                ip_addr, ip_type = self._extract_ip_address(ptf_ipv6)
                if ip_addr:
                    self._add_ip_address(
                        ip_addr, "testbed", f"{testbed_name}:ptf_ipv6", ip_type,
                        ip_addresses
                    )

    def _add_ip_address(self, ip_addr, source_type, source_name, ip_type, ip_addresses):
        """Add IP address to tracking dict and check for conflicts"""
        if ip_addr in ip_addresses:
            existing_source = ip_addresses[ip_addr]
            self.result.add_issue(
                'E2001',
                {
                    "ip_address": ip_addr,
                    "source1_type": existing_source[0],
                    "source1_name": existing_source[1],
                    "source2_type": source_type,
                    "source2_name": source_name
                }
            )
        else:
            ip_addresses[ip_addr] = (source_type, source_name, ip_type)

    def _validate_ip_addresses(self, ip_addresses):
        """Validate IP address properties"""
        for ip_addr, info in ip_addresses.items():
            try:
                # Handle both old format (3-tuple) and new format (4-tuple)
                if len(info) == 4:
                    source_type, source_name, ip_type, group_name = info
                else:
                    source_type, source_name, ip_type = info
                    group_name = "unknown"

                ip_obj = ipaddress.ip_address(ip_addr)

                # Check for reserved addresses
                if ip_obj.is_reserved:
                    self.result.add_issue(
                        'E2002',
                        {
                            "ip_address": ip_addr,
                            "source_type": source_type,
                            "source_name": source_name,
                            "group": group_name
                        }
                    )

                # Check for loopback addresses
                if ip_obj.is_loopback:
                    self.result.add_issue(
                        'E2002',
                        {
                            "ip_address": ip_addr,
                            "source_type": source_type,
                            "source_name": source_name,
                            "group": group_name
                        }
                    )

            except ValueError:
                # This should not happen as we validate during extraction
                self.result.add_issue(
                    'E2003',
                    {
                        "ip_address": ip_addr,
                        "source_type": source_type,
                        "source_name": source_name,
                        "group": group_name
                    }
                )

    def _extract_ip_address(self, ip_string):
        """
        Extract IP address from string, handling CIDR notation

        Args:
            ip_string: IP address string (may include CIDR notation)

        Returns:
            tuple: (IP address without CIDR notation, ip_type) or (None, None) if invalid
        """
        if not ip_string:
            return None, None

        try:
            # Handle CIDR notation
            if '/' in ip_string:
                ip_string = ip_string.split('/')[0]

            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_string.strip())
            ip_type = "ipv6" if ip_obj.version == 6 else "ipv4"
            return str(ip_obj), ip_type

        except (ValueError, AttributeError):
            return None, None
