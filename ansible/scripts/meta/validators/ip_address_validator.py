"""
IpAddressValidator - Validates IP address uniqueness between devices and testbeds.
"""

import ipaddress
import re
from .base_validator import GlobalValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("ip_address")
class IpAddressValidator(GlobalValidator):
    """Validates that no IP address conflicts exist between devices and testbeds"""

    def __init__(self, config=None):
        super().__init__(
            name="ip_address",
            description="Validates that no IP address conflicts exist between devices and testbeds",
            category="networking",
            config=config
        )
        # Configuration for allowing specific IP conflicts
        self.allow_conflict_list = self.config.get('allow_conflict_list', [])
        # Configuration for excluding devices from validation
        self.exclude_devices = self.config.get('exclude_devices', [])
        self._compile_conflict_patterns()
        self._compile_exclude_patterns()

    def _compile_conflict_patterns(self):
        """
        Compile regex patterns for allow_conflict_list
        """
        self.compiled_conflict_patterns = []
        for conflict_rule in self.allow_conflict_list:
            if not isinstance(conflict_rule, dict) or 'from' not in conflict_rule or 'to' not in conflict_rule:
                self.logger.warning(f"Invalid allow_conflict_list rule: {conflict_rule}."
                                    f"Must have 'from' and 'to' fields")
                continue
            try:
                compiled_pattern = re.compile(conflict_rule['from'])
                self.compiled_conflict_patterns.append({
                    'pattern': compiled_pattern,
                    'from': conflict_rule['from'],
                    'to': conflict_rule['to']
                })
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern '{conflict_rule['from']}' in allow_conflict_list: {e}")

    def _compile_exclude_patterns(self):
        """
        Compile regex patterns for exclude_devices
        """
        self.compiled_exclude_patterns = []
        for pattern in self.exclude_devices:
            try:
                compiled_pattern = re.compile(pattern)
                self.compiled_exclude_patterns.append(compiled_pattern)
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern '{pattern}' in exclude_devices: {e}")

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate that IP addresses are unique across devices and testbeds using global context

        Args:
            context: ValidatorContext containing testbed and connection graph data
        """
        testbed_info = context.get_testbeds()

        # Collect all IP addresses from all groups
        ip_addresses, device_ips = self._collect_all_ip_addresses_globally(context, testbed_info)

        # Validate IP addresses
        self._validate_collected_ip_addresses(ip_addresses, device_ips)

        # Add metadata (handle both old and new format)
        if ip_addresses and len(list(ip_addresses.values())[0]) == 4:
            # New format with group info: (source_type, source_name, ip_type, group_name)
            self.result.metadata.update({
                "total_ips": len(ip_addresses),
                "device_ips": len([
                    ip for ip, info in ip_addresses.items() if info[0] == "device"
                ]),
                "ansible_inventory_ips": len([
                    ip for ip, info in ip_addresses.items() if info[0] == "ansible_inventory"
                ]),
                "testbed_ips": len([
                    ip for ip, info in ip_addresses.items() if info[0] == "testbed"
                ]),
                "ipv4_count": len([
                    ip for ip, info in ip_addresses.items() if info[2] == "ipv4"
                ]),
                "ipv6_count": len([
                    ip for ip, info in ip_addresses.items() if info[2] == "ipv6"
                ]),
                "groups_with_devices": len(set([
                    info[3] for ip, info in ip_addresses.items()
                    if info[0] in ["device", "ansible_inventory"]
                ]))
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
        device_ips = {}  # device_name -> {group_name -> {source_type -> {ip_type -> ip_addr}}}

        # Collect device management IPs from all connection graphs
        all_conn_graphs = context.get_all_connection_graphs()
        for group_name, conn_graph in all_conn_graphs.items():
            self._collect_device_ips_with_group(conn_graph, group_name, ip_addresses, device_ips)

        # Collect ansible inventory IPs from all groups
        all_groups_data = context.get_all_groups_data()
        for group_name, group_data in all_groups_data.items():
            inventory_devices = group_data.get('inventory_devices', {})
            if inventory_devices:
                self._collect_inventory_device_ips_with_group(
                    inventory_devices, group_name, ip_addresses, device_ips
                )

        # Collect testbed PTF IPs (these are shared across groups)
        self._collect_testbed_ips_with_group(testbed_info, ip_addresses)

        return ip_addresses, device_ips

    def _collect_device_ips_with_group(self, conn_graph, group_name, ip_addresses, device_ips):
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
                    # Track device IPs for consistency checking
                    self._track_device_ip(device_name, group_name, "device", ip_type, ip_addr, device_ips)

    def _collect_inventory_device_ips_with_group(self, inventory_devices, group_name, ip_addresses, device_ips):
        """Collect device IPs from ansible inventory with group information"""
        if not inventory_devices:
            return

        for device_name, device_info in inventory_devices.items():
            if not isinstance(device_info, dict):
                continue

            # Collect IPv4 addresses
            # ansible_host (IPv4)
            ansible_host = device_info.get('ansible_host')
            if ansible_host:
                ip_addr, ip_type = self._extract_ip_address(str(ansible_host))
                if ip_addr:
                    self._add_ip_address_with_group(
                        ip_addr, "ansible_inventory", f"{device_name}:ansible_host", ip_type, group_name,
                        ip_addresses
                    )
                    # Track device IPs for consistency checking
                    self._track_device_ip(
                        device_name, group_name, "ansible_inventory", ip_type, ip_addr, device_ips
                    )

            # Collect IPv6 addresses
            # ansible_hostv6 (IPv6)
            ansible_hostv6 = device_info.get('ansible_hostv6')
            if ansible_hostv6:
                ip_addr, ip_type = self._extract_ip_address(str(ansible_hostv6))
                if ip_addr:
                    self._add_ip_address_with_group(
                        ip_addr, "ansible_inventory", f"{device_name}:ansible_hostv6", ip_type, group_name,
                        ip_addresses
                    )
                    # Track device IPs for consistency checking
                    self._track_device_ip(
                        device_name, group_name, "ansible_inventory", ip_type, ip_addr, device_ips
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

    def _add_ip_address_with_group(
        self, ip_addr, source_type, source_name, ip_type, group_name, ip_addresses
    ):
        """Add IP address to tracking dict with group information and check for conflicts"""
        # Skip excluded devices
        if self._should_exclude_device(source_name):
            return

        if ip_addr in ip_addresses:
            existing_source = ip_addresses[ip_addr]
            (existing_source_type, existing_source_name,
             existing_ip_type, existing_group_name) = existing_source

            # Check if this is the same device appearing in multiple sources (shared device)
            if (source_type == "device" and existing_source_type == "device" and
                    source_name == existing_source_name and group_name != existing_group_name):
                # This is a shared device across groups - not a conflict
                self.logger.debug(
                    f"Shared device detected: {source_name} appears in groups "
                    f"{existing_group_name} and {group_name}"
                )
                return

            # IPs from ansible inventory will conflict with any other source type, like PTF in testbed
            # or connection graph. This is by design.
            if ((source_type != "ansible_inventory" and existing_source_type == "ansible_inventory") or
                    (source_type == "ansible_inventory" and existing_source_type != "ansible_inventory")):
                self.logger.debug(
                    f"IP overlap detected between {source_type} and {existing_source_type}: {ip_addr}"
                )
                return

            # Check if this is the same device in connection graph vs ansible inventory
            device_name_from_source = source_name.split(':')[0] if ':' in source_name else source_name
            device_name_from_existing = (
                existing_source_name.split(':')[0] if ':' in existing_source_name else existing_source_name
            )

            if (device_name_from_source == device_name_from_existing and
                group_name == existing_group_name and
                ((source_type == "device" and existing_source_type == "ansible_inventory") or
                 (source_type == "ansible_inventory" and existing_source_type == "device"))):
                # This is the same device appearing in both connection graph and ansible inventory
                # The consistency validation will handle checking if IPs are consistent
                self.logger.debug(
                    f"Same device in different sources: {device_name_from_source} in "
                    f"{existing_source_type} and {source_type}"
                )
                return

            # Check if this conflict is allowed by allow_conflict_list
            device1_name = existing_source_name.split(':')[0] if ':' in existing_source_name else existing_source_name
            device2_name = source_name.split(':')[0] if ':' in source_name else source_name

            if self._should_allow_conflict(device1_name, device2_name):
                # Conflict is allowed, skip reporting the error
                self.logger.debug(
                    f"Skipping IP conflict error for {ip_addr} between {device1_name} and {device2_name} "
                    f"due to allow_conflict_list"
                )
                return

            # This is a real IP conflict
            # conflict_ip: IP address conflict detected
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

    def _track_device_ip(self, device_name, group_name, source_type, ip_type, ip_addr, device_ips):
        """Track device IP addresses for consistency validation"""
        # Skip excluded devices
        if self._should_exclude_device(group_name):
            return

        if device_name not in device_ips:
            device_ips[device_name] = {}
        if group_name not in device_ips[device_name]:
            device_ips[device_name][group_name] = {}
        if source_type not in device_ips[device_name][group_name]:
            device_ips[device_name][group_name][source_type] = {}
        device_ips[device_name][group_name][source_type][ip_type] = ip_addr

    def _should_allow_conflict(self, device1_name, device2_name):
        """
        Check if an IP conflict should be allowed based on allow_conflict_list

        Args:
            device1_name: Name of the first conflicting device
            device2_name: Name of the second conflicting device

        Returns:
            bool: True if conflict should be allowed, False otherwise
        """
        if not self.compiled_conflict_patterns:
            return False

        for rule in self.compiled_conflict_patterns:
            pattern = rule['pattern']
            to_replacement = rule['to']

            # Apply regex replacement to both device names
            try:
                normalized_device1 = pattern.sub(to_replacement, device1_name)
                normalized_device2 = pattern.sub(to_replacement, device2_name)

                # If the normalized names are the same, allow the conflict
                if normalized_device1 == normalized_device2:
                    self.logger.debug(
                        f"Allowing IP conflict between {device1_name} and {device2_name} "
                        f"(normalized to {normalized_device1})"
                    )
                    return True
            except Exception as e:
                self.logger.warning(f"Error applying conflict rule {rule['from']} -> {rule['to']}: {e}")

        return False

    def _should_exclude_device(self, device_name):
        """
        Check if a device should be excluded from validation

        Args:
            device_name: Name of the device to check

        Returns:
            bool: True if device should be excluded, False otherwise
        """
        if not self.compiled_exclude_patterns:
            return False

        for pattern in self.compiled_exclude_patterns:
            if pattern.search(device_name):
                self.logger.debug(f"Excluding device {device_name} from IP validation")
                return True

        return False

    def _validate_collected_ip_addresses(self, ip_addresses, device_ips):
        """
        Validate properties of collected IP addresses

        Args:
            ip_addresses: Dictionary of IP addresses and their source information
        """
        self._validate_ip_addresses(ip_addresses)

        # Validate device IP consistency across sources
        self._validate_device_ip_consistency(device_ips)

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
                    # reserved_ip: Reserved IP address found
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
                    # reserved_ip: Reserved IP address found
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
                # invalid_ip_format: Invalid IP address format
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

    def _validate_device_ip_consistency(self, device_ips):
        """Validate that the same device has consistent IP addresses across sources"""
        for device_name, groups in device_ips.items():
            # Skip excluded devices
            if self._should_exclude_device(device_name):
                continue

            for group_name, sources in groups.items():
                # Check if device appears in both connection graph and ansible inventory
                if "device" in sources and "ansible_inventory" in sources:
                    device_source = sources["device"]
                    inventory_source = sources["ansible_inventory"]

                    # Check IPv4 consistency (ManagementIp vs ansible_host)
                    if "ipv4" in device_source and "ipv4" in inventory_source:
                        device_ipv4 = device_source["ipv4"]
                        inventory_ipv4 = inventory_source["ipv4"]

                        if device_ipv4 != inventory_ipv4:
                            self.result.add_issue(
                                'E2004',
                                {
                                    "device": device_name,
                                    "group": group_name,
                                    "ip_type": "ipv4",
                                    "connection_graph_ip": device_ipv4,
                                    "ansible_inventory_ip": inventory_ipv4,
                                    "connection_graph_source": "ManagementIp",
                                    "ansible_inventory_source": "ansible_host"
                                }
                            )

                # Check IPv4/IPv6 relationship within ansible inventory
                if "ansible_inventory" in sources:
                    inventory_source = sources["ansible_inventory"]
                    if "ipv4" in inventory_source and "ipv6" in inventory_source:
                        ipv4_addr = inventory_source["ipv4"]
                        ipv6_addr = inventory_source["ipv6"]

                        if not self._check_ipv4_ipv6_relationship(ipv4_addr, ipv6_addr):
                            self.result.add_issue(
                                'E2005',
                                {
                                    "device": device_name,
                                    "group": group_name,
                                    "ipv4_address": ipv4_addr,
                                    "ipv6_address": ipv6_addr,
                                    "ipv4_source": "ansible_inventory",
                                    "ipv6_source": "ansible_inventory"
                                }
                            )

    def _check_ipv4_ipv6_relationship(self, ipv4_addr, ipv6_addr):
        """Check if IPv6 address's last 4 bytes match the IPv4 address"""
        try:
            ipv4_obj = ipaddress.IPv4Address(ipv4_addr)
            ipv6_obj = ipaddress.IPv6Address(ipv6_addr)

            # Get the last 4 bytes (32 bits) of the IPv6 address
            ipv6_last_32_bits = int(ipv6_obj) & 0xFFFFFFFF
            ipv4_32_bits = int(ipv4_obj)

            return ipv6_last_32_bits == ipv4_32_bits

        except (ValueError, AttributeError):
            return False
