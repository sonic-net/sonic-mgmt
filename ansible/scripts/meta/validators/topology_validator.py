"""
TopologyValidator - Validates topology files in ansible/vars folder
"""

import yaml
import ipaddress
from pathlib import Path
from .base_validator import BaseValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("topology")
class TopologyValidator(BaseValidator):
    """Validates topology files defined under ansible/vars folder"""

    def __init__(self, config=None):
        super().__init__(
            name="topology",
            description="Validates topology files defined under ansible/vars folder",
            category="configuration"
        )
        self.config = config or {}
        # Base paths relative to the validator script location
        self.base_path = Path(__file__).parent.parent.parent.parent
        self.vars_path = self.base_path / "vars"
        self.templates_path = self.base_path / "roles" / "eos" / "templates"

    def _run_pre_validation_checks(self, context: ValidatorContext) -> bool:
        """
        Override pre-validation checks since topology validator doesn't need group data

        Returns:
            bool: Always True since this validator only needs file system access
        """
        # Topology validator only needs file system access, not group data
        return True

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate topology files in ansible/vars folder

        Args:
            context: ValidatorContext containing validation data
        """
        # Find all topology files
        topology_files = self._find_topology_files()

        if not topology_files:
            self.result.add_summary("No topology files found for validation")
            return

        validated_files = 0
        total_errors = 0

        for topo_file in topology_files:
            try:
                topology_data = self._load_topology_file(topo_file)
                if topology_data:
                    file_errors = self._validate_topology_file(topo_file, topology_data)
                    total_errors += file_errors
                    validated_files += 1
            except Exception as e:
                self.result.add_parse_error(
                    f"Failed to process topology file {topo_file}: {str(e)}",
                    {"file": str(topo_file), "error": str(e)}
                )
                total_errors += 1

        # Add metadata
        self.result.metadata.update({
            "topology_files_found": len(topology_files),
            "files_validated": validated_files,
            "total_errors": total_errors
        })

        if self.result.success:
            self.result.add_summary(
                f"Topology validation passed for {validated_files} topology files",
                self.result.metadata
            )

    def _find_topology_files(self):
        """Find all topology files in ansible/vars folder"""
        topology_files = []

        if not self.vars_path.exists():
            self.result.add_missing_data(
                f"Topology vars directory not found: {self.vars_path}"
            )
            return topology_files

        # Find all topo_*.yml files
        for file_path in self.vars_path.glob("topo_*.yml"):
            topology_files.append(file_path)

        return sorted(topology_files)

    def _load_topology_file(self, topo_file):
        """Load and parse a topology YAML file"""
        try:
            with open(topo_file, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.result.add_parse_error(
                f"Invalid YAML in topology file {topo_file.name}: {str(e)}",
                {"file": str(topo_file), "yaml_error": str(e)}
            )
            return None
        except FileNotFoundError:
            self.result.add_missing_data(
                f"Topology file not found: {topo_file}"
            )
            return None

    def _validate_topology_file(self, topo_file, topology_data):
        """
        Validate a single topology file

        Returns:
            int: Number of errors found in this file
        """
        initial_error_count = self.result.error_count
        topo_name = self._extract_topology_name(topo_file.name)

        # 1. Validate template files for swroles
        self._validate_template_files(topo_name, topology_data)

        # 2. Validate VLAN and VM offset uniqueness
        self._validate_vlan_and_vm_uniqueness(topo_name, topology_data)

        # 3. Validate vlan_config interfaces
        self._validate_vlan_configs(topo_name, topology_data)

        # 4. Validate bp_interface subnet consistency
        self._validate_bp_interface_subnets(topo_name, topology_data)

        return self.result.error_count - initial_error_count

    def _extract_topology_name(self, filename):
        """Extract topology name from filename (e.g., topo_t1-isolated-d56u1-lag.yml -> t1-isolated-d56u1-lag)"""
        if filename.startswith("topo_") and filename.endswith(".yml"):
            return filename[5:-4]  # Remove "topo_" prefix and ".yml" suffix
        return filename

    def _validate_template_files(self, topo_name, topology_data):
        """Validate that required template files exist for each swrole referenced by VMs"""
        if not topology_data or 'configuration' not in topology_data:
            return

        configuration = topology_data['configuration']
        config_props = topology_data.get('configuration_properties', {})
        swroles = set()

        # Only collect swroles that are referenced by VMs through their properties
        for vm_name, vm_config in configuration.items():
            if not isinstance(vm_config, dict):
                continue

            # Check if VM has properties that reference configuration_properties
            vm_properties = vm_config.get('properties', [])
            if not vm_properties:
                continue

            # For each property referenced by this VM, get its swrole
            for prop_name in vm_properties:
                if prop_name in config_props:
                    props = config_props[prop_name]
                    if isinstance(props, dict) and 'swrole' in props:
                        swroles.add(props['swrole'])

        if not swroles:
            # This is not necessarily an error - some topologies might not use swroles
            return

        # Validate template files exist for each swrole
        for swrole in swroles:
            template_filename = f"{topo_name}-{swrole}.j2"
            template_path = self.templates_path / template_filename

            if not template_path.exists():
                self.result.add_missing_data(
                    f"Template file {template_path} not found for swrole: {swrole} in topology {topo_name}",
                    {
                        "topology": topo_name,
                        "swrole": swrole,
                        "expected_path": str(template_path),
                        "template_filename": template_filename
                    }
                )

    def _validate_vlan_and_vm_uniqueness(self, topo_name, topology_data):
        """Validate VLAN and VM offset uniqueness"""
        if not topology_data or 'topology' not in topology_data:
            return

        topology = topology_data['topology']

        # Collect VLAN IDs from host_interfaces and VMs
        used_vlans = {}  # vlan_id -> source info
        vm_offsets = {}  # offset -> vm_name

        # Check host_interfaces VLANs (these are interface indices, not VLANs, so skip VLAN validation for them)
        host_interfaces = topology.get('host_interfaces', [])

        # Check VM VLANs and offsets
        vms = topology.get('VMs', {})
        for vm_name, vm_config in vms.items():
            # Validate VM offset uniqueness
            vm_offset = vm_config.get('vm_offset')
            if vm_offset is not None:
                if vm_offset in vm_offsets:
                    self.result.add_duplicate(
                        f"VM offset {vm_offset} is used by multiple VMs: {vm_offsets[vm_offset]}, {vm_name}",
                        {
                            "topology": topo_name,
                            "duplicate_offset": vm_offset,
                            "conflicting_vms": [vm_offsets[vm_offset], vm_name]
                        }
                    )
                else:
                    vm_offsets[vm_offset] = vm_name

            # Validate VLAN uniqueness
            vm_vlans = vm_config.get('vlans', [])
            for vlan_id in vm_vlans:
                vlan_source = f"VM {vm_name}"
                if vlan_id in used_vlans:
                    self.result.add_duplicate(
                        f"VLAN ID {vlan_id} is used by both {used_vlans[vlan_id]} and {vlan_source}",
                        {
                            "topology": topo_name,
                            "duplicate_vlan": vlan_id,
                            "conflicting_sources": [used_vlans[vlan_id], vlan_source]
                        }
                    )
                else:
                    used_vlans[vlan_id] = vlan_source

        # Check for conflicts between VM VLANs and host_interfaces indices
        # Note: host_interfaces are VLAN ID indices assigned to these interfaces
        for interface_idx in host_interfaces:
            if interface_idx in used_vlans:
                self.result.add_duplicate(
                    f"VLAN ID {interface_idx} is used by both {used_vlans[interface_idx]} and host_interfaces",
                    {
                        "topology": topo_name,
                        "duplicate_vlan": interface_idx,
                        "conflicting_sources": [used_vlans[interface_idx], "host_interfaces"]
                    }
                )

    def _validate_vlan_configs(self, topo_name, topology_data):
        """Validate vlan_config interface assignments"""
        if not topology_data or 'topology' not in topology_data:
            return

        topology = topology_data['topology']
        dut_config = topology.get('DUT', {})
        vlan_configs = dut_config.get('vlan_configs', {})

        # Skip default_vlan_config entry
        config_entries = {k: v for k, v in vlan_configs.items() if k != 'default_vlan_config'}

        for config_name, config_data in config_entries.items():
            if not isinstance(config_data, dict):
                continue

            for vlan_name, vlan_info in config_data.items():
                if not isinstance(vlan_info, dict):
                    continue

                intfs = vlan_info.get('intfs', [])
                prefix = vlan_info.get('prefix')

                # Validate interface uniqueness within this VLAN config
                seen_intfs = set()
                for intf in intfs:
                    if intf in seen_intfs:
                        self.result.add_duplicate(
                            f"Interface {intf} appears multiple times in vlan_config {vlan_name}.intfs",
                            {
                                "topology": topo_name,
                                "vlan_config": config_name,
                                "vlan_name": vlan_name,
                                "duplicate_interface": intf
                            }
                        )
                    else:
                        seen_intfs.add(intf)

                # Validate interface count against prefix limits
                if prefix and intfs:
                    try:
                        network = ipaddress.IPv4Network(prefix, strict=False)
                        max_hosts = network.num_addresses - 2  # Subtract network and broadcast addresses

                        if len(intfs) > max_hosts:
                            self.result.add_consistency_error(
                                f"vlan_config {vlan_name} has {len(intfs)} interfaces but prefix {prefix} "
                                f"only supports {max_hosts} hosts",
                                {
                                    "topology": topo_name,
                                    "vlan_config": config_name,
                                    "vlan_name": vlan_name,
                                    "interface_count": len(intfs),
                                    "max_hosts": max_hosts,
                                    "prefix": prefix
                                }
                            )
                    except (ipaddress.AddressValueError, ValueError) as e:
                        self.result.add_format_error(
                            f"Invalid prefix format in vlan_config {vlan_name}: {prefix}",
                            {
                                "topology": topo_name,
                                "vlan_config": config_name,
                                "vlan_name": vlan_name,
                                "prefix": prefix,
                                "error": str(e)
                            }
                        )

    def _validate_bp_interface_subnets(self, topo_name, topology_data):
        """Validate bp_interface subnet consistency"""
        if not topology_data or 'configuration' not in topology_data:
            return

        configuration = topology_data['configuration']
        bp_subnets = {}  # subnet -> list of (vm_name, ip_address)

        for vm_name, vm_config in configuration.items():
            if not isinstance(vm_config, dict):
                continue

            bp_interface = vm_config.get('bp_interface', {})
            if not isinstance(bp_interface, dict):
                continue

            ipv4_addr = bp_interface.get('ipv4')
            if not ipv4_addr:
                continue

            try:
                # Extract IP and prefix
                ip_network = ipaddress.IPv4Interface(ipv4_addr)
                subnet = ip_network.network
                ip_addr = ip_network.ip

                if subnet not in bp_subnets:
                    bp_subnets[subnet] = []
                bp_subnets[subnet].append((vm_name, str(ip_addr)))

            except (ipaddress.AddressValueError, ValueError) as e:
                self.result.add_format_error(
                    f"Invalid bp_interface IPv4 address format in {vm_name}: {ipv4_addr}",
                    {
                        "topology": topo_name,
                        "vm_name": vm_name,
                        "ipv4_address": ipv4_addr,
                        "error": str(e)
                    }
                )

        # Check if all bp_interface IPs are in the same subnet
        if len(bp_subnets) > 1:
            subnet_info = []
            for subnet, vm_list in bp_subnets.items():
                subnet_info.append({
                    "subnet": str(subnet),
                    "vms": [vm_name for vm_name, _ in vm_list]
                })

            self.result.add_consistency_error(
                f"bp_interface IPs span multiple subnets: {', '.join(str(s) for s in bp_subnets.keys())}",
                {
                    "topology": topo_name,
                    "subnet_count": len(bp_subnets),
                    "subnets": subnet_info
                }
            )

        # Check for duplicate IP addresses within the same subnet
        for subnet, vm_list in bp_subnets.items():
            ip_to_vm = {}
            for vm_name, ip_addr in vm_list:
                if ip_addr in ip_to_vm:
                    self.result.add_duplicate(
                        f"Duplicate bp_interface IP {ip_addr} used by VMs: {ip_to_vm[ip_addr]}, {vm_name}",
                        {
                            "topology": topo_name,
                            "duplicate_ip": ip_addr,
                            "subnet": str(subnet),
                            "conflicting_vms": [ip_to_vm[ip_addr], vm_name]
                        }
                    )
                else:
                    ip_to_vm[ip_addr] = vm_name
