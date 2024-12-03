import ipaddress
import math
import os.path

from ansible import errors


class FilterModule(object):
    def filters(self):
        return {
            'filter_by_dut_interfaces': MultiServersUtils.filter_by_dut_interfaces_util,
            'get_vms_by_dut_interfaces': MultiServersUtils.parse_topology_vms,
            'extract_by_prefix': extract_by_prefix,
            'filter_by_prefix': filter_by_prefix,
            'filter_vm_targets': filter_vm_targets,
            'extract_hostname': extract_hostname,
            'first_n_elements': first_n_elements,
            'expand_properties': expand_properties,
            'first_ip_of_subnet': first_ip_of_subnet,
            'path_join': path_join
        }


def extract_by_prefix(values, prefix):
    """
    This function takes a list as 'values' parameter and extract a first value from the list which contains prefix.
    The prefix is defined in parameter 'prefix'
    """
    if values is None:
        raise errors.AnsibleFilterError('Values is not provided')

    if prefix is None:
        raise errors.AnsibleFilterError('Prefix is not provided')

    if not isinstance(values, list):
        raise errors.AnsibleFilterError('Wrong type for values')

    if not isinstance(prefix, str):
        raise errors.AnsibleFilterError('Wrong type for the prefix')

    if len(values) == 0:
        raise errors.AnsibleFilterError('Empty list. Nothing to extract')

    for v in values:
        if v.startswith(prefix):
            return v

    raise errors.AnsibleFilterError('Value not found')


def filter_by_prefix(values, prefix):
    """
    This function takes a list as 'values' parameter and filters out all list values which contain prefix.
    The prefix is defined in parameter 'prefix'
    """
    if values is None:
        raise errors.AnsibleFilterError('Values is not provided')

    if prefix is None:
        raise errors.AnsibleFilterError('Prefix is not provided')

    if not isinstance(values, list):
        raise errors.AnsibleFilterError('Wrong type for values')

    if not isinstance(prefix, str):
        raise errors.AnsibleFilterError('Wrong type for the prefix')

    return filter(lambda x: x.startswith(prefix), values)


def first_n_elements(values, num):
    """
    This function return first n elements of a list. If the list length is less than n, then return the whole list
    """
    if values is None:
        raise errors.AnsibleFilterError('Values is not provided')

    if num is None:
        raise errors.AnsibleFilterError('num is not provided')

    if not isinstance(values, list):
        raise errors.AnsibleFilterError('Wrong type for values')

    if not isinstance(num, str) and not isinstance(num, unicode):               # noqa F821
        raise errors.AnsibleFilterError("Wrong type for the num {}".format(type(num)))

    if len(values) <= int(num):
        return values

    return values[0:int(num)]


def filter_vm_targets(values, topology, vm_base, dut_interfaces=None):
    """
    This function takes a list of host VMs as parameter 'values' and then extract a list of host VMs
    which starts with 'vm_base' and contains all VMs which mentioned in 'vm_offset' keys inside of 'topology' structure
    """
    if values is None:
        raise errors.AnsibleFilterError('Values is not provided')

    if topology is None:
        raise errors.AnsibleFilterError('topology is not provided')

    if vm_base is None:
        raise errors.AnsibleFilterError('vm_base is not provided')

    if not isinstance(values, list):
        raise errors.AnsibleFilterError('Wrong type for values')

    if not isinstance(topology, dict):
        raise errors.AnsibleFilterError('Wrong type for the topology')

    if not isinstance(vm_base, str) and not isinstance(vm_base, unicode):       # noqa F821
        raise errors.AnsibleFilterError('Wrong type for the vm_base')

    if vm_base not in values:
        raise errors.AnsibleFilterError('Current vm_base: %s is not found in vm_list' % vm_base)

    vms = MultiServersUtils.parse_topology_vms(topology, dut_interfaces) if dut_interfaces else topology
    result = []
    base = values.index(vm_base)
    for hostname, attr in vms.items():
        if base + attr['vm_offset'] >= len(values):
            continue
        result.append(values[base + attr['vm_offset']])

    return result


def extract_hostname(values, topology, vm_base, inventory_hostname, dut_interfaces=None):
    """
    This function takes a list of host VMs as parameter 'values' and then return 'inventory_hostname'
    corresponding EOS hostname based on 'topology' structure, 'vm_base' parameters
    """
    if values is None:
        raise errors.AnsibleFilterError('Values is not provided')

    if topology is None:
        raise errors.AnsibleFilterError('topology is not provided')

    if vm_base is None:
        raise errors.AnsibleFilterError('vm_base is not provided')

    if inventory_hostname is None:
        raise errors.AnsibleFilterError('inventory_hostname is not provided')

    if not isinstance(values, list):
        raise errors.AnsibleFilterError('Wrong type for values')

    if not isinstance(topology, dict):
        raise errors.AnsibleFilterError('Wrong type for the topology')

    if not isinstance(vm_base, str) and not isinstance(vm_base, unicode):       # noqa F821
        raise errors.AnsibleFilterError('Wrong type for the vm_base')

    if not isinstance(inventory_hostname, str) and not isinstance(inventory_hostname, unicode):     # noqa F821
        raise errors.AnsibleFilterError('Wrong type for the inventor_hostname')

    if vm_base not in values:
        raise errors.AnsibleFilterError('Current vm_base: %s is not found in vm_list' % vm_base)

    vms = MultiServersUtils.parse_topology_vms(topology, dut_interfaces) if dut_interfaces else topology
    base = values.index(vm_base)
    for hostname, attr in vms.items():
        if base + attr['vm_offset'] >= len(values):
            continue
        if inventory_hostname == values[base + attr['vm_offset']]:
            return hostname

    return "hostname not found"  # This string should not be used as valid hostname


def log(value, base):
    """
    This function returns the logarithm of 'value' to the given base 'base'
    """
    if value is None:
        raise errors.AnsibleFilterError('value is not provided')

    if base is None:
        raise errors.AnsibleFilterError('base is not provided')

    if not isinstance(value, int):
        raise errors.AnsibleFilterError('Wrong type for value')

    if not isinstance(base, int):
        raise errors.AnsibleFilterError('Wrong type for base')

    return math.log(value, base)


def expand_properties(value, configuration_properties):
    """Expand configuration properties list to property key-value dictionary."""
    configuration = value
    vm_properties = {}
    for vm, vm_info in configuration.items():
        properties = vm_info.get("properties", [])
        vm_properties[vm] = {}
        for p in properties:
            if p in configuration_properties:
                vm_properties[vm].update(configuration_properties[p])
    return vm_properties


def first_ip_of_subnet(value):
    subnet = ipaddress.ip_network(value.encode().decode(), strict=False)
    if subnet.num_addresses >= 2:
        return str(subnet[1])
    else:
        return ''


def path_join(paths):
    """Join path strings."""
    return os.path.join(*paths)


class MultiServersUtils:
    @staticmethod
    def filter_by_dut_interfaces_util(values, dut_interfaces):
        if not dut_interfaces:
            return values

        if isinstance(dut_interfaces, str) or isinstance(dut_interfaces, unicode):  # noqa F821
            dut_interfaces = MultiServersUtils.parse_multi_servers_interface(dut_interfaces)

        if isinstance(values, dict):
            return {k: v for k, v in values.items() if int(k) in dut_interfaces}
        elif isinstance(values, list):
            return [v for v in values if int(v) in dut_interfaces]
        else:
            raise ValueError('Unsupported type "{}"'.format(type(values)))

    @staticmethod
    def parse_multi_servers_interface(intf_pattern):
        intf_pattern = str(intf_pattern)
        intfs = []
        for intf in iter(map(str.strip, intf_pattern.split(','))):
            if intf.isdigit():
                intfs.append(int(intf))
            elif '-' in intf:
                intf_range = list(map(int, map(str.strip, intf.split('-'))))
                assert len(intf_range) == 2, 'Invalid interface range "{}"'.format(intf)
                intfs.extend(list(range(intf_range[0], intf_range[1]+1)))
            else:
                raise ValueError('Unsupported format "{}"'.format(intf_pattern))
        if len(intfs) != len(set(intfs)):
            raise ValueError('There are interface duplication/overlap in "{}"'.format(intf_pattern))
        return intfs

    @staticmethod
    def parse_topology_vms(VMs, dut_interfaces):
        if not dut_interfaces:
            return VMs

        if isinstance(dut_interfaces, str) or isinstance(dut_interfaces, unicode):  # noqa F821
            dut_interfaces = MultiServersUtils.parse_multi_servers_interface(dut_interfaces)

        result = {}
        offset = 0
        for hostname, attr in VMs.items():
            if dut_interfaces and attr['vlans'][0] not in dut_interfaces:
                continue
            result[hostname] = attr
            result[hostname]['vm_offset'] = offset
            offset += 1
        return result
