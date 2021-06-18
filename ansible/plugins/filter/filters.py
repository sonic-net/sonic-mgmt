from ansible import errors
from math import log


class FilterModule(object):
    def filters(self):
        return {
            'extract_by_prefix': extract_by_prefix,
            'filter_by_prefix': filter_by_prefix,
            'filter_vm_targets': filter_vm_targets,
            'extract_hostname': extract_hostname,
            'first_n_elements': first_n_elements,
            'expand_properties': expand_properties
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

    if not isinstance(num, str) and not isinstance(num, unicode):
        raise errors.AnsibleFilterError("Wrong type for the num {}".format(type(num)))

    if len(values) <= int(num):
        return values

    return values[0:int(num)]


def filter_vm_targets(values, topology, vm_base):
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

    if not isinstance(vm_base, str) and not isinstance(vm_base, unicode):
        raise errors.AnsibleFilterError('Wrong type for the vm_base')

    if vm_base not in values:
        raise errors.AnsibleFilterError('Current vm_base: %s is not found in vm_list' % vm_base)

    result = []
    base = values.index(vm_base)
    for hostname, attr in topology.iteritems():
        if base + attr['vm_offset'] >= len(values):
            continue
        result.append(values[base + attr['vm_offset']])

    return result


def extract_hostname(values, topology, vm_base, inventory_hostname):
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

    if not isinstance(vm_base, str) and not isinstance(vm_base, unicode):
        raise errors.AnsibleFilterError('Wrong type for the vm_base')

    if not isinstance(inventory_hostname, str) and not isinstance(inventory_hostname, unicode):
        raise errors.AnsibleFilterError('Wrong type for the inventor_hostname')

    if vm_base not in values:
        raise errors.AnsibleFilterError('Current vm_base: %s is not found in vm_list' % vm_base)

    hash = {}
    base = values.index(vm_base)
    for hostname, attr in topology.iteritems():
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
