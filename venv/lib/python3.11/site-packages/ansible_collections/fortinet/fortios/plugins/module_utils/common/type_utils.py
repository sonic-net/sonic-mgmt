from __future__ import absolute_import, division, print_function

__metaclass__ = type


def underscore_to_hyphen(data):
    """Recursively replace underscores in input object keys to hyphens"""
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def hyphen_to_underscore(data):
    """Recursively replace hyphens in input object keys to underscores"""
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = hyphen_to_underscore(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("-", "_")] = hyphen_to_underscore(v)
        data = new_data

    return data


def cidr_to_netmask(ip_cidr):
    """Convert IP/CIDR format to IP Subnet Mask format."""
    ip, cidr = ip_cidr.split("/")
    cidr = int(cidr)
    mask = ((1 << cidr) - 1) << (32 - cidr)
    subnet_mask = ".".join(str((mask >> i) & 0xFF) for i in [24, 16, 8, 0])
    return "{} {}".format(ip, subnet_mask)


def netmask_to_cidr(ip_subnet):
    """Convert IP Subnet Mask format to IP/CIDR format."""
    ip, subnet = ip_subnet.split(None, 1)
    subnet_parts = map(int, subnet.split("."))
    cidr = sum(bin(part).count("1") for part in subnet_parts)
    return "{}/{}".format(ip, cidr)


def match_applied_ip_address_format(current_ip, applied_ip):
    """current_ip can be either an ip of type str or ip and subnet of tye list
    ip like
    make current_ip and applied_ip in the same format
    """
    # the input is in the netmask format
    if "/" in applied_ip:
        if "/" in current_ip:
            return current_ip
        return netmask_to_cidr(current_ip)
    elif " " in applied_ip:
        if " " in current_ip:
            return current_ip
        return cidr_to_netmask(current_ip)

    return current_ip
