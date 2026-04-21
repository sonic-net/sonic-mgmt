from __future__ import absolute_import, division, print_function

try:
    from ansible_collections.fortinet.fortios.plugins.module_utils.common.type_utils import (
        match_applied_ip_address_format,
        hyphen_to_underscore,
    )
except ImportError:
    # for pytest to look up the module in the same directory
    from module_utils.common.type_utils import (
        match_applied_ip_address_format,
        hyphen_to_underscore,
    )

__metaclass__ = type
import re


IP_PREFIX = re.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")


def bits(netmask):
    count = 0
    while netmask:
        count += netmask & 1
        netmask >>= 1
    return count


def is_same_ip_address(current_ip, applied_ip):
    """
    current_ip can be either an ip of type str or ip and subnet of tye list
    ip like "10.10.10.0"
    ip with subnet mask: ["10.10.10.0", "255.255.255.0"]
    applied_ip can be in 3 formats:
    2 same as above and
    "10.10.10.0/24"
    """
    if isinstance(current_ip, list):
        current_ip = " ".join(current_ip)
    if len(current_ip) == 0 and len(applied_ip) == 0:
        return True
    if len(current_ip) == 0 or len(applied_ip) == 0:
        return False
    if " " not in applied_ip and "/" not in applied_ip:
        return current_ip == applied_ip

    splitted_current_ip = [current_ip]
    splitted_applied_ip = [applied_ip]
    total_bits_current_ip = 0
    total_bits_applied_ip = 0

    if " " in current_ip:
        splitted_current_ip = current_ip.split(" ")
    elif "/" in current_ip:
        splitted_current_ip = current_ip.split("/")
    if " " in applied_ip:
        splitted_applied_ip = applied_ip.split(" ")
    elif "/" in applied_ip:
        splitted_applied_ip = applied_ip.split("/")

    if splitted_current_ip[0] != splitted_applied_ip[0]:
        return False
    else:
        if "." in splitted_current_ip[1]:
            total_bits_current_ip = sum(
                [bits(int(s)) for s in splitted_current_ip[1].split(".")]
            )
        else:
            total_bits_current_ip = int(splitted_current_ip[1])
        if "." in splitted_applied_ip[1]:
            total_bits_applied_ip = sum(
                [bits(int(s)) for s in splitted_applied_ip[1].split(".")]
            )
        else:
            total_bits_applied_ip = int(splitted_applied_ip[1])

        return total_bits_current_ip == total_bits_applied_ip


def is_same_comparison(reorder_current, reorder_filtered):
    for key, value in reorder_filtered.items():
        if key not in reorder_current:
            return False

        if isinstance(value, dict):
            if not is_same_comparison(reorder_current[key], value):
                return False
        elif isinstance(value, list):
            if len(value) != len(reorder_current[key]):
                return False
            if len(value) and isinstance(value[0], dict):
                for item in value:
                    if not any(
                        is_same_comparison(current_dict, item)
                        for current_dict in reorder_current[key]
                    ):
                        return False
            elif reorder_current[key] != value:
                return False
        elif isinstance(value, str) and IP_PREFIX.match(value):
            if not is_same_ip_address(reorder_current[key], value):
                return False
        elif reorder_current[key] != value:
            return False
        else:
            # print("same value confirmed, continue", reorder_current[key], value)
            continue

    return len(reorder_current) == len(reorder_filtered)


def is_subset(small, big):
    """check if small is a subset of big object:
    1. If small is a dict and big is a dict, then check if all key-value pairs in small are present in big.
    2. If small is a list and big is a list, then check if all elements in small are present in big.
    3. [TODO debatable] If small is a primitive type, then check if it is equal to big.
    """
    if isinstance(small, dict) and isinstance(big, dict):
        for key, value in small.items():
            if key not in big or not is_subset(value, big[key]):
                return False
        return True
    elif isinstance(small, list) and isinstance(big, list):
        for item in small:
            if any(is_subset(item, x) for x in big):
                continue
            return False
        return True
    else:
        return isinstance(big, type(small)) and (
            match_applied_ip_address_format(big, small) == small
            if isinstance(big, str) and IP_PREFIX.match(big)
            else big == small
        )


def omit_keys(input, keys_to_omit):
    """Remove key values pairs from input that are in omit_keys list and return the result with keys that contain hyphens replaced by underscores."""

    result = {}
    if not isinstance(input, dict):
        return input
    for key, value in input.items():
        underscore_key = key.replace("-", "_")
        if underscore_key in keys_to_omit:
            continue
        result[underscore_key] = omit_keys(value, keys_to_omit)

    return result


def omit_encrypted_fields(input, keys_to_omit=frozenset(["psksecret"])):
    """Omit some common encrypted fields from the input dictionary."""
    return omit_keys(input, keys_to_omit)


def unify_data_format(input, keys_to_omit=frozenset(["psksecret"])):
    """Convert input data to a consistent format by replacing hyphens with underscores in keys and remove unwanted keys.

    This function is useful for ensuring that the input data has a consistent key format when doing diffs and other comparisons.
    """

    return omit_encrypted_fields(hyphen_to_underscore(input), keys_to_omit)


def find_current_values(small, big, keys_to_omit=frozenset(["q_origin_key"])):
    """Extract all key-value pairs from big that also exist in small and convert keys with hyphens to underscores.

    For values that are lists:
        1. extract the items in small first following the same order as in small;
        2. add the rest of items in big that are not in small to the end of the resulting list.

    If a key-pair in a dict in small is not found in big, it will be omitted.
    If a key-pair in a dict in big is not found in small, it will be omitted.

    Some values in `big` are record keeping values that do not need to be returned in the result that
    can be omitted by passing `omit_keys` parameter. It should contain lowercase keys only.
    for IP address, it will convert the format of the IP address in big to the format of the IP
    address from small.
    """

    # print("enter", small, big, isinstance(small, list), isinstance(big, list))
    if isinstance(small, dict) and isinstance(big, dict):
        result = {}
        for key, value in small.items():
            if key in big:
                result[key] = find_current_values(value, big[key])
        return result
    elif isinstance(small, list) and isinstance(big, list):
        result = []
        # A hack to track all keys that are known to be present and later can be used to filter out these current keys with default values.
        # This helps to remove unwanted keys in the result and make the check and diff mode results more clear.
        known_keys = set()

        # Go through the small items first to collect existing configurations and
        # then add the new ones to the end of the result list to make the diff mode # results more clear
        for small_item in small:
            (
                known_keys.update(small_item.keys())
                if isinstance(small_item, dict)
                else None
            )
            for big_item in big:
                if is_subset(small_item, big_item):
                    result.append(find_current_values(small_item, big_item))
                    break
        # print('     result after small items:', result)

        for big_item in big:
            if not any(is_subset(x, big_item) for x in result):
                result_without_omit_keys = omit_keys(big_item, keys_to_omit)

                result_without_hidden_keys = (
                    {
                        key: val
                        for key, val in result_without_omit_keys.items()
                        if key in known_keys
                    }
                    if isinstance(result_without_omit_keys, dict)
                    else {}
                )

                if result_without_hidden_keys:
                    result.append(result_without_hidden_keys)
                else:
                    result.append(result_without_omit_keys)
                # print("    not in result", big_item, result)
        return result
    elif isinstance(small, str) and isinstance(big, str):
        # raise Exception(f"small: {small}, big before {big}, big after: {big.strip('" ')}, IP_PREFIX: {IP_PREFIX.match(big.strip('" '))}")
        strip_big = big.strip('" ')
        # raise Exception(match_applied_ip_address_format(strip_big, small) if IP_PREFIX.match(strip_big) else strip_big)
        return (
            match_applied_ip_address_format(strip_big, small) if IP_PREFIX.match(strip_big) else strip_big
        )

    return big


def serialize(data):
    if isinstance(data, str) and " " in data:
        return serialize(data.split(" "))
    if isinstance(data, list) and len(data) > 0:
        if isinstance(data[0], dict):
            list_to_order = []
            for dt in data:
                ret = {}
                for key, value in dt.items():
                    ret[key] = serialize(value)
                list_to_order.append(ret)

            return sorted(list_to_order, key=lambda dt: str(dt.items()))
        else:
            return sorted(data)

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            result[key] = serialize(value)

        return result

    return data


def validate_result(result, desc):
    if not result:
        raise AssertionError("failed on test " + desc)
