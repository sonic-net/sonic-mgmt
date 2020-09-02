
"""Utilities for interacting with configurable drop counters."""

from collections import namedtuple

PORT_INGRESS_COUNTER_TYPE = "PORT_INGRESS_DROPS"
SWITCH_INGRESS_COUNTER_TYPE = "SWITCH_INGRESS_DROPS"

SUPPORTED_COUNTER_TYPES = [PORT_INGRESS_COUNTER_TYPE, SWITCH_INGRESS_COUNTER_TYPE]

_ParserParameters = namedtuple("_ParserParameters", ["leading_rows",
                                                     "header_rows",
                                                     "status_columns"])
_PARSER_PARAMETERS = {
    PORT_INGRESS_COUNTER_TYPE: _ParserParameters(leading_rows=0, header_rows=2, status_columns=2),
    SWITCH_INGRESS_COUNTER_TYPE: _ParserParameters(leading_rows=1, header_rows=2, status_columns=1)
}

_SHOW_CAPABILITIES = "show dropcounters capabilities"
_CREATE_COUNTER = "config dropcounters install {} {} {}"
_DELETE_COUNTER = "config dropcounters delete {}"


def get_device_capabilities(dut):
    """
    Fetch the drop counter capabilities for the given device.

    Args:
        dut (SonicHost): The device to query for drop counter capabilities.

    Returns:
        A Dictionary containing 1) A Dictionary that maps from supported counter types to the
        number of support counters of that type, and 2) a Dictionary that maps from supported
        counter types to drop reasons that are supported for that type.

        If drop counters are not supported on this device, then an empty dictionary will be
        returned, like this: `{"counters": {}, "reasons": {}}`.

        If any other error occurs, then None will be returned.

    """

    output = dut.command(_SHOW_CAPABILITIES)

    if output["rc"] == 2:
        return {"counters": {}, "reasons": {}}
    elif output["rc"]:
        return None

    if "does not support drop counters" in output["stdout"]:
        return {"counters": {}, "reasons": {}}

    counters = {}
    reasons = {}

    # Delete the header.
    output = output["stdout_lines"][2:]

    # Extract the supported counter types and quantities from the first
    # part of the output. We'll parse until we hit the empty line.
    line = output.pop(0)
    while line:
        line = line.split()

        counters[line[0]] = int(line[1])
        reasons[line[0]] = []
        line = output.pop(0)

    # Extract the supported drop reasons from the second part of the output.
    curr_type = []
    for line in output:
        if not line:
            continue
        elif line in SUPPORTED_COUNTER_TYPES:
            curr_type = reasons[line]
        else:
            curr_type.append(line.strip())

    return {"counters": counters, "reasons": reasons}


def create_drop_counter(dut, counter_name, counter_type, drop_reasons):
    """
    Create a drop counter on the target device.

    Args:
        dut (SonicHost): The target device.
        counter_name (str): The name of the counter to be created.
        counter_type (str): The type of counter to create.
        drop_reasons (List[str]): The drop reasons to add to the counter.

    Raises:
        RunAnsibleModuleFail: If the given counter name is already in use.

    """
    dut.command(_CREATE_COUNTER.format(counter_name, counter_type, ",".join(drop_reasons)))


def delete_drop_counter(dut, counter_name):
    """
    Delete the drop counter from the target device.

    Args:
        dut (SonicHost): The target device.
        counter_name (str): The name of the counter to be created.

    """
    dut.command(_DELETE_COUNTER.format(counter_name))


def get_drop_counts(dut, counter_type, counter_name, interface):
    """
    Get the count for a given counter on a given interface.

    Note:
        If the specified type is a SWITCH level counter, then the "interface" field is ignored.

    Args:
        dut (SonicHost): The target device.
        counter_type (str): The type of counter being queried.
        counter_name (str): The name of the counter to query.
        interface (str): The interface to query.

    Returns:
        The number of drops on the specified counter, or "None" if the counter type is not
        supported or the counter is not found.

    """
    if counter_type not in SUPPORTED_COUNTER_TYPES:
        return None

    bind_point = interface if "PORT" in counter_type else dut.hostname

    output = dut.command("show dropcounters counts -t {}".format(counter_type))["stdout_lines"]
    counts = _parse_drop_counts(counter_type, output)

    return int(counts[bind_point.upper()].get(counter_name))


def _parse_drop_counts(counter_type, counts_output):
    leading_rows = _PARSER_PARAMETERS[counter_type].leading_rows
    header_rows = _PARSER_PARAMETERS[counter_type].header_rows
    status_columns = _PARSER_PARAMETERS[counter_type].status_columns

    # Skip any leading rows in the output
    trimmed_output = counts_output[leading_rows:]

    # Skip over the status columns to get the counter names
    counter_names = trimmed_output[0].split()[status_columns:]

    # Skip over the header rows to get to the actual counts
    interface_counts = trimmed_output[header_rows:]

    counts_dict = {}
    for row in interface_counts:
        tokens = row.split()

        interface = tokens[0].upper()
        counts_dict[interface] = {}

        # Skip over the status columns so the counter names and drop counts line up
        drop_counts = tokens[status_columns:]

        for i in range(len(drop_counts)): # pylint: disable=consider-using-enumerate
            counts_dict[interface][counter_names[i]] = drop_counts[i]

    return counts_dict
