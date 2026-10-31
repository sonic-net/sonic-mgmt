"""Finite command/argument coverage for the merged cpoutil contract.

Templates are filled with discovered resources at runtime. Every generated
write case is deliberately invalid and must be rejected before a write.
"""
from itertools import combinations
import shlex


INTERFACE_QUERIES = ("map", "presence", "dom", "tx-disable", "speed application", "lane-status")
ENDPOINT_QUERIES = ("status", "temperature", "lpmode")
LEAF_COMMANDS = tuple("show interface " + name for name in INTERFACE_QUERIES) + tuple(
    "show {} {}".format(target, name) for target in ("oe", "els") for name in ENDPOINT_QUERIES) + (
    "config interface tx-disable", "config oe lpmode", "config oe reset", "config els lpmode", "config els reset",
    "read-eeprom interface", "read-eeprom oe", "read-eeprom els",
    "write-eeprom interface", "write-eeprom oe", "write-eeprom els",
)
HELP_COMMANDS = tuple(sorted({""} | {
    " ".join(command.split()[:length])
    for command in LEAF_COMMANDS for length in range(1, len(command.split()) + 1)
}))
EEPROM_ROUTES = (
    ("oe", "oe", ("--index", "{oe}")),
    ("els", "els", ("--index", "{els}")),
    ("interface-oe", "interface --oe", ("--port", "{port}")),
    ("interface-els", "interface --els", ("--port", "{port}")),
)


def argument_cases():
    cases = []

    def add(name, command, diagnostic, leaf, expected_rc=2):
        # The installed console entry uses Click: usage errors are 2 and
        # callback validation errors (ClickException) are 1.
        cases.append((name, command, diagnostic, leaf, expected_rc))

    for leaf in LEAF_COMMANDS:
        key = leaf.replace(" ", "-")
        add(key + "-unknown-option", leaf + " --unknown-cpo-option", "no such option", leaf)
    for name in INTERFACE_QUERIES:
        leaf = "show interface " + name
        key = leaf.replace(" ", "-")
        add(key + "-invalid-port", leaf + " --port __invalid_cpo_port__", "invalid", leaf, expected_rc=1)
        add(key + "-positional-port", leaf + " __invalid_cpo_port__", "unexpected extra argument", leaf)
        add(key + "-port-no-value", leaf + " --port", "requires an argument", leaf)
    for target in ("oe", "els"):
        for name in ENDPOINT_QUERIES:
            leaf = "show {} {}".format(target, name)
            add(leaf.replace(" ", "-") + "-invalid-index", leaf + " __invalid_index__", "invalid", leaf,
                expected_rc=1)
        for name in ("lpmode", "reset"):
            leaf = "config {} {}".format(target, name)
            key = leaf.replace(" ", "-")
            suffix = " full" if name == "lpmode" else ""
            add(key + "-invalid-index", leaf + " __invalid_index__" + suffix, "invalid", leaf, expected_rc=1)
            add(key + "-no-arguments", leaf, "missing argument", leaf)
            if name == "lpmode":
                add(key + "-missing-mode", leaf + " {" + target + "}", "missing argument", leaf)
                for mode in ("on", "FULL", "invalid"):
                    add(key + "-bad-mode-" + mode, leaf + " {" + target + "} " + mode, "invalid value", leaf)
    leaf = "config interface tx-disable"
    add("tx-invalid-port", leaf + " -p __invalid_cpo_port__ false", "invalid", leaf, expected_rc=1)
    for suffix, arguments in (("no-arguments", ""), ("missing-port", " false"), ("missing-state", " -p {port}")):
        add("tx-" + suffix, leaf + arguments, "missing", leaf)
    for state in ("enable", "TRUE", "1"):
        add("tx-bad-state-" + state, leaf + " -p {port} " + state, "invalid value", leaf)

    read_fields = (("--page", "0"), ("--offset", "0"), ("--size", "1"))
    for route, suffix, selector in EEPROM_ROUTES:
        read_leaf = "read-eeprom " + ("interface" if route.startswith("interface") else suffix)
        read = "read-eeprom " + suffix + " " + " ".join(selector)
        # All three absent is a legal full dump; the six nonempty proper
        # subsets must fail for every endpoint and both interface targets.
        for length in (1, 2):
            for subset in combinations(read_fields, length):
                label = "-".join(option[2:] for option, _ in subset)
                add("read-" + route + "-partial-" + label,
                    read + " " + " ".join(token for pair in subset for token in pair),
                    "must be supplied together", read_leaf, expected_rc=1)
        for option, _ in read_fields:
            add("read-" + route + "-no-value-" + option[2:], read + " " + option,
                "requires an argument", read_leaf)
            add("read-" + route + "-bad-number-" + option[2:], read + " " + option + " invalid",
                "invalid value", read_leaf)
        add("read-" + route + "-unsupported-length-alias", read + " --length 1", "no such option", read_leaf)
        boundaries = (
            ("negative-page", "--page -1 --offset 128 --size 1", "page must be between"),
            ("page-overflow", "--page 256 --offset 128 --size 1", "page must be between"),
            ("negative-offset", "--page 0 --offset -1 --size 1", "offset must be between"),
            ("offset-overflow", "--page 0 --offset 256 --size 1", "offset must be between"),
            ("zero-size", "--page 0 --offset 0 --size 0", "size must be greater than zero"),
            ("negative-size", "--page 0 --offset 0 --size -1", "size must be greater than zero"),
            ("cross-page", "--page 0 --offset 255 --size 2", "crosses the cmis page boundary"),
            ("nonzero-page-lower-half", "--page 1 --offset 0 --size 1", "valid range: 80h-ffh"),
        )
        for label, arguments, error in boundaries:
            add("read-" + route + "-" + label, read + " " + arguments, error, read_leaf, expected_rc=1)

        write_leaf = "write-eeprom " + ("interface" if route.startswith("interface") else suffix)
        write = "write-eeprom " + suffix
        fields = (selector, ("--page", "0"), ("--offset", "0"), ("--data", "ff"))
        for length in range(len(fields)):
            for subset in combinations(fields, length):
                present = "-".join(option[2:] for option, _ in subset) or "none"
                arguments = " ".join(token for pair in subset for token in pair)
                add("write-" + route + "-required-subset-" + present, write + " " + arguments,
                    "missing option", write_leaf)
        for option, _ in fields:
            other = " ".join(token for pair in fields if pair[0] != option for token in pair)
            add("write-" + route + "-no-value-" + option[2:], write + " " + other + " " + option,
                "requires an argument", write_leaf)
        prefix = write + " " + " ".join(selector) + " --page 0 --offset 0 --data "
        for label, data, error in (("empty", "", "data must contain at least one byte"),
                                   ("odd", "1", "hex"), ("nonhex", "gg", "hex")):
            add("write-" + route + "-data-" + label, prefix + shlex.quote(data), error, write_leaf, expected_rc=1)
        for option in ("--page", "--offset"):
            for value in ("-1", "256", "invalid"):
                arguments = " ".join(token for pair in fields for token in
                                     ((option, value) if pair[0] == option else pair))
                error = "invalid value" if value == "invalid" else option[2:] + " must be between"
                add("write-" + route + "-bad-" + option[2:] + "-" + value,
                    write + " " + arguments, error, write_leaf, expected_rc=2 if value == "invalid" else 1)
        for label, arguments, error in (
                ("cross-page", "--page 0 --offset 255 --data 55aa", "crosses the cmis page boundary"),
                ("nonzero-page-lower-half", "--page 1 --offset 0 --data ff", "valid range: 80h-ffh")):
            add("write-" + route + "-" + label,
                write + " " + " ".join(selector) + " " + arguments, error, write_leaf, expected_rc=1)
        if not route.startswith("interface"):
            for operation, prefix in (("read-eeprom", read), ("write-eeprom", write + " " + " ".join(
                    token for pair in fields for token in pair))):
                for option in (("--index", "--bank") if operation == "read-eeprom" else ("--bank",)):
                    if option == "--index":
                        prefix_without = prefix.replace(" ".join(selector), "")
                    else:
                        prefix_without = prefix
                    add(operation + "-" + route + "-no-value-" + option[2:],
                        prefix_without + " " + option, "requires an argument", operation + " " + suffix)
                for value in ("-1", "256"):
                    extra = " --page 0 --offset 0 --size 1" if operation == "read-eeprom" else ""
                    add(operation + "-" + route + "-bad-bank-" + value,
                        prefix + extra + " --bank " + value, "bank must be between", operation + " " + suffix,
                        expected_rc=1)
                for option in ("--index", "--bank"):
                    arguments = prefix.replace(" ".join(selector), "") if option == "--index" else prefix
                    add(operation + "-" + route + "-bad-number-" + option[2:],
                        arguments + " " + option + " invalid", "invalid value", operation + " " + suffix)
    for operation in ("read-eeprom", "write-eeprom"):
        for target_flags, label in (("", "missing-target"), ("--oe --els", "both-targets")):
            arguments = " -p {port} --page 0 --offset 0 " + (
                "--size 1" if operation == "read-eeprom" else "--data ff")
            add(operation + "-interface-" + label, operation + " interface " + target_flags + arguments,
                "exactly one", operation + " interface", expected_rc=1)
    assert len({case[0] for case in cases}) == len(cases), "Duplicate argument-case id"
    return tuple(cases)


ARGUMENT_CASES = argument_cases()
