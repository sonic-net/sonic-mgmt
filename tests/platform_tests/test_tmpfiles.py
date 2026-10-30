import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("any"),
]


def test_tmpfiles_age_disabled(duthosts, enum_dut_hostname):
    """Verify /tmp and /var/tmp have no cleanup age on SONiC 202511 and later."""
    duthost = duthosts[enum_dut_hostname]

    output = duthost.command("systemd-tmpfiles --no-pager --cat-config")
    # Ignore blank lines and comments, then split each rule into columns.
    rules = []
    for line in output["stdout_lines"]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(line.split())

    # Vendor config
    # q /tmp 1777 root root 10d
    # q /var/tmp 1777 root root 30d
    # What we want
    # q /tmp 1777 root root -
    # q /var/tmp 1777 root root -
    for path in ("/tmp", "/var/tmp"):
        matching_rule = None
        for rule in rules:
            if rule[0] in ("q", "d", "D") and rule[1] == path:
                matching_rule = rule
                break

        if matching_rule is None:
            pytest.fail("No tmpfiles rule found for {}".format(path))
        age = "-"
        if len(matching_rule) > 5:
            age = matching_rule[5]
        pytest_assert(age == "-", "Expected no cleanup age for {}, found {}".format(path, age))
