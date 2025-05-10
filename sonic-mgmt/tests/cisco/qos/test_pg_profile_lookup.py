import pytest
import logging
import re

pytestmark = [ pytest.mark.topology('t1') ]

def redis(asic, cmd):
    return asic.run_redis_cmd(cmd.split(' '))

def get_port_speed_cable_length(profile_name):
    # Returns string tuple of the port speed and cable length encoded in the profile
    # name. Includes the trailing 'm' on the cable length.
    match = re.search("pg_lossless_([0-9]+)_([0-9]+m)_profile", profile_name)
    assert match is not None, "Failed to parse lossless profile name '{}'".format(profile_name)
    return (match.group(1), match.group(2))

# Sample pg_profile_lookup.ini format. Note that there's an optional extra column
'''
#  PG lossless profiles - for test purpose only
# speed  cable  size   xon    xoff   threshold
 40000      1m     0     0    441600   -2
'''
def parse_pg_profile_lookup(duthost, fname):
    file_output = duthost.shell("cat {}".format(fname))['stdout']
    table = {}
    for line in file_output.split('\n'):
        line = line.strip()
        if line.startswith("#"):
            continue
        line_data = line.split()
        speed, cable_length = line_data[:2]
        values = line_data[2:]
        table[(speed, cable_length)] = values
    return table


def lookup_redis_field(redis_output, lookup_key):
    # Redis outputs a 1D list of alternating keys/values. Perform lookup manually here.
    try:
        idx = redis_output.index(lookup_key)
        return redis_output[idx + 1]
    except ValueError:
        assert False, "Failed to find key {} in redis output {}".format(lookup_key, redis_output)


def verify_lossless_profile(asic, profile, lookup_table):
    # Get ini file fields
    speed, cable_length = get_port_speed_cable_length(profile)
    assert (speed, cable_length) in lookup_table, "Failed to find ({}, {}) in lookup_table {}".format(speed, cable_length, lookup_table)
    values = lookup_table[(speed, cable_length)]
    size = values[0]
    xon = values[1]
    xoff = values[2]
    threshold = values[3]
    # Note: xon_offset is an optional 4th arg

    # Get fields that are present in the redis DB
    fields = redis(asic, "redis-cli -n 4 HGETALL {}".format(profile))
    actual_size = lookup_redis_field(fields, "size")
    actual_xon = lookup_redis_field(fields, "xon")
    actual_xoff = lookup_redis_field(fields, "xoff")
    actual_threshold = lookup_redis_field(fields, "dynamic_th")

    # Verify matching
    assert actual_size == size
    assert actual_xon == xon
    assert actual_xoff == xoff
    assert actual_threshold == threshold

def test_pg_profile_lookup(duthosts):
    for duthost in duthosts:
        if duthost.facts["asic_type"] != "cisco-8000":
            pytest.skip("Test is only supported for cisco-8000")
        prefix = "/usr/share/sonic/device"
        platform = duthost.facts["platform"]
        hwsku = duthost.facts["hwsku"]
        fname = "pg_profile_lookup.ini"
        for asic in duthost.asics:
            if duthost.is_multi_asic:
                curr_pg_file = "{}/{}/{}/{}/{}".format(prefix, platform, hwsku, asic.asic_index, fname)
            else: # single asic
                curr_pg_file = "{}/{}/{}/{}".format(prefix, platform, hwsku, fname)
            output = duthost.shell("test -f {}".format(curr_pg_file), module_ignore_errors=True)
            file_exists = (output['rc'] == 0)
            assert file_exists, "{} file is missing, required for PFC".format(curr_pg_file)

            # pg_profile_lookup.ini should be picked up by the buffer config manager during
            # minigraph deployment and PFC priority activation.
            lookup_table = parse_pg_profile_lookup(duthost, curr_pg_file)
            profiles = redis(asic, "redis-cli -n 4 KEYS BUFFER_PROFILE|*")
            lossless_profile_count = 0
            for profile in profiles:
                if profile.startswith("BUFFER_PROFILE|pg_lossless"):
                    verify_lossless_profile(asic, profile, lookup_table)
                    lossless_profile_count += 1
            assert lossless_profile_count != 0, "Failed to find any lossless profiles in buffer profile list: {}".format(profiles)
            logging.info("Found and verified {} lossless profiles".format(lossless_profile_count))
