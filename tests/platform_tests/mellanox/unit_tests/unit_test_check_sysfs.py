from tests.platform_tests.mellanox.check_sysfs import _is_fan_speed_in_range


def _fan_info(speed_get, speed_set=63, min_speed=4500, max_speed=25000):
    return {
        "min_speed": str(min_speed),
        "max_speed": str(max_speed),
        "speed_set": str(speed_set),
        "speed_get": str(speed_get),
    }


def test_fan_speeds_in_range():
    sysfs_facts = {
        "fan_info": {
            "1": _fan_info(10000),
            "2": _fan_info(9000),
        }
    }

    assert _is_fan_speed_in_range(sysfs_facts)


def test_transient_fan_speed_mismatch_returns_false(caplog):
    sysfs_facts = {"fan_info": {"1": _fan_info(12157)}}

    assert not _is_fan_speed_in_range(sysfs_facts)
    assert "Fan 1 speed 12157 not in range" in caplog.text


def test_invalid_fan_speed_data_returns_false(caplog):
    sysfs_facts = {"fan_info": {"1": _fan_info("unavailable")}}

    assert not _is_fan_speed_in_range(sysfs_facts)
    assert "Invalid fan speed data for fan 1" in caplog.text


def test_all_fans_are_validated():
    sysfs_facts = {
        "fan_info": {
            "1": _fan_info(10000),
            "2": _fan_info(12157),
        }
    }

    assert not _is_fan_speed_in_range(sysfs_facts)
