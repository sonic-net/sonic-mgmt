"""Read platform objects directly, independently of the cpoutil implementation.

Executed with the DUT's Python interpreter by test_cpoutil.py. No writes.
"""
import json
import sys

from sonic_platform.platform import Platform


def read_value(operation):
    try:
        return {"value": operation()}
    except NotImplementedError:
        return {"unsupported": True}


def main():
    indices = json.loads(sys.argv[1])
    chassis = Platform().get_chassis()
    records = {}
    for index in indices:
        cpo = chassis.get_cpo(index)
        if cpo is None:
            records[str(index)] = None
            continue
        records[str(index)] = {
            "presence": read_value(cpo.get_presence),
            "lpmode": read_value(cpo.get_lpmode),
            "oe_lpmode": read_value(cpo.oe.get_lpmode),
            "els_lpmode": read_value(cpo.elsfp.get_lpmode),
        }
    print(json.dumps(records))


if __name__ == "__main__":
    main()
