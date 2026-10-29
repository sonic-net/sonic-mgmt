"""Read platform objects directly, independently of the cpoutil implementation.

Executed with the DUT's Python interpreter by test_cpoutil.py. No writes.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import sys


def read_value(operation):
    try:
        return {"value": operation()}
    except NotImplementedError:
        return {"unsupported": True}


def endpoint_pages(endpoint):
    from sonic_platform_base.sonic_xcvr.mem_maps.public.cmis.pages import CmisAdministrativeLowerPage

    pages = endpoint.get_api().xcvr_eeprom.mem_map.pages
    return [{"page": page.page, "lower": isinstance(page, CmisAdministrativeLowerPage)} for page in pages]


def hook_value(target, method):
    function = getattr(target, method, None)
    return read_value(function) if callable(function) else {"unsupported": True}


def collect(indices):
    from sonic_platform.platform import Platform

    chassis = Platform().get_chassis()
    records = {}
    for index in indices:
        cpo = chassis.get_cpo(index)
        if cpo is None:
            records[str(index)] = None
            continue
        records[str(index)] = {
            "presence": read_value(cpo.get_presence),
            "tx_disable": hook_value(cpo, "get_tx_disable"),
            "oe_lpmode": hook_value(cpo.oe, "get_lpmode"),
            "els_lpmode": hook_value(cpo.elsfp, "get_lpmode"),
            "oe_pages": endpoint_pages(cpo.oe),
            "els_pages": endpoint_pages(cpo.elsfp),
        }
    return records


def main():
    try:
        # Platform imports/getters may print diagnostics; transport only the
        # explicitly selected booleans, lane flags and page metadata below.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            records = collect(json.loads(sys.argv[1]))
    except Exception:
        print(json.dumps({"error": "Platform probe failed; raw output suppressed"}))
        raise SystemExit(3)
    print(json.dumps(records))


if __name__ == "__main__":
    main()
