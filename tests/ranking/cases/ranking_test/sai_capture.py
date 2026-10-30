# -*- coding: utf-8 -*-
"""Per-case SAI attribute capture.

Records which attributes (and, for enum/bool types, which concrete values) each
test case touches. Association only -- no pass/fail judgement here: the report
side joins ptf_results.json and lets the case outcome decide.

Records carry no phase and no SAI status by design: a case is associated with
every attr it touches in any stage, and the verdict comes purely from the case
result.
"""
import json

_CASE = None
_SINK = None
_MAP = {}
_SIGNATURES = {}
_ENABLED = False

# Unions that carry a value-level payload. Everything else stays attr-level.
_SCALAR_UNIONS = ('s32', 'booldata')


def reset():
    """Drop all state. Test-only helper."""
    global _CASE, _SINK, _MAP, _SIGNATURES, _ENABLED
    _CASE, _SINK, _MAP, _SIGNATURES, _ENABLED = None, None, {}, {}, False


def set_case(module, cls):
    global _CASE
    _CASE = '%s.%s' % (module, cls)


def set_sink(fn):
    global _SINK
    _SINK = fn


def configure_adapter(adapter, enabled):
    """Enable or disable the installed runtime wrappers for this case."""
    global _ENABLED
    _ENABLED = enabled
    # Disable a template hook if present; runtime wrappers are authoritative.
    adapter.sai_capture = None


def load_map_dict(envelope):
    """Load the gen_attr_map envelope: attr entries plus adapter signatures."""
    global _MAP, _SIGNATURES
    _MAP = envelope.get('entries') or {}
    _SIGNATURES = envelope.get('signatures') or {}
    return len(_MAP)


def load_map(path):
    with open(path, encoding='utf-8') as f:
        return load_map_dict(json.load(f))


def _pick_scalar(union_obj):
    """acl parameter/data are themselves unions; return the populated field."""
    for f in _SCALAR_UNIONS:
        v = getattr(union_obj, f, None)
        if v is not None:
            return v
    return None


def extract_values(union, raw):
    """Expand one kwarg into the list of values to record.

    Returns [None] for attr-level-only unions so the caller still records one
    cell without a value.
    """
    if union in _SCALAR_UNIONS:
        return [raw]
    if union == 's32list':
        return list(getattr(raw, 'int32list', None) or [])
    if union == 'aclaction':
        if not getattr(raw, 'enable', False):
            return []
        return [_pick_scalar(getattr(raw, 'parameter', None))]
    if union == 'aclfield':
        if not getattr(raw, 'enable', False):
            return []
        return [_pick_scalar(getattr(raw, 'data', None))]
    return [None]


def record_call(func_name, kwargs):
    """Record every mapped, non-None kwarg of one adapter call."""
    if not _ENABLED or _SINK is None:
        return
    for name, raw in kwargs.items():
        if raw is None:
            continue
        entry = _MAP.get('%s|%s' % (func_name, name))
        if entry is None:
            continue
        values = [None] if entry['op'] == 'read' \
            else extract_values(entry['union'], raw)
        for value in values:
            _SINK({'case': _CASE, 'attr': entry['attr'],
                   'op': entry['op'], 'value': value})


def install(adapter, argnames_by_func_map=None):
    """Wrap adapter's sai_thrift_* functions in place.

    Development-phase injection. The community @invocation_logger has no
    functools.wraps, so the wrapped __name__ is 'inner_logger' -- the real
    interface name must be passed in explicitly.

    Defaults to the signatures carried in the loaded map. Those must come from
    the adapter source: most functions take an object id or entry second, so
    guessing ['client'] + mapped kwargs would zip that object id onto an
    attribute the call never set and claim it supported.
    """
    if argnames_by_func_map is None:
        argnames_by_func_map = _SIGNATURES
    wrapped = 0
    for func_name, argnames in argnames_by_func_map.items():
        orig = getattr(adapter, func_name, None)
        if orig is None or getattr(orig, '_sai_capture', False):
            continue

        def make(orig=orig, func_name=func_name, argnames=argnames):
            def inner(*args, **kw):
                try:
                    d = dict(zip(argnames, args))
                    d.update(kw)
                    record_call(func_name, d)
                except Exception:      # capture must never break a test
                    pass
                return orig(*args, **kw)
            inner._sai_capture = True
            return inner

        setattr(adapter, func_name, make())
        wrapped += 1
    return wrapped
