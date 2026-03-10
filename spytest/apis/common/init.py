# this file is imported from framework and hence
# we can't import framework API globally here
# import them with in functions
# from spytest import st

from utilities.tracer import Tracer


def _callback(event, data, fpath, func, *args, **kwargs):
    if data == "infra":
        kwargs["_func_"] = func
        from apis.common.instrument import apis_instrument as apis_instrument_impl
        return apis_instrument_impl("infra-call-prolog", *args, **kwargs)


def apis_register():
    # Tracer.register(_callback, "infra", include="spytest/infra.py")
    from apis.common.hooks import Hooks
    return Hooks()


def apis_instrument(scope, *args, **kwargs):
    from apis.common.instrument import apis_instrument as apis_instrument_impl
    return apis_instrument_impl(scope, *args, **kwargs)


def apis_trace_register(callback, data):
    exclude = ["common/sonic_prompts.py", "common/hooks.py",
               "common/checks.py", "common/support.py",
               "common/init.py", "common/instrument.py",
               "common/sonic_hooks.py", "common/sonic_features.py"]
    Tracer.register(callback, data, exclude=exclude)
