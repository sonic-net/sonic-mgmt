# this file is imported from framework and hence
# we can't import framework API globally here
# import them with in functions
#from spytest import st

def apis_register():
    from apis.common.hooks import Hooks
    return Hooks()

def apis_instrument(scope, data):
    from apis.common.instrument import apis_instrument as apis_instrument_impl
    return apis_instrument_impl(scope, data)
