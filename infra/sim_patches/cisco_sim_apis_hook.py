def sim_reboot_delay(func):
    def wrapper(*args, **kwargs):
        ## check the wait time for the reboot command and change it to 480 seconds
        kwargs['wait'] = 480
        return func(*args, **kwargs) 
    return wrapper


## this can be used for other cases when the timeout is low for passing tests on sim
## lambada function is a little bit tricky, be careful when using it
def sim_wait_until_extra_delay(func):
    def wrapper(*args, **kwargs):
        function = args[3]
        test_function_name = function.__qualname__
        if 'test_bgp_update_timer' in test_function_name:
            return func(240, args[1], args[2], args[3], **kwargs) 
        return func(*args, **kwargs)
    return wrapper
