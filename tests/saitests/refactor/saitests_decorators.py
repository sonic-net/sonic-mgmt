
import functools

from qos_helper import log_message
from counter_collector import CounterCollector, initialize_diag_counter, capture_diag_counter, summarize_diag_counter


def saitests_decorator(func, param=None, enter=True, exit=True):
    """
    General decorator for executing debug functions at the entry and/or exit of a method,
    and passing specific parameters to the debug functions.
    
    :param func: The debug function to execute
    :param param: Parameters to pass to the debug function
    :param enter: Whether to execute the debug function at the method entry
    :param exit: Whether to execute the debug function at the method exit
    """
    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            if enter:
                func(self, method.__name__, param, *args, **kwargs)
            result = method(self, *args, **kwargs)
            if exit:
                func(self, method.__name__, param, result, *args, **kwargs)
            return result
        return wrapper
    return decorator


def step_banner(self, method_name, param, *args, **kwargs):
    log_message(f'Entering {method_name} with args={args} kwargs={kwargs}', to_stderr=True)


def step_result(self, method_name, param, result, *args, **kwargs):
    if result is None:
        log_message(f'Exiting {method_name} with no return value', to_stderr=True)
    else:
        log_message(f'Exiting {method_name} with result={result}', to_stderr=True)


def diag_counter(self, method_name, param, *args, **kwargs):
    if param == 'initialize':
        initialize_diag_counter(self)
    elif param == 'capture':
        capture_diag_counter(self, method_name)
    elif param == 'summarize':
        summarize_diag_counter(self)
