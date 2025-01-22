from functools import wraps


def support_ignore_loganalyzer(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        """
        try to fetch loganalyzer instances from kwargs:
        if ignore_loganalyzer is not passed, do nothing but execute the decorated function.
        if ignore_loganalyzer is passed, to avoid 'unexpected keyword argument error',
            delete the ignore_loganalyzer from kwargs so that it would not be passed to the decorated function,
            and set ignore_loganalyzer markers before and after the decorated function on all log analyzer instances.
        """

        # Need to remove parameter 'ignore_loganalyzer' from kwargs
        # Otherwise it breaks the decorated func
        # Since the parameter 'ignore_loganalyzer' is not defined in the signature
        loganalyzer = kwargs.pop('ignore_loganalyzer', {})

        if loganalyzer:
            for _, dut_loganalyzer in list(loganalyzer.items()):
                dut_loganalyzer.add_start_ignore_mark()

        res = func(*args, **kwargs)

        if loganalyzer:
            for _, dut_loganalyzer in list(loganalyzer.items()):
                dut_loganalyzer.add_end_ignore_mark()

        return res

    return decorated
