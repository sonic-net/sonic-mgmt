def aio_documented_by(original):
    def wrapper(target):
        target.__doc__ = "Aio function: {original_doc}".format(original_doc=original.__doc__)
        return target

    return wrapper


def documented_by(original):
    def wrapper(target):
        target.__doc__ = original.__doc__
        return target

    return wrapper
