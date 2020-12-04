from spytest import st

def retry_rest_api(func, *args, **kwargs):
    """
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)
    Util function to retry REST APIs.
    :param data:
    :return: output_data or False
    """
    retry_count = kwargs.pop("retry_count", 10)
    delay = kwargs.pop("delay", 3)
    ret_val = False
    for i in range(retry_count):
        st.log("Attempt {} of {}".format((i+1),retry_count))
        try:
            ret_val = func(*args, **kwargs)
            if ret_val:
                return ret_val
        except Exception:
            pass
        if retry_count != (i+1):
            st.log("waiting for {} seconds before retyring again".format(delay))
            st.wait(delay)
    return False

