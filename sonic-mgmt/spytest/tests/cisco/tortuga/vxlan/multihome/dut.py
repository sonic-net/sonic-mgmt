from spytest import st


def wait(seconds):
    """
    Wait for a specified number of seconds.
    Args:
        seconds (int): Number of seconds to wait.
    """
    st.wait(seconds)
