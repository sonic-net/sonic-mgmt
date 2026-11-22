"""
Connect and disconnect shared by the console classes that run one pexpect child.
"""
import signal
import threading

import pexpect


class ConsoleConnectTimeout(pexpect.TIMEOUT, TimeoutError):
    """connect() did not finish within timeout_s; the child was killed without writing."""
    pass


def _kill(child):
    # SIGKILL wakes an expect() blocked in another thread; close() alone does not.
    child.kill(signal.SIGKILL)
    child.close(force=True)


class PexpectConsoleConn(object):
    """
    Connect and disconnect for the console classes that run one pexpect child: ConserverConsoleConn.
    A class supplies _connect(), which starts the child with _spawn() and logs in, and
    _graceful_disconnect(), its regular disconnect.
    """

    def __new__(cls, *args, **kwargs):
        self = super(PexpectConsoleConn, cls).__new__(cls)
        # Guards _connected and _child: disconnect() may come from another thread at any point,
        # even while connecting. Set here, so they exist before any constructor runs.
        self._state_lock = threading.Lock()
        self._connected = False
        self._child = None
        return self

    def connect(self, timeout_s=None):
        """
        Connect, or connect again after disconnect(), with the class's _connect(). Connecting
        while connected raises RuntimeError, and a failed connect is as if it never happened:
        the child is killed and the object is not connected. With timeout_s, a connect still
        running after timeout_s seconds is closed without writing to the line
        (disconnect(graceful=False)) and raises ConsoleConnectTimeout.
        """
        with self._state_lock:
            if self._connected:
                raise RuntimeError("Already connected; call disconnect() first")
            self._connected = True
        timed_out = threading.Event()
        timer = None
        if timeout_s is not None:
            def time_out():
                timed_out.set()
                self.disconnect(graceful=False)
            timer = threading.Timer(timeout_s, time_out)
            timer.start()
        try:
            self._connect()
        except Exception as e:
            self._stop_timer(timer)
            # A failed constructor never returns the object for anyone to disconnect.
            self.disconnect(graceful=False)
            if timed_out.is_set():
                raise ConsoleConnectTimeout("connect() did not finish within timeout_s") from e
            raise
        self._stop_timer(timer)
        if timed_out.is_set():
            # The timer fired just as the connect finished: a timeout all the same.
            raise ConsoleConnectTimeout("connect() did not finish within timeout_s")

    def _stop_timer(self, timer):
        """Stop the connect() timer, waiting for it if it is firing."""
        if timer is not None:
            timer.cancel()
            timer.join()

    def _spawn(self, command, args=(), **kwargs):
        """
        Helper used in ConserverConsoleConn._connect(). It performs the same function as
        pexpect.spawn(), with the addition of keeping the child, so that disconnect() can kill it
        at any time, even mid-connect; once disconnected, it kills the child and raises pexpect.EOF.
        """
        child = pexpect.spawn(command, list(args), **kwargs)
        with self._state_lock:
            if not self._connected:
                _kill(child)
                raise pexpect.EOF("Disconnected; nothing is started until the next connect()")
            self._child = child
        return child

    def disconnect(self, graceful=True):
        """
        graceful=False kills the child at once without writing to the line, is safe from another
        thread even while connecting, and starts nothing new until the next connect().
        graceful=True first runs the class's regular disconnect, _graceful_disconnect(). Either
        way, the child does not stay running.
        """
        with self._state_lock:
            self._connected = False
        try:
            if graceful:
                self._graceful_disconnect()
        finally:
            with self._state_lock:
                child, self._child = self._child, None
            if child is not None:
                _kill(child)
