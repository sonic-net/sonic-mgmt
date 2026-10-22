"""Exclusive locking for one Ranking output directory."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat


def _root(value):
    path = Path(os.path.abspath(value))
    if (path.is_symlink() or not path.is_dir() or
            os.path.realpath(str(path)) != str(path)):
        raise ValueError('output root must be a real directory')
    return path


@contextmanager
def exclusive(output_root):
    path = _root(output_root)
    descriptor = os.open(path / '.ranking.lock',
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('unsafe Ranking lock file')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(
                'another Ranking command is already active for this directory') from error
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
