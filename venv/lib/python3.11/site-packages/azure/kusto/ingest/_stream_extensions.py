import io

from typing import IO, AnyStr


def read_until_size_or_end(stream: IO[AnyStr], size: int) -> io.BytesIO:
    pos = 0
    result = io.BytesIO()
    while True:
        try:
            returned = stream.read(size - pos)
            pos += len(returned)
            result.write(returned)

            if len(returned) == 0 or pos == size:
                result.seek(0, io.SEEK_SET)
                return result

        except BlockingIOError:
            continue


class ChainStream(io.RawIOBase):
    """
    https://stackoverflow.com/questions/24528278/stream-multiple-files-into-a-readable-object-in-python
    """

    def __init__(self, streams):
        self.leftover = b""
        self.stream_iter = iter(streams)
        try:
            self.stream = next(self.stream_iter)
        except StopIteration:
            self.stream = None

    def readable(self):
        return True

    def _read_next_chunk(self, max_length):
        # Return 0 or more bytes from the current stream, first returning all
        # leftover bytes. If the stream is closed returns b''
        if self.leftover:
            return self.leftover
        elif self.stream is not None:
            return self.stream.read(max_length)
        else:
            return b""

    def readinto(self, b):
        buffer_length = len(b)
        chunk = self._read_next_chunk(buffer_length)
        while len(chunk) == 0:
            # move to next stream
            if self.stream is not None:
                self.stream.close()
            try:
                self.stream = next(self.stream_iter)
                chunk = self._read_next_chunk(buffer_length)
            except StopIteration:
                # No more streams to chain together
                self.stream = None
                return 0  # indicate EOF
        output, self.leftover = chunk[:buffer_length], chunk[buffer_length:]
        b[: len(output)] = output
        return len(output)


def chain_streams(streams, buffer_size=io.DEFAULT_BUFFER_SIZE):
    """
    Chain an iterable of streams together into a single buffered stream.
    Usage:
        def generate_open_file_streams():
            for file in filenames:
                yield open(file, 'rb')
        f = chain_streams(generate_open_file_streams())
        f.read()
    """
    return io.BufferedReader(ChainStream(streams), buffer_size=buffer_size)
