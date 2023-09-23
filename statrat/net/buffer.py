from typing import Callable, Any


class Buffer:

    def __init__(self, data: bytes = None):

        if data is None:
            data = bytes()

        self.buffer = data

    def read(self, field, *, raw=False, as_bytes=False) -> Any | tuple[int, Any]:
        """
        Read a field from a buffer.

        Optional ``raw`` parameter to return the offset as well.
        """

        # Read field and splice buffer
        offset, data = field.from_bytes(self.copy())

        if as_bytes:
            data = self.buffer[:offset]

        self.buffer = self.buffer[offset:]

        if not raw:
            return data

        return offset, data

    def read_n_bytes(self, n: int) -> bytes:
        """Read a sequence of ``n`` bytes from a buffer."""

        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data

    def copy(self):
        """Returns a copy of the buffer object."""

        return Buffer(self.buffer)

    def __len__(self):
        return len(self.buffer)


def copy_buffer(func: Callable):
    """
    A utility function to pass a copy of a buffer in the arguments of a function.

    Many fields must read other fields from a buffer, which results in counting the offset twice; once
    in the field from reading it, and once in the ``read()`` method of the ``Buffer()`` class. This decorator
    avoids this problem.
    """

    def wrapper(instance, buffer: Buffer, *args, **kwargs):
        copy = Buffer(buffer.buffer)

        return func(instance, buffer, *args, **kwargs)

    return wrapper


class ByteStack(Buffer):

    def add(self, b: bytes):
        self.buffer += b

    def pop(self, n: int):
        return self.read_n_bytes(n)

    def get_packet_length(self, *, raw=False):
        """
        Reads the start of the buffer as a ``VarInt()`` - the length of the incoming packet.

        Optional ``raw`` argument to return the offset too.
        """

        from statrat.net.field import VarInt

        offset, length = VarInt().from_bytes(Buffer(self.buffer))

        if raw:
            return offset, length

        return length
