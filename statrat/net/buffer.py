from typing import Any

import statrat.net.field as fields
from statrat.core.helpers import remove_prefix


class Buffer:

    def __init__(self, data: bytes = None):

        if data is None:
            data = bytes()

        self.buffer = data

    def read(self, field: 'fields.Field', *, offset=False) -> Any | tuple[int, Any]:
        """
        Read a field from a buffer.

        Optional ``raw`` parameter to return the offset.
        """

        # Read field and splice buffer
        field_offset, data = field.from_bytes(self.copy())
        self.buffer = self.buffer[field_offset:]

        if not offset:
            return data

        return field_offset, data

    def read_bytes(self, field: 'fields.Field', *, offset=False, prefix=False) -> bytes | tuple[int, bytes]:
        """
        Read a field from a buffer, returning the `bytes`.

        ``offset`` parameter to return the offset.
        ``prefix`` parameter to remove `VarInt()` and prefixes (i.e. return only the data as bytes)
        """

        # Read field and splice buffer
        field_offset, _ = field.from_bytes(self.copy())

        data = self.buffer[:field_offset]
        self.buffer = self.buffer[field_offset:]

        # Remove prefix
        if not prefix and field.has_prefix:
            data = remove_prefix(field, data)

        if not offset:
            return data

        return field_offset, data

    def read_n_bytes(self, n: int) -> bytes:
        """Read a sequence of ``n`` bytes from a buffer."""

        if n > len(self.buffer):
            raise IndexError(f'Number of bytes to be read exceeds size of buffer! ({ n } > { len(self.buffer) })')

        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data

    def copy(self):
        """Returns a copy of the buffer object."""

        return Buffer(self.buffer)

    def __len__(self):
        return len(self.buffer)


class ByteStack(Buffer):

    def add(self, b: bytes):
        self.buffer += b

    def pop(self, n: int):
        return self.read_n_bytes(n)

    def get_packet_length(self):
        """
        Reads the start of the buffer as a ``VarInt()`` - the length of the incoming packet.

        Optional ``raw`` argument to return the offset too.
        """

        from statrat.net.field import VarInt

        offset, length = VarInt().from_bytes(Buffer(self.buffer))

        # You have no idea how much suffering this one line caused me.
        length += offset

        return length
