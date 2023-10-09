import struct

import statrat.net.field as fields


def twos_comp(*n: int):
    """A function to convert Two's Complement signed integers to the Python ``int`` primitive."""

    return (
        struct.unpack('>i', v)
        for v in n
    )


def remove_prefix(field: 'fields.Field', data: bytes):
    """Function to remove a `VarInt()` prefix from data."""

    from statrat.net.buffer import Buffer
    from statrat.net.field import VarInt

    data = Buffer(data)

    if field.has_prefix:
        data.read(VarInt())

        return data.buffer

    return data
