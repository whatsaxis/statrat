import struct


def twos_comp(*n: int):
    """A function to convert Two's Complement signed integers to the Python ``int`` primitive."""

    return (
        struct.unpack('>i', v)
        for v in n
    )

