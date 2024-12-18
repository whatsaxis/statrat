import math
import uuid as uuid_lib
import struct

from statrat.net.buffer import Buffer
from statrat.core.helpers import twos_comp

from typing import Any


"""Field Definition"""


class Field:

    format: str
    has_prefix: bool = False

    def from_bytes(self, buffer: Buffer) -> tuple[int, Any]:
        fmt_size = struct.calcsize(self.format)

        return fmt_size, struct.unpack(
            self.format,
            buffer.read_n_bytes(fmt_size)
        )[0]

    def to_bytes(self, *data):
        return struct.pack(
            self.format,
            data[0]
        )

    def __repr__(self):
        return self.__class__.__name__


"""Helpers"""


# Bit masks for obtaining the segment and continue bits of VarInt and VarLong.
# For any byte, the MSB represents whether the next byte is part of the value as well,
# and the 7 remaining bits are for the value assigned to that numerical offset.

SEGMENT_BITS = 0x7F
CONTINUE_BIT = 0x80


def read_var(data: bytes, max_pos: int):
    """
    Function to read a numerical value from a list of raw bytes in the Minecraft format.
    Returns the number of bytes to offset the bytes array, and the number.
    """

    value = 0
    position = 0

    for b in data:

        # Add the numerical value of the byte and offset it to its intended position
        value |= (b & SEGMENT_BITS) << position

        # We do not account for the segment bit, as it is not included in the value
        position += 7

        # No next byte (MSB = 0); break
        if b & CONTINUE_BIT == 0:
            break

        # Number of bytes > specification maximum; Yikes.
        if position >= max_pos:
            raise RuntimeError('Number of raw bytes exceeds the maximum number of bytes for this data type!')

    return position // 7, value


def write_var(value: int):
    """
    Function to write an integer value as the Minecraft numerical `Var` format.
    """

    b = bytes()

    while True:

        # Return value if there are no more bits outside the segment bit
        if value & ~SEGMENT_BITS == 0:
            b += (value & SEGMENT_BITS).to_bytes(byteorder='big')
            return b

        # Continue bit + values
        b += (CONTINUE_BIT | value & SEGMENT_BITS).to_bytes(byteorder='big')

        # Truncate last bits
        value >>= 7


"""Protocol Implementations"""


class Bool(Field):
    format = '>?'


class Byte(Field):
    format = '>b'


class UnsignedByte(Field):
    format = '>B'


class Short(Field):
    format = '>h'


class UnsignedShort(Field):
    format = '>H'


class Int(Field):
    format = '>i'


class Long(Field):
    format = '>l'


class Float(Field):
    format = '>f'


class Double(Field):
    format = '>d'


class VarInt(Field):

    def from_bytes(self, buffer: Buffer):
        return read_var(buffer.buffer, 32)

    def to_bytes(self, value: int, *rest):
        return write_var(value)


class VarLong(Field):

    def from_bytes(self, buffer: Buffer):
        return read_var(buffer.buffer, 64)

    def to_bytes(self, value: int, *rest):
        return write_var(value)


class String(Field):

    has_prefix = True

    # There are additional subtypes derived from String: Chat and Identifier, with varying
    # maximum lengths. These are simply semantic, and String can be used in their place.

    def from_bytes(self, buffer: Buffer):

        # Prefixed with its length as a VarInt
        len_size, length = buffer.read(VarInt(), offset=True)

        # Obtain string payload
        payload = buffer.read_n_bytes(length)

        return len_size + length, payload.decode('utf-8')

    def to_bytes(self, s: str, *rest):

        # Bytes aren't always a 1-1 to characters!
        b = bytes(s, encoding='utf-8')

        return \
            VarInt().to_bytes(len(b)) + \
            b


class UUID(Field):

    def from_bytes(self, buffer: Buffer):
        return 16, str(uuid_lib.UUID(bytes=buffer.read_n_bytes(16))).replace('-', '')

    def to_bytes(self, uuid: str, *rest):

        # Dashes NOT included, as they are traditionally
        # not present in packets.
        return uuid_lib.UUID(uuid).bytes


class Position(Field):

    # Pre 1.14, Position fields were split into 3 parts for over a 64-bit unsigned long:
    #
    #    x: 26 bits
    #    y: 12 bits
    #    z: 26 bits
    #
    # In newer versions, the Z and Y coordinates are swapped in order, with number
    # of bits remaining the same.

    def from_bytes(self, buffer: Buffer):
        unsigned_long = int.from_bytes(buffer.read_n_bytes(8), byteorder='big')

        return 8, twos_comp(
            unsigned_long >> (64 - 26),     # Shift value 38 positions, leaving only the X coordinate
            (unsigned_long >> 26) & 0xFFF,  # Bitmask for the first 12 bits after truncating X
            unsigned_long << 38 >> 38       # Remove all other bits, shifting back to preserve magnitude
        )

    def to_bytes(self, x: int, y: int, z: int, *rest):
        return (
            x.to_bytes(26, 'big', signed=True) +
            y.to_bytes(12, 'big', signed=True) +
            z.to_bytes(26, 'big', signed=True)
        )


class Angle(Field):

    # A signed or unsigned byte (does not matter; the angle remains the same) representing
    # rotation in 1/256ths of a full turn. Unsigned is used in this implementation.

    def from_bytes(self, buffer: Buffer):
        unsigned_byte = buffer.read(UnsignedByte())
        return 1, unsigned_byte * 2 * math.pi

    def to_bytes(self, angle: int, *rest):
        return angle.to_bytes(1, 'big')


"""
Transform Classes

Not formally in the MC protocol, but common patterns in many packets.
"""


class Container(Field):
    """A container field to hold two or more fields together."""

    has_prefix = False

    def __init__(self, *fields: tuple[str, Field]):
        self.fields = fields

    def from_bytes(self, buffer: Buffer):
        offset, values = 0, []

        for f in self.fields:
            # TODO At some point incorporate the name thing with the read_field()
            off, data = buffer.read(f[1], offset=True)

            offset += off
            values.append(data)

        return offset, tuple(values)

    def to_bytes(self, data, *rest):
        b = bytes()

        for i, (name, field) in enumerate(self.fields):
            b += field.to_bytes(data[i])

        return b

    def __repr__(self):
        return f'Container[{ ", ".join(repr(f[1]) for f in self.fields) }]'


class Optional(Field):
    """Optional class, allowing for optional fields."""

    # While officially, Optional fields do not have a preceding byte in the types specification
    # to signify that the field is present, although in practice, they do.

    has_prefix = True

    def __init__(self, field: Field):
        self.field = field

    def from_bytes(self, buffer: Buffer):
        status_offset, status = buffer.read(Bool(), offset=True)

        if status is True:
            # If status is True, and there is indeed a next byte, obtain it
            offset, value = buffer.read(self.field, offset=True)
            return offset + status_offset, value

        return status_offset, False

    def to_bytes(self, value: Any, *rest):

        # Value is not present
        if value is False:
            return Bool().to_bytes(False)

        return Bool().to_bytes(True) + self.field.to_bytes(value)

    def __repr__(self):
        return f'Optional[{ repr(self.field) }]'


class Array(Field):
    """An array of a specific field."""

    has_prefix = True

    def __init__(self, field: Field, qty: int = None):
        self.field = field

        # If `qty` is None upon initialisation, it will be read from a VarInt field
        # indicating the length of the array when the `from_bytes()` method is called
        self.qty = qty

    def from_bytes(self, buffer: Buffer):
        """Read a set number of fields and compact them as an array."""

        offset = 0
        reset_qty = False

        # Get quantity, if it isn't provided
        if self.qty is None:
            reset_qty = True
            offset, self.qty = buffer.read(VarInt(), offset=True)

        values = []

        for _ in range(self.qty):
            size, value = buffer.read(self.field, offset=True)

            offset += size
            values.append(value)

        # Reading an Array() sets its quantity.
        # It is a lot more efficient and clean to simply put the size back to its original state, preserving the initial
        # parameters of the definition, than to make a deep copy every time.
        if reset_qty:
            self.qty = None

        return offset, tuple(values)

    def to_bytes(self, array: list | tuple, *rest):

        # Length of array appended first as a VarInt.
        # If `qty` is defined, meaning it is known from context, no such VarInt is prepended.
        b = VarInt().to_bytes(len(array)) \
            if self.qty is None \
            else bytes()

        for i in array:
            b += self.field.to_bytes(i)

        return b

    def __repr__(self):
        return f'Array[{ repr(self.field) }]'
