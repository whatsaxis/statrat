import os

from enum import Enum
from typing import Any

import statrat.net.field as fields

from statrat.net.buffer import Buffer, ByteStack
from statrat.net.compress import Compression

from statrat.core.crypto import AESCipher
from statrat.core.helpers import remove_prefix
from statrat.core.error import IncorrectPacketLengthError, IncompletePacketError, MissingHandlerError


class State(Enum):
    Status = 1
    Login = 2

    # Numbers are arbitrary for the below.
    # Handshake packet can only switch state to Status or Login, and
    # Login Success changes always changes the state to Play.

    Handshaking = -1
    Configuration = -2
    Play = -3


class Direction(Enum):
    Inbound = 'in'
    Outbound = 'out'


class InboundEnum(Enum):
    """Inbound enumeration base class."""


class OutboundEnum(Enum):
    """Outbound enumeration base class."""


class PacketRaw:
    """Bare-bones container for information about arbitrary packets."""

    def __init__(self, data: bytes, canonical: bytes = None, handler: 'PacketHandler' = None):

        # Canonical form is only defined if compression is enabled. Otherwise, remains `None`.

        # Processing
        self.raw = data
        self.canonical = canonical

        self.handler = handler

        buff = Buffer(
            canonical
            if canonical is not None
            else data
        )

        # Extract length and ID
        self.length = buff.read(fields.VarInt())
        id_size, self.packet_id = buff.read(fields.VarInt(), offset=True)

        # Dump data
        if not len(buff) == self.length - id_size:
            raise IncorrectPacketLengthError(
                f'Length field ({ self.length - id_size }) does not match data ({ len(buff) })!'
            )

        self.data = buff

    def copy(self):
        return PacketRaw(self.raw, canonical=self.canonical, handler=self.handler)

    def __or__(self, other: InboundEnum | OutboundEnum):
        return (
            self.packet_id == other.value[0] and
            (
                    (self.handler is not None and self.handler.state == other.value[1]) or
                    self.handler is None
            )
        )

    def __repr__(self):
        data = self.data.buffer.hex()

        if len(data) > 10:
            data = data[:10] + '...'

        return f'PacketRaw[id={ fields.VarInt().to_bytes(self.packet_id).hex() }, size={ self.length }, data={ data }]'


class Packet:
    """Specialised container about a specific packet."""

    def __init__(
            self,
            packet_type: InboundEnum | OutboundEnum,
            data: bytes | PacketRaw | None = None,
            handler: 'PacketHandler' = None
    ):
        if handler is None:
            raise MissingHandlerError()

        self.raw = data
        self.packet_type = packet_type

        self.handler = handler

        self._packet_fields: dict[str, fields.Field] = {
            name: field_type
            for name, field_type in self.packet_type.value[2]
        }

        if data is None:
            fields_empty = {
                f: None
                for f in self.packet_type.value[2].keys()
            }

            self.fields_real = fields_empty.copy()
            self.fields_byte = fields_empty.copy()

            return

        packet_raw = data
        if isinstance(data, bytes):
            packet_raw = PacketRaw(data)

        # Load fields
        self.fields_real = PacketHandler.read(packet_type, packet_raw)
        self.fields_byte = PacketHandler.read_bytes(packet_type, packet_raw)

    def get_fields(self, *field_names: str):
        """Get the primitive values of select fields."""

        if len(field_names) == 1:
            return self.fields_real[field_names[0]]

        return tuple(
            self.fields_real[f]
            for f in field_names
        )

    def get_bytes(self, *field_names: str, prefix=True):
        """Get the bytes representation of select fields."""

        # Destructuring would set a variable to a tuple containing the value
        # if there is only one value.
        if len(field_names) == 1:
            field_name = field_names[0]
            data = self.fields_byte[field_name]

            if prefix:
                return data

            return remove_prefix(
                field=self._packet_fields[field_name],
                data=data
            )

        # More than 1 value
        if prefix:
            return tuple(
                self.fields_byte[f]
                for f in field_names
            )

        return tuple(
            remove_prefix(
                field=self._packet_fields[f],
                data=self.fields_byte[f]
            )
            for f in field_names
        )

    def write_field(self, field_name: str, data: Any):
        """Writes a value to a certain field."""

        self.fields_real[field_name] = data
        self.fields_byte[field_name] = self._packet_fields[field_name].to_bytes(data)

    def write_bytes(self, field_name: str, data: bytes):
        """Writes to the byte representation of a certain field."""

        self.fields_byte[field_name] = data
        self.fields_real[field_name] = self._packet_fields[field_name].from_bytes(Buffer(data))

    def construct(self):
        """Converts a `Packet()` object to bytes."""

        if not all(v is not None for v in self.fields_real.values()):
            raise IncompletePacketError()

        return self.handler.write(
            self.packet_type,
            *self.fields_real.values()
        )

    def __repr__(self):
        packet_type_fields = self.packet_type.value[2]

        field_data = ''
        for i, (name, value) in enumerate(self.fields_real.items()):
            field_data += f'\n        { packet_type_fields[i][1] } { name }={ value }'

        return f'''Packet[
    type={ self.packet_type },
    size={ self.raw.length },
    fields=[{ field_data }\n    ]\n]'''


class PacketHandler:
    """A handler for incoming and outgoing packets."""

    def __init__(self):
        self.cipher = AESCipher(secret=os.urandom(16))

        # Compression
        self.compression = Compression()

        # State regarding the handshake and encryption process
        self.state = State.Handshaking
        self.encryption = False

        # Byte stacks
        #   As the packets may not arrive all at once, a stack data structure is used to await the arrival
        #   of a full packet before reading it. This works by continually checking the first element of
        #   the ``bytes`` object to obtain the length, and asserting whether the length of the byte stack ≥ the length
        #   of the packet.

        self.inbound_stack = ByteStack()
        self.outbound_stack = ByteStack()

    """Processing"""

    def _recv(self, data: bytes, stack: ByteStack):

        # Stacks
        stack.add(data)

        # Read packets
        while len(stack) >= stack.get_packet_length() and len(stack) > 0:
            raw = stack.read_n_bytes(stack.get_packet_length())

            canonical = self.compression.decompress(raw)
            yield PacketRaw(raw, canonical=canonical, handler=self)

    def recv_client(self, data: bytes):

        # Encryption is not dealt with here because... it can't be.
        # The client is tricked into thinking it is joining an offline-mode server, so
        # that encryption is disabled, and the proxy can act as though it is the client
        # encrypting packets.

        # If this was not the case, it would be impossible to decrypt both incoming and outgoing packets.

        yield from self._recv(data, self.outbound_stack)

    def recv_server(self, data: bytes):
        if self.encryption:
            data = self.cipher.decrypt(data)

        yield from self._recv(data, self.inbound_stack)

    """Utility"""

    @staticmethod
    def read(
            packet_type: InboundEnum | OutboundEnum | int,
            packet_raw: PacketRaw
    ) -> dict[str, Any]:
        """Read the raw data fields from a raw packet."""

        packet_id, _, packet_fields = packet_type.value
        buffer = Buffer(packet_raw.data.buffer)

        data = {}

        for f in packet_fields:
            field_name, field_type = f
            data[field_name] = buffer.read(field_type)

        return data

    @staticmethod
    def read_bytes(
            packet_type: InboundEnum | OutboundEnum,
            packet_raw: PacketRaw,
            *, prefix=True
    ):
        """
        Read data fields as bytes from a raw packet.

        Returns ``bytes`` instead of Python primitives.
        """

        packet_id, _, packet_fields = packet_type.value
        buffer = Buffer(packet_raw.data.buffer)

        data = {}

        for f in packet_fields:
            field_name, field_type = f
            data[field_name] = buffer.read_bytes(field_type, prefix=prefix)

        return data

    def write(self, packet_type: InboundEnum | OutboundEnum, *data):
        """
        Write data into a Minecraft packet.

        This additionally applies AES encryption and zlib compression, if applicable.
        """

        data = list(data)
        packet_id, _, packet_fields = packet_type.value

        # Write fields
        b = fields.VarInt().to_bytes(packet_id)

        for f in packet_fields:
            field_name, field_type = f

            # Will ALWAYS be 1 value long
            b += field_type.to_bytes(data.pop(0))

        # Prepend length
        length = fields.VarInt().to_bytes(len(b))
        packet = length + b

        # Compression
        packet = self.compression.compress(packet)

        # Encryption
        #   Only encrypt outbound packets.
        if self.encryption and isinstance(packet_type, OutboundEnum):
            return self.cipher.encrypt(packet)

        return packet

    def create_packet(self, packet_type: InboundEnum | OutboundEnum, data: bytes | PacketRaw | None = None,):
        return Packet(packet_type, data, handler=self)
