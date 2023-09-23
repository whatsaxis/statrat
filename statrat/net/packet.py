from enum import Enum

import statrat.net.field as field
from statrat.net.buffer import Buffer, ByteStack
from statrat.net.compress import Compression

from statrat.core.crypto import AESCipher
from statrat.core.error import IncorrectPacketLengthError


class PacketType:

    class Inbound(Enum):
        Disconnect = (
            0x00,
            (
                ('reason', field.String()),
            )
        )

        EncryptionRequest = (
            0x01,
            (
                ('server_id', field.String()),
                ('public_key', field.Array(field.Byte())),
                ('verify_token', field.Array(field.Byte()))
            )
        )

        LoginSuccess = (
            0x02,
            (
                ('uuid', field.String()),
                ('username', field.String())
            )
        )

        SetCompression = (
            0x03,
            (
                ('threshold', field.VarInt()),
            )
        )

    class Outbound(Enum):

        # TODO RMV
        PlayerSession = (
            0x06,
            tuple()
        )

        Handshake = (
            0x00,
            (
                ('protocol_version', field.VarInt()),
                ('server_address', field.String()),
                ('server_port', field.UnsignedShort()),
                ('next_state', field.VarInt())
            )
        )

        LoginStart = (
            0x00,
            (
                ('username', field.String()),
            )
        )

        EncryptionResponse = (
            0x01,

            # Dynamic array field is NOT used here, as the length of the field is
            # not encrypted, but the data of the field is (why)!

            # Thankfully, the size of both fields is constant (128 bytes) due to PKCS#1 v1.5 padding.

            (
                ('shared_secret_length', field.VarInt()),
                ('shared_secret', field.Array(field.UnsignedByte(), 128)),

                ('verify_token_length', field.VarInt()),
                ('verify_token', field.Array(field.UnsignedByte(), 128))
            )
        )


class PacketRaw:
    """Bare-bones container for information about arbitrary packets."""

    def __init__(self, data: bytes, canonical: bytes = None):

        # Canonical form is only defined if compression is enabled. Otherwise, remains `None`.

        # Processing
        self.raw = data
        self.canonical = canonical

        buff = Buffer(
            canonical
            if canonical is not None
            else data
        )

        # Extract length and ID
        self.length = buff.read(field.VarInt())
        id_size, self.packet_id = buff.read(field.VarInt(), raw=True)

        # Dump data
        if not len(buff) == self.length - id_size:
            raise IncorrectPacketLengthError(
                f'Length field ({ self.length - id_size }) does not match data ({ len(buff) })!'
                + f'[canonical={ canonical is not None }, buff_size={ len(buff) }, length - id={ self.length - id_size }, id={ self.packet_id }]'
            )

        self.data = buff

    def __or__(self, other: PacketType.Inbound | PacketType.Outbound):
        return self.packet_id == other.value[0]

    def __repr__(self):
        data = self.data.buffer.hex()

        if len(data) > 10:
            data = data[:10] + '...'

        return f'PacketRaw[id={ field.VarInt().to_bytes(self.packet_id).hex() }, size={ self.length }, data={ data }]'


class State(Enum):
    Status = 1
    Login = 2
    Play = 3


class PacketHandler:
    """A handler for incoming and outgoing packets."""

    def __init__(self, cipher: AESCipher):

        self.cipher = cipher

        # Compression
        self.compression = Compression()

        # State regarding the handshake and encryption process
        self.state = State.Status
        self.encryption = False

        # Byte stacks
        #   As the Minecraft packet length varies, a stack data structure is used to await the arrival
        #   of a full packet before reading it. This works by continually checking the first element of
        #   the ``bytes`` object to obtain the length, and asserting whether the length of the byte stack ≥ the length
        #   of the packet. In the case that the byte stack is empty, the operation is, again, skipped.
        #
        #   It is necessarily true that the first byte of the byte stack will be a `length` field, and that of an
        #   incomplete packet, as any full packets will have been processed and popped off the stack in previous
        #   calls.

        self.inbound_stack = ByteStack()
        self.outbound_stack = ByteStack()

    """Processing"""

    def _recv(self, data: bytes, stack: ByteStack):

        # Stacks
        stack.add(data)

        # Read packets
        while len(stack) >= stack.get_packet_length() != 0 and len(stack) > 0:

            len_size, size = stack.get_packet_length(raw=True)

            # TODO RMV
            if size == 0:
                continue

            raw = stack.read_n_bytes(len_size + size)

            # print('Attempting to decompress', raw)

            # TODO CHeck if this is right.. eww
            try:
                canonical = self.compression.decompress(raw)
                packet = PacketRaw(raw, canonical=canonical)
            except Exception as e:
                raise Exception(f'Failed to read packet { packet }, data={ raw }')

            yield packet

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
            packet_type: PacketType.Inbound | PacketType.Outbound | int,
            packet_raw: PacketRaw
    ):
        """Read the raw data fields from a raw packet."""

        packet_id, fields = packet_type.value
        buffer = Buffer(packet_raw.data.buffer)

        data = {}

        for f in fields:
            field_name, field_type = f
            data[field_name] = buffer.read(field_type)

        return data

    @staticmethod
    def read_bytes(
            packet_type: PacketType.Inbound | PacketType.Outbound,
            packet_raw: PacketRaw,
            *, prefix=True
    ):
        """
        Read the raw data fields from a raw packet.

        Returns ``bytes`` instead of Python primitives.
        """

        packet_id, fields = packet_type.value
        buffer = Buffer(packet_raw.data.buffer)

        data = {}

        for f in fields:
            field_name, field_type = f

            if not prefix:
                data[field_name] = field.remove_prefix(
                    field=field_type,
                    data=buffer.read(field_type, as_bytes=True)
                )

                continue

            data[field_name] = buffer.read(field_type, as_bytes=True)

        return data

    def write(self, packet_type: PacketType.Inbound | PacketType.Outbound, *data):
        """
        Write data into a Minecraft packet.

        This additionally applies AES encryption, if applicable.
        """

        data = list(data)
        packet_id, fields = packet_type.value

        # Write fields
        b = field.VarInt().to_bytes(packet_id)

        for f in fields:
            field_name, field_type = f

            # Will ALWAYS be 1 value long
            b += field_type.to_bytes(data.pop(0))

        # Prepend length
        length = field.VarInt().to_bytes(len(b))
        packet = length + b

        # TODO I THINK they compress before encrypting? We shall see.

        # Compression
        packet = self.compression.compress(packet)

        # Encryption
        if self.encryption:
            return self.cipher.encrypt(packet)

        return packet
