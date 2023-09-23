import zlib

from statrat.net.buffer import Buffer
from statrat.net.field import VarInt


class Compression:

    def __init__(self, threshold: int = 256):
        self.enabled = False
        self.threshold = threshold

    def decompress(self, data: bytes, *, override=False):
        """Convert a compressed packet to decompressed form [size, id, data]."""

        if not self.enabled and not override:
            return data

        buff = Buffer(data)

        packet_size = buff.read(VarInt())
        data_offset, data_size = buff.read(VarInt(), raw=True)

        # The data length field is just a \x00 if the size of the data does not exceed
        # the compression threshold. In this case, no decompression is required.
        if data_size < self.threshold:
            data_size_computed = packet_size - data_offset - 1
            return VarInt().to_bytes(data_size_computed) + buff.read_n_bytes(data_size_computed)

        # Reading the difference of the entire packet and the size of the data length field, as the field
        # describes the UNCOMPRESSED size of the data.
        # Todo rmv
        # A = buff.read_n_bytes(packet_size - data_offset)
        A = buff.buffer
        return VarInt().to_bytes(data_size) + zlib.decompress(
            buff.read_n_bytes(packet_size - data_offset)
        )

    def compress(self, data: bytes, *, override=False):
        """Convert a canonical packet to a compressed one."""

        if not self.enabled and not override:
            return data

        buff = Buffer(data)
        packet_size = buff.read(VarInt())

        if packet_size < self.threshold:
            # In the case that packet is not compressed, a \x00 is there instead of
            # the data size field.
            return VarInt().to_bytes(packet_size + 1) + b'\x00' + buff.read_n_bytes(packet_size)

        compressed = zlib.compress(buff.buffer)
        data = VarInt().to_bytes(packet_size) + compressed

        return VarInt().to_bytes(len(data)) + data
