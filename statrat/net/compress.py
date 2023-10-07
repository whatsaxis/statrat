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
        uncompressed_data_offset, uncompressed_data_size = buff.read(VarInt(), raw=True)

        data = buff.read_n_bytes(packet_size - uncompressed_data_offset)

        # [!] Packet is below compression threshold
        #   A \x00 byte is placed between the size and data fields, which means it is below
        #   the server compression threshold. This is what the below condition verifies.

        if uncompressed_data_size == 0 or packet_size < self.threshold:
            return VarInt().to_bytes(len(data)) + data

        # [!] Packet is compressed
        uncompressed_data = zlib.decompress(data)
        packet = VarInt().to_bytes(uncompressed_data_size) + uncompressed_data

        return packet

    def compress(self, data: bytes, *, override=False):
        """Convert a canonical packet to a compressed one."""

        if not self.enabled and not override:
            return data

        buff = Buffer(data)

        packet_size = buff.read(VarInt())

        # [!] Not compressed
        if packet_size < self.threshold:
            return VarInt().to_bytes(packet_size + 1) + b'\x00' + buff.read_n_bytes(packet_size)

        # [!] Compressed
        compressed = zlib.compress(buff.buffer)
        data = VarInt().to_bytes(packet_size) + compressed

        return VarInt().to_bytes(len(data)) + data
