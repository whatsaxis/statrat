from enum import Enum

from statrat.core.logging import info, disconnect
from statrat.core.mixin import Mixin

from statrat.net.field import String
from statrat.net.packet import Packet, InboundEnum, State


class DisconnectReason(Enum):
    Quit = 'disconnect:quit'
    DisconnectLogin = 'disconnect:login'
    DisconnectPlay = 'disconnect:play'

    MOTD = 'internal:motd'


class DisconnectPacket:

    class Inbound(InboundEnum):

        DisconnectLogin = (
            0x00,
            State.Login,
            (
                ('reason', String()),
            )
        )

        DisconnectPlay = (
            0x40,
            State.Play,
            (
                ('reason', String()),
            )
        )


class DisconnectMixin(Mixin):
    """Disconnect mixin."""

    def register(self):
        """Packet listeners to do with disconnects."""

        # Disconnects from Server -> Client

        @self.proxy.listen(DisconnectPacket.Inbound.DisconnectLogin)
        @self.proxy.listen(DisconnectPacket.Inbound.DisconnectPlay)
        def disconnect_listener(packet: Packet):
            self.disconnect(
                DisconnectReason.DisconnectLogin
                if packet.packet_type == DisconnectPacket.Inbound.DisconnectLogin
                else DisconnectReason.DisconnectPlay
            )

    def disconnect(self, reason: DisconnectReason):
        """Disconnect cleanup routine."""

        if self.proxy.client_connected is False and self.proxy.server_connected is False:
            return

        # Disconnect sockets
        self.proxy.client_connected = False
        self.proxy.server_connected = False

        self.proxy.profile = None
        self.proxy.packet_handler = None

        self.proxy.shutdown(None, None)

        disconnect(f'Disconnected! [reason={ reason }]')

        # Restart server

        info('Restarting server!')
        self.proxy.start()
