import json
import base64

from statrat.core.mixin import Mixin
from statrat.core.logging import info, warn, success

from statrat.net.field import String
from statrat.net.packet import Packet, State, InboundEnum, OutboundEnum

from statrat.mixins.login import LoginPacket
from statrat.mixins.disconnect import DisconnectReason


class StatusPacket:
    class Inbound(InboundEnum):

        StatusResponse = (
            0x00,
            State.Status,
            (
                ('json', String()),
            )
        )

    class Outbound(OutboundEnum):

        StatusRequest = (
            0x00,
            State.Status,
            tuple()
        )


class MOTDMixin(Mixin):
    """A mixin for applying custom MOTDs and blocking connections to the server from the server list GUI."""

    def register(self):

        @self.proxy.listen(LoginPacket.Outbound.Handshake)
        def handshake_listener(packet: Packet):
            next_state = State(packet.get_fields('next_state'))

            # Client is connecting to server
            if next_state == State.Login:
                info('Attempting to establish connection with server.')

                # Establish TCP connection with server
                self.proxy.inbound_socket.connect((
                    self.proxy.config.get('server-address'),
                    self.proxy.config.get('server-port')
                ))
                
                self.proxy.server_connected = True

                success('Connection to server established!')

            # This packet is blocked anyway - dealt with in the Login Handshake listener
            return False

        @self.proxy.listen(StatusPacket.Outbound.StatusRequest)
        def status_request_listener(_):
            # Client requests MOTD
            #   Do not allow them to connect to server - respond with custom MOTD

            filename = self.proxy.config.get('favicon')

            if not filename.endswith('.png'):
                warn(f'The favicon file `{filename}` does not seem to be in the PNG format!')

            response = {
                'version': {
                    'name': '1.8.9',
                    'protocol': 47
                },
                'players': {
                    'max': 1,
                    'online': 0
                },
                'description': {
                    'text': self.proxy.config.get('motd')
                },
                'favicon': MOTDMixin.favicon_from_file(filename)
            }

            motd_packet = self.proxy.packet_handler.write(
                StatusPacket.Inbound.StatusResponse,
                json.dumps(response)
            )

            self.proxy.send_client(motd_packet)
            info('Sent MOTD to client')

            self.proxy.dc_mixin.disconnect(DisconnectReason.MOTD)

            return False

    @staticmethod
    def favicon_from_file(filename: str):
        """Convert PNG image file to MC favicon format."""

        with open(filename, 'rb') as icon_file:
            data_encoded = base64.b64encode(icon_file.read()).decode('utf-8')
            return f'data:image/png;base64,{ data_encoded }'
