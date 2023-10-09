import socket
import typing
import signal
import threading

from collections import defaultdict

from statrat.core.logging import info, success
from statrat.core.config import Config

from statrat.auth.profile import Profile
from statrat.net.packet import PacketHandler, Packet, PacketRaw, InboundEnum, OutboundEnum, Direction

from statrat.mixins.motd import MOTDMixin
from statrat.mixins.login import LoginMixin
from statrat.mixins.disconnect import DisconnectMixin, DisconnectReason


class Proxy:

    def __init__(self, cfg_path: str = 'config.yaml'):

        # Load config

        self.config = Config(cfg_path)

        # Shutdown routine

        signal.signal(signal.SIGINT, self.shutdown)

        # Sockets
        self.inbound_socket = None
        self.outbound_socket = None

        self.client_socket, self.client_address = None, None

        # State
        self.client_connected = False
        self.server_connected = False

        self.profile = None
        self.packet_handler = None

        # Packet Listeners
        #   Used to intercept certain packets in order to perform select actions.

        self.inbound_listeners = defaultdict(lambda: [])
        self.outbound_listeners = defaultdict(lambda: [])

        # Threads
        self._client_thread = None
        self._server_thread = None

        # Inject mixins

        # [!] MOTD is a special mixin as it alters the state of `connected`. It must have priority as further listener
        # calls require data received from the server.
        MOTDMixin(self)

        LoginMixin(self)
        self.dc_mixin = DisconnectMixin(self)

    def start(self):
        """Function to start the server."""

        # Create sockets

        self.inbound_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.inbound_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        self.outbound_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.outbound_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Bind outbound socket to localhost, so that client can connect to it, allowing
        # for the proxy to receive and relay the outgoing packets.

        # NOTE: Minecraft's default server port is 25565. As such, typing `localhost` into
        # the 'Direct Connect' menu connects to this.
        self.outbound_socket.bind(('127.0.0.1', 25565))

        info('Waiting for client connection! Log on to `localhost` to connect!')

        # Wait for client to connect to local socket
        # TODO Sometimes the client connects but does not think it is connected. I do not know why.
        self.outbound_socket.listen()
        self.client_socket, self.client_address = self.outbound_socket.accept()

        success('Connected to client!')

        # Initialise profile and packet handler
        self.profile = Profile()
        self.packet_handler = PacketHandler()

        self.client_connected = True

        # Relay all packets from one party to the other
        if self._client_thread is None and self._server_thread is None:

            self._client_thread = threading.Thread(target=self.accept_client)
            self._server_thread = threading.Thread(target=self.accept_server)

            self._client_thread.start()
            self._server_thread.start()

    def accept_client(self):
        """Function to accept packets from the client to relay them to the server."""

        while True:
            if not self.client_connected:
                continue

            try:
                data = self.client_socket.recv(1024)

            # When the client clicks on the Disconnect button, it forcibly closes the TCP connection.
            except ConnectionError:
                self.dc_mixin.disconnect(DisconnectReason.Quit)
                continue

            for packet_raw in self.packet_handler.recv_client(data):
                cancelled = self._call_listeners(packet_raw, direction=Direction.Outbound)

                # Check if packet is cancelled or server is not connected
                if cancelled or not self.server_connected:
                    continue

                # Send packet
                packet = packet_raw.raw

                if self.packet_handler.encryption:
                    packet = self.packet_handler.cipher.encrypt(packet)

                self.send_server(packet)

    def accept_server(self):
        """Function to accept packets from the server to relay them to the client."""

        while True:
            if not self.server_connected:
                continue

            try:
                data = self.inbound_socket.recv(1024)

            except ConnectionError:
                self.dc_mixin.disconnect(DisconnectReason.Quit)
                continue

            for packet_raw in self.packet_handler.recv_server(data):
                cancelled = self._call_listeners(packet_raw, direction=Direction.Inbound)

                # Check if the packet is cancelled or the client is not connected (for some reason)
                if cancelled or not self.client_connected:
                    continue

                # Send packet
                self.send_client(packet_raw)

    def _call_listeners(self, packet_raw: PacketRaw, direction: Direction):
        listeners = (
            self.inbound_listeners
            if direction == direction.Inbound
            else
            self.outbound_listeners
        )

        cancelled = False

        for packet_type in listeners.keys():

            # Call listeners for detected packet
            if packet_raw | packet_type:
                for listener in listeners[packet_type]:
                    # Make sure to only switch the cancelled state if it isn't already cancelled
                    should_send_packet = listener(
                        self.packet_handler.create_packet(packet_type, packet_raw.copy())
                    )

                    cancelled = (
                        not should_send_packet
                        if cancelled is False
                        else True
                    )

                # Only use first packet type that matches.
                # Otherwise, changing something like the status can result in collisions with the same packet.
                break

        return cancelled

    '''Sending'''

    def send_client(self, packet: Packet | PacketRaw | bytes):
        """Send a packet to the client."""

        try:
            if isinstance(packet, bytes):
                self.client_socket.sendall(packet)
            elif isinstance(packet, PacketRaw):
                self.client_socket.sendall(packet.raw)
            elif isinstance(packet, Packet):
                self.client_socket.sendall(packet.construct())
        except ConnectionError:
            self.dc_mixin.disconnect(DisconnectReason.Quit)

    def send_server(self, packet: Packet | PacketRaw | bytes):
        """Send a packet to the server."""

        try:
            if isinstance(packet, bytes):
                self.inbound_socket.sendall(packet)
            elif isinstance(packet, PacketRaw):
                self.inbound_socket.sendall(packet.raw)
            elif isinstance(packet, Packet):
                self.inbound_socket.sendall(packet.construct())
        except ConnectionError:
            self.dc_mixin.disconnect(DisconnectReason.Quit)

    '''Listening'''

    def listen(self, packet_type: InboundEnum | OutboundEnum):
        """Registers a callback when certain a certain packet is sent or received."""

        registered = False

        def decorator(func: typing.Callable):
            nonlocal registered

            if registered:
                return func

            if isinstance(packet_type, InboundEnum):
                self.inbound_listeners[packet_type].append(func)
            elif isinstance(packet_type, OutboundEnum):
                self.outbound_listeners[packet_type].append(func)

            registered = True

            return func

        return decorator

    def shutdown(self, _, __):
        """Function to shut down the proxy upon ``SIGINT``."""

        self.inbound_socket.close()
        self.client_socket.close()
        self.outbound_socket.close()
