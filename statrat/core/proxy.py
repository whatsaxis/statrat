import os
import uuid
import socket
import signal
import threading

from statrat.core.crypto import AESCipher, PublicKey
from statrat.core.logging import info, success, error
from statrat.core.config import Config

from statrat.net.packet import PacketHandler, PacketType, State

from statrat.auth.request import authenticate, ERR_MAP
from statrat.auth.session import get_access_token, get_uuid


class Proxy:

    def __init__(self, cfg_path: str = 'config.yaml'):

        # Load config

        self.config = Config(cfg_path)

        # Shutdown routine

        signal.signal(signal.SIGINT, self.shutdown)

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
        self.outbound_socket.listen()
        self.client_socket, self.client_address = self.outbound_socket.accept()

        success('Connected to client!')
        info('Attempting to establish connection with server.')

        # Establish TCP connection with server
        self.inbound_socket.connect((
            self.config.get('server-address'),
            self.config.get('server-port')
        ))

        success('Connection to server established!')

        # State

        self.username = None
        self.uuid = None

        self.cipher = AESCipher(secret=os.urandom(16))
        self.packet_handler = PacketHandler(self.cipher)

        # Relay all packets from one party to the other
        client_thread = threading.Thread(target=self.accept_client)
        server_thread = threading.Thread(target=self.accept_server)

        client_thread.start()
        server_thread.start()

    def accept_client(self):
        """Function to accept packets from the client to relay them to the server."""

        while True:
            data = self.client_socket.recv(1024)

            for packet_raw in self.packet_handler.recv_client(data):

                # Handshake
                if self.packet_handler.state == State.Status and packet_raw | PacketType.Outbound.Handshake:
                    data = PacketHandler.read(PacketType.Outbound.Handshake, packet_raw)

                    protocol_version, server_address, server_port, next_state = (
                        data['protocol_version'], data['server_address'],
                        data['server_port'], data['next_state']
                    )

                    info(f'Handshake packet received! State: [{ self.packet_handler.state } -> { State(next_state) }]')

                    # The server address field is always 127.0.0.1, as the client is connecting to a local socket.
                    # This must be edited, as servers may check this and not allow the proxy to connect.

                    handshake = self.packet_handler.write(
                        PacketType.Outbound.Handshake,

                        protocol_version,
                        self.config.get('server-address'),
                        server_port,
                        next_state
                    )

                    self.inbound_socket.sendall(handshake)

                    # Reverse Enum lookup! Cool!
                    self.packet_handler.state = State(next_state)

                    continue

                # Login Start
                elif self.packet_handler.state == State.Login and packet_raw | PacketType.Outbound.LoginStart:

                    self.username = PacketHandler.read(PacketType.Outbound.LoginStart, packet_raw)['username']
                    self.uuid = get_uuid(self.username)

                    info(f'Received Login Start! [username={ self.username }, uuid={ self.uuid }]')

                    # Send Login Start packet in advance
                    self.inbound_socket.sendall(packet_raw.raw)
                    info(f'[P -> S] Relayed Login Start to server! { packet_raw.raw }')

                    # Fabricate Set Compression packet
                    #   Compression threshold must be known beforehand, as this fake packet is sent before
                    #   the real Set Compression is sent to the proxy by the server.

                    set_compression = self.packet_handler.write(
                        PacketType.Inbound.SetCompression,

                        self.config.get('compression-threshold')
                    )

                    self.client_socket.sendall(set_compression)

                    # Fabricate a Login Success packet, making the client think
                    # the server is in offline mode.

                    # Manual compression takes place as it isn't enabled till later.

                    login_success = self.packet_handler.compression.compress(
                        self.packet_handler.write(
                            PacketType.Inbound.LoginSuccess,

                            str(uuid.UUID(hex=self.uuid)),
                            self.username
                        ),
                        override=True
                    )

                    self.client_socket.sendall(login_success)

                    info(f'[C <- P] Sent Login Success to client! { login_success }')

                    continue

                # Send packet
                packet = packet_raw.raw

                if self.packet_handler.encryption:
                    packet = self.cipher.encrypt(packet)

                self.inbound_socket.sendall(packet)

                print('[P -> S]', packet_raw)

    def accept_server(self):
        """Function to accept packets from the server to relay them to the client."""

        while True:
            data = self.inbound_socket.recv(1024)

            for packet_raw in self.packet_handler.recv_server(data):

                # Encryption Request
                if self.packet_handler.state == State.Login and packet_raw | PacketType.Inbound.EncryptionRequest:
                    packet = self.packet_handler.read_bytes(
                        PacketType.Inbound.EncryptionRequest,
                        packet_raw,

                        prefix=False
                    )

                    server_id, public_key, verify_token = (packet['server_id'], packet['public_key'],
                                                           packet['verify_token'])

                    info('Received Encryption request!')

                    print('Server ID: ', server_id.decode('utf-8'))
                    print('Public Key: ', public_key)
                    print('Verify Token: ', verify_token)

                    public_cipher = PublicKey(public_key)

                    # Authenticate with Mojang servers

                    info('Attempting to authenticate!')
                    print('Session ID: ', get_access_token(self.config))
                    print('Public Key: ', public_key)
                    print('Server ID: ', server_id)
                    print('UUID: ', self.uuid)

                    auth_res = authenticate(
                        session_id=get_access_token(self.config),
                        cipher=self.cipher,
                        public_key=public_key,
                        server_id=server_id,
                        uuid=self.uuid
                    )

                    if auth_res is True:
                        success('Authenticated successfully!')
                    else:
                        error('Authentication failed!')

                        status, res = auth_res
                        print('Status: ', status)
                        print('Payload: ', res)

                        # Throw appropriate error.. TODO Change this later. I do not like it.
                        for k, v in ERR_MAP.items():
                            if res['error'].startswith(k):
                                raise v()

                    secret_encrypted = public_cipher.encrypt(self.cipher.secret)
                    verify_token_encrypted = public_cipher.encrypt(verify_token)

                    # Send encryption response
                    enc_response = self.packet_handler.write(
                        PacketType.Outbound.EncryptionResponse,

                        len(secret_encrypted),
                        secret_encrypted,
                        len(verify_token_encrypted),
                        verify_token_encrypted
                    )

                    self.inbound_socket.sendall(enc_response)

                    info(f'[P -> S] Sent Encryption Response! { enc_response }')

                    # Finalize encryption process
                    self.packet_handler.encryption = True

                    info('Encryption enabled!')

                    # Block from going to the client, tricking it into Offline Mode
                    continue

                # Compression Set
                elif self.packet_handler.state == State.Login and packet_raw | PacketType.Inbound.SetCompression:
                    info(f'Received Set Compression! { packet_raw }')
                    self.packet_handler.compression.enabled = True

                    threshold = self.packet_handler.read(
                        PacketType.Inbound.SetCompression,
                        packet_raw
                    )['threshold']

                    self.packet_handler.compression.threshold = threshold
                    info(f'Enabled compression! [threshold={ threshold }]')

                    # Block Compression Set packet - it has already been sent
                    continue

                # Login Success
                elif self.packet_handler.state == State.Login and packet_raw | PacketType.Inbound.LoginSuccess:
                    info('Blocked Login Success!')

                    # Finalize login - this is the last step as Login Success is already sent
                    self.packet_handler.state = State.Play
                    info(f'Switched state to { self.packet_handler.state }!')

                    # Block Login Success packet - it has already been sent
                    continue

                # Send packet
                packet = packet_raw.raw
                self.client_socket.sendall(packet)

                # print('[C <- P]', packet_raw)

    def shutdown(self, _, __):
        """Function to shut down the proxy upon ``SIGINT``."""

        # ``socket.SHUT_RDWR`` disallows further sends and receives.
        # Followed by `close()`, clearing the file descriptor buffer.

        self.inbound_socket.shutdown(socket.SHUT_RDWR)
        self.inbound_socket.close()

        self.client_socket.shutdown(socket.SHUT_RDWR)
        self.client_socket.close()

        self.outbound_socket.shutdown(socket.SHUT_RDWR)
        self.outbound_socket.close()
