import uuid

from statrat.core.logging import info, success, warn, error
from statrat.core.crypto import PublicKey
from statrat.core.mixin import Mixin

from statrat.auth.session import get_access_token
from statrat.auth.request import authenticate, ERR_MAP

import statrat.net.field as field
from statrat.net.packet import Packet, State, InboundEnum, OutboundEnum


class LoginPacket:

    class Inbound(InboundEnum):
        EncryptionRequest = (
            0x01,
            State.Login,
            (
                ('server_id', field.String()),
                ('public_key', field.Array(field.Byte())),
                ('verify_token', field.Array(field.Byte()))
            )
        )

        LoginSuccess = (
            0x02,
            State.Login,
            (
                ('uuid', field.String()),
                ('username', field.String())
            )
        )

        SetCompression = (
            0x03,
            State.Login,
            (
                ('threshold', field.VarInt()),
            )
        )

    class Outbound(OutboundEnum):

        Handshake = (
            0x00,
            State.Handshaking,
            (
                ('protocol_version', field.VarInt()),
                ('server_address', field.String()),
                ('server_port', field.UnsignedShort()),
                ('next_state', field.VarInt())
            )
        )

        LoginStart = (
            0x00,
            State.Login,
            (
                ('username', field.String()),
            )
        )

        EncryptionResponse = (
            0x01,
            State.Login,

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


class LoginMixin(Mixin):
    """Login sequence mixin."""

    def register(self):
        """
        A collection of packet listeners associated with the login and authentication process.
        """

        '''Outbound'''

        @self.proxy.listen(LoginPacket.Outbound.Handshake)
        def handshake_listener(packet: Packet):
            protocol_version, server_address, server_port, next_state = packet.get_fields(
                'protocol_version',
                'server_address',
                'server_port',
                'next_state'
            )

            info(f'Handshake packet received! State: [{ self.proxy.packet_handler.state } -> { State(next_state) }]')

            # Reverse Enum lookup! Cool!
            self.proxy.packet_handler.state = State(next_state)

            if self.proxy.packet_handler.state == State.Status:
                return False

            # The server address field is always 127.0.0.1, as the client is connecting to a local socket.
            # This must be edited, as servers may check this and not allow the proxy to connect.

            handshake = self.proxy.packet_handler.write(
                LoginPacket.Outbound.Handshake,

                protocol_version,
                self.proxy.config.get('server-address'),
                server_port,
                next_state
            )

            self.proxy.send_server(handshake)

            return False

        @self.proxy.listen(LoginPacket.Outbound.LoginStart)
        def login_start_listener(packet: Packet):
            self.proxy.profile.username = packet.get_fields('username')

            info(f'Received Login Start! [username={ self.proxy.profile.username }, uuid={ self.proxy.profile.uuid }]')

            # Send Login Start packet in advance
            self.proxy.send_server(packet)
            info(f'[P -> S] Relayed Login Start to server! { packet.raw.raw }')

            # Fabricate Set Compression packet
            #   Compression threshold must be known beforehand, as this fake packet is sent before
            #   the real Set Compression is sent to the proxy by the server.

            set_compression = self.proxy.packet_handler.write(
                LoginPacket.Inbound.SetCompression,

                self.proxy.config.get('compression-threshold')
            )

            self.proxy.send_client(set_compression)

            # Fabricate a Login Success packet, making the client think
            # the server is in offline mode.

            # Manual compression takes place as it isn't enabled till later.

            login_success = self.proxy.packet_handler.compression.compress(
                self.proxy.packet_handler.write(
                    LoginPacket.Inbound.LoginSuccess,

                    str(uuid.UUID(hex=self.proxy.profile.uuid)),
                    self.proxy.profile.username
                ),
                override=True
            )

            self.proxy.send_client(login_success)

            info(f'[C <- P] Sent Login Success to client! { login_success }')

            return False

        '''Inbound'''

        @self.proxy.listen(LoginPacket.Inbound.EncryptionRequest)
        def encryption_request_listener(packet: Packet):
            server_id, public_key, verify_token = packet.get_bytes(
                'server_id',
                'public_key',
                'verify_token',
                prefix=False
            )

            info('Received Encryption request!')

            print('Server ID: ', server_id.decode('utf-8'))
            print('Public Key: ', public_key)
            print('Verify Token: ', verify_token)

            public_cipher = PublicKey(public_key)

            # Authenticate with Mojang servers

            info('Attempting to authenticate!')
            print('Session ID: ', get_access_token(self.proxy.config))
            print('Public Key: ', public_key)
            print('Server ID: ', server_id)
            print('UUID: ', self.proxy.profile.uuid)

            auth_res = authenticate(
                session_id=get_access_token(self.proxy.config),
                cipher=self.proxy.packet_handler.cipher,
                public_key=public_key,
                server_id=server_id,
                uuid=self.proxy.profile.uuid
            )

            if auth_res is True:
                success('Authenticated successfully!')
            else:
                error('Authentication failed!')

                status, res = auth_res
                print('Status: ', status)
                print('Payload: ', res)

                # Throw appropriate error
                for k, v in ERR_MAP.items():
                    if res['error'].startswith(k):
                        raise v()

            secret_encrypted = public_cipher.encrypt(self.proxy.packet_handler.cipher.secret)
            verify_token_encrypted = public_cipher.encrypt(verify_token)

            # Send encryption response
            enc_response = self.proxy.packet_handler.write(
                LoginPacket.Outbound.EncryptionResponse,

                len(secret_encrypted),
                secret_encrypted,
                len(verify_token_encrypted),
                verify_token_encrypted
            )

            self.proxy.send_server(enc_response)

            info(f'[P -> S] Sent Encryption Response! { enc_response }')

            # Finalize encryption process
            self.proxy.packet_handler.encryption = True

            info('Encryption enabled!')

            # Block from going to the client, tricking it into Offline Mode
            return False

        @self.proxy.listen(LoginPacket.Inbound.SetCompression)
        def set_compression_listener(packet: Packet):
            info(f'Received Set Compression! { packet.raw.raw }')

            threshold = packet.get_fields('threshold')

            if not self.proxy.packet_handler.compression.threshold == threshold:
                warn(
                    f'Compression threshold in configuration differs to the one provided by the server!'
                    f' [config={ self.proxy.packet_handler.compression.threshold }, server={ threshold }]'
                )

                self.proxy.packet_handler.compression.threshold = threshold

            self.proxy.packet_handler.compression.enabled = True
            info(f'Enabled compression! [threshold={ threshold }]')

            # Block Compression Set packet - it has already been sent
            return False

        @self.proxy.listen(LoginPacket.Inbound.LoginSuccess)
        def login_success_listener(_):
            info('Blocked Login Success!')

            # Finalize login - this is the last step as Login Success is already sent
            self.proxy.packet_handler.state = State.Play
            info(f'Switched state to { self.proxy.packet_handler.state }!')

            # Block Login Success packet - it has already been sent
            return False
