import requests
import hashlib

from statrat.core.crypto import AESCipher
from statrat.core.error import InvalidSessionID, InvalidServerID, InvalidUUID

SESSION_ENDPOINT = 'https://sessionserver.mojang.com/session/minecraft/join'

ERR_MAP = {
    'ForbiddenOperationException': InvalidSessionID,
    'Invalid serverId': InvalidServerID,
    'Invalid profileId': InvalidUUID
}


def hex_digest(sha1_hash: bytes):
    """Generate a Minecraft hex digest from a SHA1 hash."""

    # Data is first converted to a signed number, with the digest
    # function subsequently spitting out its hex representation
    return format(
        int.from_bytes(sha1_hash, byteorder='big', signed=True),
        'x'
    )


def generate_server_hash(secret: bytes, server_id: bytes, public_key: bytes):
    """Generate a hex digest of the SHA1 server hash used in the ``serverId`` field for authentication."""

    server_hash = hashlib.sha1()

    server_hash.update(server_id.decode().encode('ascii'))
    server_hash.update(secret)
    server_hash.update(public_key)

    return hex_digest(server_hash.digest())


def authenticate(session_id: str, uuid: str, cipher: AESCipher, server_id: bytes, public_key: bytes):
    """
    Authenticate with the Mojang session servers, telling them that this account is joining a server.
    """

    res = requests.post(
        SESSION_ENDPOINT,

        headers={
            'Content-Type': 'application/json'
        },

        json={
            'accessToken': session_id,
            'selectedProfile': uuid,
            'serverId': generate_server_hash(cipher.secret, server_id, public_key)
        }
    )

    if res.status_code == 204:
        return True

    return res.status_code, res.json()
