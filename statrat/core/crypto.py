import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


class PublicKey:
    """DER public key encryption utility class."""

    def __init__(self, key: bytes):
        print('key', key)
        self.key = load_der_public_key(key, backend=default_backend())

    def encrypt(self, data: bytes):
        return self.key.encrypt(
            data,
            PKCS1v15()
        )


class AESCipher:
    """AES asymmetric encryption cipher utility class."""

    # Symmetric encryption is enabled once the Encryption Response packet has been received.
    # This packed is signed with the public key, which is not in the scope of this class's implementation.

    def __init__(self, secret: bytes):

        self.secret = secret

        # Shared secret is both the AES key and the IV, as per the MC protocol
        self.cipher = Cipher(
            algorithm=algorithms.AES(secret),
            mode=modes.CFB8(secret)
        )

        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def encrypt(self, data: bytes):
        return self.encryptor.update(data)

    def decrypt(self, data: bytes):
        return self.decryptor.update(data)
