class StatRatError(Exception):
    """
    Base Exception class for all StatRat exceptions.

    Used for easily catching all StatRat-related errors.
    """


class AuthError(StatRatError):
    """Base class for authentication-related exceptions."""


# TODO Create errors for each authentication status (incorrect session id, server id, and the other thing idk i forgot)

class AccessKeyError(AuthError):
    """
    Base class for when something goes wrong with obtaining the access key (also known as session token).
    """


class UnsupportedPlatformException(AccessKeyError):
    """Thrown on an attempt to get access key from Minecraft logs on an unsupported platform."""


class NetworkError(StatRatError):
    """Base class for network-related exceptions."""


class IncorrectPacketLengthError(NetworkError):
    """
    Thrown when a ``PacketMeta()`` object receives raw bytes that exceed or fall short of the length field.
    """
