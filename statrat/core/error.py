class StatRatError(Exception):
    """
    Base Exception class for all StatRat exceptions.

    Used for easily catching all StatRat-related errors.
    """


class AuthError(StatRatError):
    """Base class for authentication-related exceptions."""


class InvalidSessionID(AuthError):
    """Thrown when an invalid session ID is provided."""


class InvalidServerID(AuthError):
    """Thrown when the hex digest of the server ID contains invalid information."""


class InvalidUUID(AuthError):
    """Thrown when the authentication server returns that a profile ID (UUID) is invalid."""


class NetworkError(StatRatError):
    """Base class for network-related exceptions."""


class IncorrectPacketLengthError(NetworkError):
    """
    Thrown when the length of the raw bytes exceed or fall short of the length field of a packet.
    """


class IncompletePacketError(NetworkError):
    """
    Thrown when attempting to construct a `Packet()` while not having provided values for all fields.
    """


class MissingHandlerError(NetworkError):
    """
    Thrown when attempting to construct a `Packet()` while not having provided a handler.
    """
