"""
Logging Module
"""


INFO_COLOR = (68, 170, 238)
SUCCESS_COLOR = (204, 255, 51)
WARNING_COLOR = (255, 204, 85)
ERROR_COLOR = (255, 51, 102)

# TODO A redux-type broadcast thing for logging


def colored(msg: str, color: tuple[int, int, int]):
    """
    Return a string with an ANSI escape code colored message.
    Will only work if the terminal supports TrueColor.
    """

    r, g, b = color

    return f'\x1b[38;2;{ r };{ g };{ b }m{ msg }\033[0m'


def info(msg: str):
    """Info logging function."""

    print(colored('[INFO]', INFO_COLOR) + ' ' + msg)


def success(msg: str):
    """Success logging function."""

    print(colored('[SUCCESS]', SUCCESS_COLOR) + ' ' + msg)


def warn(msg: str):
    """Warning logging function."""

    print(colored('[WARN]', WARNING_COLOR) + ' ' + msg)


def disconnect(msg: str):
    """Disconnect logging function."""

    print(colored('[DISCONNECT]', WARNING_COLOR) + ' ' + msg)


def error(msg: str):
    """Error logging function."""

    print(colored('[ERROR]', ERROR_COLOR) + ' ' + msg)
