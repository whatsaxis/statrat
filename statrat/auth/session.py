import re
import sys
import pathlib
import requests
import functools

from statrat.core.error import UnsupportedPlatformException


def get_mc_folder():
    """A cross-platform function to get the location of the /.minecraft folder."""

    # Windows
    if sys.platform.startswith('win32'):
        return pathlib.Path.home() / 'AppData' / 'Roaming' / '.minecraft'

    # MacOS
    elif sys.platform.startswith('darwin'):
        return pathlib.Path.home() / 'Library' / 'Application Support' / 'minecraft'

    # Linux
    elif sys.platform.startswith('linux'):
        return pathlib.Path.home() / '.minecraft'

    raise UnsupportedPlatformException(f'Could not locate Minecraft folder! Unsupported platform! [{ sys.platform }]')


TOKEN_REGEX = re.compile(r'\(Session ID is token:(.*)\)')


def get_access_token():
    """Gets the access token (session ID) from the Minecraft directory."""

    # This only works before 1.9.1, as the Session ID is no
    # longer in the log files after that version.


    key = 'haha you are not getting this!'
    return key

    # with open(get_mc_folder() / 'logs' / 'latest.log') as f:
    #     log = f.read()
    #
    #     match = TOKEN_REGEX.search(log)
    #     token = match.group(1)
    #
    #     return token


@functools.cache
def get_uuid(username: str):
    """Gets the UUID of a player."""

    return requests.get(f'https://api.mojang.com/users/profiles/minecraft/{ username }').json()['id']
