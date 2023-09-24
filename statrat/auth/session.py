import requests
import functools

from statrat.core.config import Config


def get_access_token(config: Config):
    """
    Gets the access token (session ID) from the configuration directory.

    This is obtained through looking at the cookies on a logged in minecraft.net page - weird how it's so easy, given
    they made the MS authentication scheme absolute hell, huh?
    """

    return config.get('session-id')


@functools.cache
def get_uuid(username: str):
    """Gets the UUID of a player."""

    return requests.get(f'https://api.mojang.com/users/profiles/minecraft/{ username }').json()['id']
