from statrat.auth.session import get_uuid


class Profile:

    def __init__(self, username: str = None):
        self._username = username
        self.uuid = None if username is None else get_uuid(username)

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, name: str):
        self._username = name
        self.uuid = get_uuid(self.username)
