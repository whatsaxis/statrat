from abc import ABC, abstractmethod

import statrat.core.proxy as prx


class Mixin(ABC):
    """A mixin is a collection of packet listener definitions."""

    # String type hints are awesome!
    def __init__(self, proxy: 'prx.Proxy'):
        self.proxy = proxy
        self.register()

    @abstractmethod
    def register(self):
        """Function to register listeners."""
        return
