import yaml


class Config:
    """Configuration manager from external ``yaml`` files."""

    def __init__(self, path: str):
        with open(path, 'r') as f:
            self.config = yaml.safe_load(f.read())

    def get(self, prop: str):
        return self.config[prop]
