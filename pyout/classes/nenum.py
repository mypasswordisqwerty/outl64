

class NEnum:
    _instances = {}

    def __init__(self):
        self._names = None

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(
                NEnum, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

    def allValues(self):
        return {name: value for name, value in vars(self.__class__).iteritems() if name.isupper()}

    def allNames(self):
        if self._names is None:
            self._names = {value: name for name, value in vars(self.__class__).iteritems() if name.isupper()}
        return self._names

    def getName(self, value):
        return self.allNames().get(value)
