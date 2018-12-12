
try:
    import _winreg
except Exception:
    _winreg = None
import platform


class RegKey:

    def __init__(self, parent, key, name="root"):
        self.key = key
        self.parent = parent
        self._subkeys = None
        self._values = None
        self._name = name

    def __del__(self):
        _winreg.CloseKey(self.key)

    def getBits(self):
        return self.parent.getBits()

    def name(self):
        return self.parent.name() + "\\" + self._name

    def open(self, key):
        k = self.regOpenKey(self.key, key)
        if not k:
            key = self._getSubs().get(key.lower())
            k = self.regOpenKey(self.key, key)
        return RegKey(self, k, key) if k else None

    def values(self):
        if not self._values:
            self._values = {}
            try:
                i = 0
                while True:
                    n, v, t = _winreg.EnumValue(self.key, i)
                    self._values[n.lower()] = v
                    i += 1
            except WindowsError:
                pass
        return self._values

    def value(self, name='', default=None):
        return self.values().get(name.lower()) or default

    def hasValue(self, name):
        return name.lower() in self.values()

    def _getSubs(self):
        if not self._subkeys:
            self._subkeys = {}
            try:
                i = 0
                while True:
                    k = _winreg.EnumKey(self.key, i)
                    i += 1
                    self._subkeys[k.lower()] = k
            except WindowsError:
                pass
        return self._subkeys

    def subkeys(self):
        return self._getSubs().values()

    def hasSubkey(self, name):
        return name.lower() in self._getSubs()

    def subkeyValue(self, name, default=None):
        sub = self._getSubs().get(name.lower())
        try:
            return _winreg.QueryValue(self.key, sub) if sub else default
        except WindowsError:
            try:
                hk = _winreg.OpenKey(self.key, sub)
                val, tp = _winreg.QueryValueEx(hk, None)
                _winreg.CloseKey(hk)
                return val
            except WindowsError:
                print "Error getting sub", sub, name, self.key, self.name()
                raise

    @staticmethod
    def regOpenKey(root, key, sam=_winreg.KEY_READ):
        if not key:
            return None
        try:
            return _winreg.OpenKeyEx(root, key, 0, sam)
        except WindowsError:
            return None


class Registry:
    MODE_64 = 0
    MODE_32 = 1
    MODE_6432 = 2
    MODE_3264 = 3
    HKEY_CLASSES_ROOT = _winreg.HKEY_CLASSES_ROOT
    HKEY_CURRENT_USER = _winreg.HKEY_CURRENT_USER
    HKEY_LOCAL_MACHINE = _winreg.HKEY_LOCAL_MACHINE
    HKEY_USERS = _winreg.HKEY_USERS
    HKEY_CURRENT_CONFIG = _winreg.HKEY_CURRENT_CONFIG

    def __init__(self, root=HKEY_CLASSES_ROOT, mode=MODE_6432):
        self.bits = int(platform.architecture()[0][:2])
        self.root = root

    def open(self, key, mode=MODE_6432):
        ret = None
        if mode == self.MODE_64 or mode == self.MODE_6432:
            key = RegKey.regOpenKey(self.root, key, _winreg.KEY_READ | _winreg.KEY_WOW64_64KEY)
            ret = RegKey(self, key) if key else None
        if mode != self.MODE_64 and not ret:
            key = RegKey.regOpenKey(self.root, key, _winreg.KEY_READ | _winreg.KEY_WOW64_32KEY)
            ret = RegKey(self, key) if key else None
        if mode == self.MODE_3264 and not ret:
            key = RegKey.regOpenKey(self.root, key, _winreg.KEY_READ | _winreg.KEY_WOW64_64KEY)
            ret = RegKey(self, key) if key else None
        return ret

    def getBits(self):
        return self.bits

    def name(self):
        return "HKROOT"
