import pyout
import uuid
import os
import json
import binascii
import _winreg


class GuidHelper:
    """ find guids """

    def __init__(self):
        path = os.path.join(pyout.mypath('doc'), "interfaces.json")
        self.manual = {}
        if os.path.isfile(path):
            with open(path, "r") as f:
                self.manual = json.load(f)

    def guidOfVals(self, val):
        s = "{0:08X}-{1:04X}-{2:04X}-{a[0]:02X}{a[1]:02X}-{a[2]:02X}{a[3]:02X}{a[4]:02X}{a[5]:02X}{a[6]:02X}{a[7]:02X}"
        v = s.format(val[0], val[1], val[2], a=val[3])
        return uuid.UUID(v)

    def guidStr(self, guid):
        if isinstance(guid, uuid.UUID):
            guid = str(guid)
        if not guid.startswith('{'):
            guid = '{' + guid + '}'
        return guid

    def findGuid(self, guid):
        s = self.guidStr(guid)
        if s.upper() in self.manual:
            return {"guid": s, "name": self.manual[s.upper()].encode('ascii'), "prefix": None}
        reg = {
            _winreg.OpenKeyEx(_winreg.HKEY_CLASSES_ROOT, "Interface", 0, _winreg.KEY_READ | _winreg.KEY_WOW64_64KEY): "IID",
            _winreg.OpenKeyEx(_winreg.HKEY_CLASSES_ROOT, "CLSID", 0, _winreg.KEY_READ | _winreg.KEY_WOW64_64KEY): "CLSID",
            _winreg.OpenKeyEx(_winreg.HKEY_CLASSES_ROOT, "Interface", 0, _winreg.KEY_READ | _winreg.KEY_WOW64_32KEY): "IID",
            _winreg.OpenKeyEx(_winreg.HKEY_CLASSES_ROOT, "CLSID", 0, _winreg.KEY_READ | _winreg.KEY_WOW64_32KEY): "CLSID",
        }
        for y in reg:
            try:
                k = _winreg.OpenKey(y, s)
                nm = _winreg.QueryValue(k, None)
                if nm:
                    return {"guid": s, "name": nm, "prefix": reg[y]}
            except Exception:
                continue
        return None
