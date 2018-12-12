import struct
import os
import uuid
import olestream
import oleobject
from . import gendata


class StdOleLink(oleobject.OleObject):
    """ Moniker stream base """
    FILES = [olestream.OleStream.NAME]
    STDOLE_CLSID = uuid.UUID("{00000300-0000-0000-C000-000000000046}")

    def save(self, olefile):
        oleobject.OleObject.save(self, olefile)
        olefile.root.clsid = self.STDOLE_CLSID

    def dumpStr(self, s="", unicode=True, withZero=True):
        ret = struct.pack("<L", len(s) + (1 if withZero else 0))
        ret += s.encode("UTF-16LE") if unicode else s
        if withZero:
            ret += "\x00\x00" if unicode else "\x00"
        return ret

    def dump(self, filename, **kwargs):
        return self.clsid.bytes_le + self.build(kwargs.get("isLink"))

    def build(self, isLink):
        return self.data


class UrlMoniker(StdOleLink):
    """ urlmon """
    CLSID = uuid.UUID("{79eac9e0-baf9-11ce-8c82-00aa004ba90b}")

    def __init__(self, url, **kwargs):
        StdOleLink.__init__(self, **kwargs)
        self.url = unicode(url)
        self.urllen = kwargs.get("urllen") or 324

    def createStream(self, name):
        if name == olestream.CompObj.NAME:
            return olestream.CompObj(self, self, fmt="text/html")
        return StdOleLink.createStream(self, name)

    def build(self, isLink):
        ret = struct.pack("<L", self.urllen)
        ret += self.url.encode("UTF-16LE")
        ret += "\x00" * (self.urllen - len(self.url) * 2)
        return ret


class ClassMoniker(StdOleLink):
    """ combase """
    CLSID = uuid.UUID("{0000031A-0000-0000-C000-000000000046}")

    def __init__(self, data, dataclsid=None, **kwargs):
        StdOleLink.__init__(self, data, **kwargs)
        self.dataclsid = dataclsid or self.CLSID

    def build(self, isLink):
        ret = self.dataclsid.bytes_le
        ret += struct.pack('<L', len(self.data))
        ret += self.data
        return ret


class ObjRefMoniker(StdOleLink):
    OBJREF_CLSID = uuid.UUID("{00000327-0000-0000-C000-000000000046}")
    IID = uuid.UUID("{00000000-0000-0000-c000-000000000046}")

    def __init__(self, data=None, clsid=None, flags=4):
        StdOleLink.__init__(self, data, clsid)
        self.flags = flags
        self.stdFlags = 0
        self.refs = 1
        self.pntr = 0
        self.ext = 0
        self.resAddr = []
        if not self.clsid:
            self.clsid = uuid.UUID(data)

    def dumpStd(self):
        return struct.pack("<LLQQ", self.stdFlags, self.refs, self.OXID, self.OID) + self.IPID.bytes_le

    def dumpResAddr(self):
        ret = struct.pack("<HH", len(self.resAddr), 0)
        for x in self.resAddr:
            ret += x + "\0"
        return ret

    def _dumpInternal(self, data=None, clsid=None, iid=None, flags=None):
        ret = "MEOW"
        f = flags or self.flags
        iid = iid or self.IID
        clsid = clsid or self.CLSID
        ret += struct.pack('<L', f)
        ret += iid.bytes_le
        if f & 4 == 0:  # not cust
            ret += self.dumpStd()
        if f & 6 != 0:  # cust or handler
            ret += clsid.bytes_le
        if f & 4 != 0:  # cust
            data = data or self.build()
            return ret + struct.pack("<LL", self.ext, len(data)) + data
        if f & 0x8 != 0:  # ext
            return ret + struct.pack("<Q", self.pntr)
        return ret + self.dumpResAddr()

    def dump(self, filename, **kwargs):
        return self.OBJREF_CLSID.bytes_le + self._dumpInternal()

    def build(self):
        data = gendata()
        return struct.pack("<L", len(data)) + data


class NewMoniker(StdOleLink):
    """ comcvs.dll """
    CLSID = uuid.UUID("{ecabafc6-7f19-11d2-978e-0000f8757e2a}")

    def __init__(self, data, **kwargs):
        StdOleLink.__init__(self, data, **kwargs)
        self.dataclsid = uuid.UUID(self.data)
        self.dname = data

    def build(self, isLink):
        ret = self.dataclsid.bytes_le
        ret += struct.pack('<L', len(self.data) * 2 + 2)
        ret += self.data.encode("utf-16le") + "\x00\x00"
        ret += struct.pack('<L', len(self.dname) * 2 + 2)
        ret += self.dname.encode("utf-16le") + "\x00\x00"
        return ret


class PointerMoniker(StdOleLink):
    CLSID = uuid.UUID("00000306-0000-0000-c000-000000000046")


class FileMoniker(StdOleLink):
    CLSID = uuid.UUID("00000303-0000-0000-c000-000000000046")


class CompositeMoniker(StdOleLink):
    CLSID = uuid.UUID("00000309-0000-0000-c000-000000000046")


class AntiMoniker(StdOleLink):
    CLSID = uuid.UUID("00000305-0000-0000-c000-000000000046")


class ItemMoniker(StdOleLink):
    CLSID = uuid.UUID("00000304-0000-0000-c000-000000000046")


class ScriptMoniker(UrlMoniker):
    CLSID = uuid.UUID("{06290BD3-48AA-11D2-8432-006008C3FBFC}")


class PackagerMoniker(StdOleLink):
    CLSID = uuid.UUID("{00000308-0000-0000-C000-000000000046}")


class ServiceMoniker(StdOleLink):
    CLSID = uuid.UUID("{ce39d6f3-dab7-41b3-9f7d-bd1cc4e92399}")


class QueueMoniker(UrlMoniker):
    """ comcvs.dll """
    CLSID = uuid.UUID("{ecabafc7-7f19-11d2-978e-0000f8757e2a}")

    def build(self, isLink):
        ret = struct.pack('<L', len(self.data) * 2 + 2)
        ret += self.data.encode("utf-16le") + "\x00\x00"
        return ret


class SoapMoniker(StdOleLink):
    """ comcvs.dll """
    CLSID = uuid.UUID("{ecabb0c7-7f19-11d2-978e-0000f8757e2a}")

    def build(self, isLink):
        ret = struct.pack('<L', 0)
        #ret += self.clsid.bytes_le
        ret += struct.pack('<L', len(self.data) * 2 + 2)
        ret += self.data.encode("utf-16le") + "\x00\x00"
        return ret


class PartitionMoniker(StdOleLink):
    """ comsvcs """
    CLSID = uuid.UUID("{ecabb0c5-7f19-11d2-978e-0000f8757e2a}")


class DeviceMoniker(StdOleLink):
    """ devenum.dll """
    CLSID = uuid.UUID("{4315D437-5B8C-11D0-BD3B-00A0C911CE86}")


class XmlMoniker(UrlMoniker):
    """ msxml3.dll """
    CLSID = uuid.UUID("{F5078F3F-C551-11D3-89B9-0000F81FE221}")

    def __init__(self, data):
        UrlMoniker.__init__(self, data, clsid=self.CLSID)


class XmlViewerMoniker(XmlMoniker):
    """ msxml3.dll """
    CLSID = uuid.UUID("{7E3FCEA1-31B4-11D2-AE1F-0080C7337EA1}")


class XmlFeedMoniker(StdOleLink):
    """ ieframe.dll """
    CLSID = uuid.UUID("{ffd90217-f7c2-4434-9ee1-6f1b530db20f}")

    def __init__(self, data, **kwargs):
        StdOleLink.__init__(self, data, **kwargs)

    def build(self, isLink):
        ret = self.clsid.bytes_le
        ret += struct.pack("<Q", len(self.data))
        ret += self.data.encode("utf-16le")
        return ret
