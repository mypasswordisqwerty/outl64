import uuid
import struct
from utils import Utils, Hexdumper
import hexdump

_REGISTERED_FILES = {}


def StreamFactory(name, obj, **kwargs):
    for x in _REGISTERED_FILES:
        eq = x == name
        if not eq and x.endswith("000"):
            eq = x[:-3] == name[:-3]
        if eq:
            Cls = _REGISTERED_FILES[x]
            return Cls(obj, name=name, **kwargs)
    return None


class OleStreamBase:

    def __init__(self, obj, name=None):
        self.name = name or self.NAME
        self.obj = obj

    def dump(self, filename):
        self.obj.dump(filename)

    def parse(self, buf):
        return Hexdumper(self.name + ": " + self.__class__.__name__, buf)


class OleStream(OleStreamBase):
    """ \x01Ole stream """
    NAME = "\\x01Ole"

    APPID = uuid.UUID("{25336920-03F9-11cf-8FD0-00AA00686F13}")  # htmldoc
    CLSID_HTA = uuid.UUID("{3050f4d8-98b5-11cf-bb82-00aa00bdce0b}")

    FLAG_EMBED = 0
    FLAG_LINK = 1
    FLAG_HINT = 8

    def __init__(self, obj, name=None, flags=FLAG_LINK | FLAG_HINT, relative=False, **kwargs):
        OleStreamBase.__init__(self, obj, name)
        self.flags = flags
        self.reserved = None
        self.relative = obj if self.isLink() and relative else None
        self.absolute = obj if self.isLink() and not relative else None
        if "reservedStream" in kwargs:
            self.reserved = kwargs.get("reservedStream")
        if "relativeStream" in kwargs:
            self.relative = kwargs.get("relativeStream")
        if "absoluteStream" in kwargs:
            self.absolute = kwargs.get("absoluteStream")
        self.linkUpdate = kwargs.get("linkUpdate") or 0
        self.appid = kwargs.get("appid")
        self.displayName = kwargs.get("displayName") or ''
        self.appReserved = kwargs.get("appReserved") or 0xFFFFFFFF
        self.utime = kwargs.get("updateTime")
        self.ctime = kwargs.get("checkTime")
        self.rtime = kwargs.get("remoteTime")

    def isLink(self):
        return (self.flags & self.FLAG_LINK) != 0

    def packMoniker(self, moniker, isLink):
        if moniker is None:
            return struct.pack("<L", 0)
        data = moniker.dump(self.name, isLink=isLink)
        return struct.pack("<L", len(data)) + data

    def dump(self, filename):
        ret = struct.pack("<LLLL", 0x02000001, self.flags, self.linkUpdate, 0)
        ret += self.packMoniker(self.reserved, False)
        if not self.isLink() and not self.relative and not self.absolute:
            return ret
        ret += self.packMoniker(self.relative, True)
        ret += self.packMoniker(self.absolute, True)
        ret += struct.pack("<L", 0xFFFFFFFF)
        ret += self.appid.bytes_le if self.appid else "\x00" * 16
        ret += Utils.oleString(self.displayName) + struct.pack("<L", self.appReserved)
        ret += struct.pack("<QQQ", Utils.toFiletime(self.utime), Utils.toFiletime(self.ctime),
                           Utils.toFiletime(self.rtime))
        return ret


_REGISTERED_FILES[OleStream.NAME] = OleStream


class OlePresentation(OleStreamBase):
    NAME = "\\x02OlePres000"
    CF_BITMAP = 0x00000002
    CF_METAFILEPICT = 0x00000003
    CF_DIB = 0x00000008
    CF_ENHMETAFILE = 0x0000000E

    TOCS_PRESENT = 0x494E414E

    def __init__(self, obj, name=None, fmt=1, width=100, height=100, **kwargs):
        OleStreamBase.__init__(self, obj, name)
        self.fmt = fmt
        self.targetDevice = None
        self.aspect = 0
        self.lindex = 0
        self.advf = 0
        self.reserved1 = 0
        self.width = width
        self.height = height
        self.reserved2 = "\x00" * 18
        self.tocs = []

    def dump(self, filename):
        if isinstance(self.fmt, basestring):
            ret = struct.pack("<L", len(self.fmt) + 1)
            ret += self.fmt + "\x00"
        else:
            ret = struct.pack("<LL", 0xFFFFFFFE, self.fmt)
        if self.targetDevice:
            ret += struct.pack("<L", len(self.targetDevice)) + self.targetDevice
        else:
            ret += struct.pack("<L", 4)
        ret += struct.pack("<LLLLLL", self.aspect, self.lindex, self.advf, self.reserved1, self.width, self.height)
        data = self.obj.dump(self.name)
        ret += struct.pack("<L", len(data)) + data
        ret += self.reserved2
        ret += struct.pack("<LL", 0 if len(self.tocs) == 0 else self.TOCS_PRESENT, len(self.tocs))
        for x in self.tocs:
            ret += x
        return ret

_REGISTERED_FILES[OlePresentation.NAME] = OlePresentation


class CompObj(OleStreamBase):
    NAME = "\\x01CompObj"
    UNICODE_MARKER = 0x71B239F4

    def __init__(self, obj, name=None, fmt=1, **kwargs):
        OleStreamBase.__init__(self, obj, name)
        self.fmt = fmt
        self.header = kwargs.get("header") or "\x00" * 28
        self.displayName = kwargs.get("displayName") or "obj"
        self.reserved = kwargs.get("reserved")
        self.unicode = kwargs.get("unicode") or False

    def dump(self, filename):
        ret = self.header
        ret += struct.pack("<L", len(self.displayName) + 1)
        ret += self.displayName + "\x00"
        if isinstance(self.fmt, basestring):
            ret += struct.pack("<L", len(self.fmt) + 1)
            ret += self.fmt + "\x00"
        else:
            ret += struct.pack("<LL", 0xFFFFFFFE, self.fmt)
        ret += struct.pack("<L", 0 if not self.reserved else len(self.reserved) + 1)
        if self.reserved:
            ret += self.reserved + "\x00"
        # unicode
        ret += struct.pack("<L", self.UNICODE_MARKER if self.unicode else 0)
        if not self.unicode:
            ret += struct.pack("<LLL", 0, 0, 0)
            return ret
        ret += struct.pack("<L", len(self.displayName) + 1)
        ret += self.displayName.encode("utf-16le") + "\x00\x00"
        if isinstance(self.fmt, basestring):
            ret += struct.pack("<L", len(self.fmt) + 1)
            ret += self.fmt.encode("utf-16le") + "\x00\x00"
        else:
            ret += struct.pack("<LL", 0xFFFFFFFE, self.fmt)
        ret += struct.pack("<L", 0 if not self.reserved else len(self.reserved) + 1)
        if self.reserved:
            ret += self.reserved.encode("utf-16le") + "\x00\x00"
        return ret


_REGISTERED_FILES[CompObj.NAME] = CompObj


class ObjInfo(OleStreamBase):
    NAME = "\\x03ObjInfo"

    def __init__(self, obj, name=None):
        OleStreamBase.__init__(self, obj, name)
        self.v1 = 0
        self.v2 = 3
        self.v3 = 4

    def dump(self, filename):
        return struct.pack("<HHH", self.v1, self.v2, self.v3)


_REGISTERED_FILES[ObjInfo.NAME] = ObjInfo
