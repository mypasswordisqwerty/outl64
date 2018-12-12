from datetime import datetime, timedelta
import uuid
import struct
import hexdump


class OleError(Exception):

    def __init__(self, what): Exception.__init__(self, what)


class Utils:
    GUID_NULL = uuid.UUID(int=0)
    FTIME_INIT = datetime(1601, 1, 1)

    @staticmethod
    def toFiletime(dtm):
        if dtm is None:
            return 0
        if not isinstance(dtm, datetime):
            return dtm
        delta = dtm - Utils.FTIME_INIT
        return delta.microseconds * 10

    @staticmethod
    def fromFiletime(filetime):
        if filetime == 0:
            return None
        return Utils.FTIME_INIT + timedelta(microseconds=filetime // 10)

    @staticmethod
    def oleString(string):
        string = unicode(string) or ''
        ret = struct.pack("<L", len(string) + 1 if len(string) else 0)
        if len(string):
            ret += string + "\x00\x00"
        return ret

    @staticmethod
    def openFP(fp, mode="rb"):
        if isinstance(fp, basestring):
            return open(fp, mode)
        return fp

    @staticmethod
    def readFP(fp, size=None):
        return Utils.openFP(fp).read(size) if size else Utils.openFP(fp).read()


class Hexdumper:

    def __init__(self, name, buf):
        self.name = name
        self.buf = buf

    def pprint(self):
        print self.name
        hexdump.hexdump(self.buf)
