
import struct
import sys
from datetime import datetime, timedelta
import uuid
from pyout.enums.mapi import MapiEnum


class MapiProps:

    OLETIME_INIT = datetime(1899, 12, 30)
    SYSTIME_INIT = datetime(1601, 1, 1)

    class NeedGuidError(Exception):

        def __init__(self):
            Exception.__init__(self, "GUID and propMap expected.")

    class ArrayMismatchError(Exception):

        def __init__(self):
            Exception.__init__(self, "Property type and data array mismatch.")

    class WrongTypeError(Exception):

        def __init__(self, propTag):
            Exception.__init__(self, "Unknown type 0x{:04X}.".format(propTag & 0xFFFF))

    class Prop:
        """ Mapi property holder """

        IDTYPE_NUMBER = 0
        IDTYPE_STRING = 1

        def __init__(self, propTag, data=None, **kwargs):
            """ Create prop tag.
                kwargs:
                type - MapiEnum.PT_ - change prop type
                guid - named property guid
                map - named property map (int or str/unicode)
            """
            self.propTag = propTag
            self.data = None if data is None else MapiProps.pad(data)
            if 'type' in kwargs:
                self.propTag = (self.propTag & 0xFFFF0000) | kwargs['type']
            self.guid = kwargs.get('guid')
            self.map = kwargs.get('map')
            if self.propTag > 0x80000000 and not self.guid:
                raise MapiProps.NeedGuidError()
            if self.guid and self.map is None:
                raise MapiProps.NeedGuidError()

        def dumpTnef(self):
            ret = struct.pack('I', self.propTag)
            if self.guid:
                ret += MapiProps.convertGuid(self.guid)
                if isinstance(self.map, basestring):
                    ret += struct.pack('I', self.IDTYPE_STRING)
                    ret += MapiProps.convertUnicode(self.map)
                else:
                    ret += struct.pack('I', self.IDTYPE_NUMBER)
                    ret += struct.pack('I', self.map)
            if self.data is not None:
                ret += self.data
            return ret

    class BinStream:

        def __init__(self, data, version=2, type=1, flags=1):
            self.data = data
            self.version = version
            self.type = type
            self.flags = flags
            self.reserved = "\x00" * 28

        def dump(self):
            ret = struct.pack('III', self.version, self.type, self.flags)
            ret += self.reserved
            ret += struct.pack("I", len(self.data))
            ret += self.data
            return ret

    def __init__(self):
        self.clear()

    @staticmethod
    def parse(fp, sz, dump=None, dfile=None):
        ln = struct.unpack("I", fp.read(4))[0]
        print >> sys.stderr, "MapiProps", ln, ":"
        e = MapiEnum()
        for i in range(ln):
            pid = struct.unpack("I", fp.read(4))[0]
            spec = ''
            if pid > 0x80000000:
                g = uuid.UUID(bytes_le=fp.read(16))
                spec = str(g) + '_'
                tp, lid = struct.unpack("II", fp.read(8))
                if tp == 0:
                    spec += str(lid)
                else:
                    bts = lid * 2
                    spec += fp.read(bts - 2).decode("utf-16le")
                    fp.read(2 + 0 if (bts % 4) == 0 else 2)
            tp = pid & 0x7FFF
            if pid & 0x1000 or tp in [e.PT_STRING8, e.PT_UNICODE, e.PT_OBJECT, e.PT_BINARY]:
                arr = struct.unpack("I", fp.read(4))[0]
            else:
                arr = 1
            data = []
            pidfmt = "{:08X}".format(pid)
            nm = e.getName(pid)
            for x in range(arr):
                if tp in [e.PT_NULL, e.PT_NONE]:
                    continue
                if tp == e.PT_I2:
                    data += struct.unpack("I", fp.read(4))
                elif tp in [e.PT_R4, e.PT_LONG, e.PT_ERROR, e.PT_BOOLEAN]:
                    data += struct.unpack("I", fp.read(4))
                elif tp in [e.PT_I8, e.PT_DOUBLE, e.PT_CURRENCY, e.PT_SYSTIME, e.PT_APPTIME]:
                    data += struct.unpack("Q", fp.read(8))
                elif tp == e.PT_CLSID:
                    data += [uuid.UUID(bytes_le=fp.read(16))]
                elif tp in [e.PT_STRING8, e.PT_UNICODE, e.PT_OBJECT, e.PT_BINARY]:
                    bsz = struct.unpack("I", fp.read(4))[0]
                    buf = fp.read(bsz)
                    val = "<data>:" + str(bsz)
                    if tp == e.PT_STRING8:
                        val = buf[:-1]
                    if tp == e.PT_UNICODE:
                        val = buf[:-2].decode("utf-16le")
                    data += [val]
                    if bsz % 4 != 0:
                        fp.read(4 - (bsz % 4))
                    if dump and dump in [pidfmt, nm]:
                        with open(dfile, "wb") as f:
                            f.write(buf)
                else:
                    raise Exception("Unknown tag type: %08X" % pid)
            print >> sys.stderr, "{}:{} {} {}".format(pidfmt, nm, spec, str(data))

    @staticmethod
    def replaceRtf(data, rtfdata):
        return data

    def clear(self):
        self.props = []
        return self

    def dumpTnef(self):
        ret = struct.pack('I', len(self.props))
        for x in self.props:
            ret += x.dumpTnef()
        return ret

    def isArr(self, data, default=True):
        if data is None:
            return default
        return isinstance(data, (list, tuple))

    def oleTime(self, dtm):
        if not isinstance(dtm, datetime):
            return dtm
        delta = dtm - MapiProps.OLETIME_INIT
        day = timedelta(days=1)
        return delta.total_seconds() / day.total_seconds()

    def sysTime(self, dtm):
        if not isinstance(dtm, datetime):
            return dtm
        delta = dtm - MapiProps.SYSTIME_INIT
        return delta.microseconds * 10

    @staticmethod
    def pad(string, padding=4):
        while len(string) % padding != 0:
            string += "\x00"
        return string

    @staticmethod
    def convertBinary(binary):
        ret = struct.pack('I', len(binary))
        ret += binary
        return MapiProps.pad(ret)

    @staticmethod
    def convertString(string):
        return MapiProps.convertBinary(string + "\x00")

    @staticmethod
    def convertUnicode(string):
        if not isinstance(string, unicode):
            string = string.decode('ascii')
        return MapiProps.convertBinary(string.encode('utf-16le') + "\x00" * 2)

    @staticmethod
    def convertGuid(guid):
        return guid.bytes_le

    def convertData(self, propTag, data, default, converter):
        if data is None:
            data = [default] if propTag & 0x1000 != 0 else default
        if self.isArr(data):
            return [converter(x) for x in data]
        else:
            return converter(data)

    def addRaw(self, propTag, data, **kwargs):
        """Add property
        """
        if self.isArr(data):
            val = struct.pack('I', len(data))
            val += ''.join(data)
        else:
            val = data
        prop = MapiProps.Prop(propTag, val, **kwargs)
        self.props += [prop]
        return self

    def addFmt(self, propTag, data, fmt, **kwargs):
        data = self.convertData(propTag, data, 0, lambda x: struct.pack(fmt, x))
        return self.addRaw(propTag, data, **kwargs)

    def addInt16(self, propTag, data=None, **kwargs):
        return self.addFmt(propTag, data, 'h', **kwargs)

    def addInt32(self, propTag, data=None, **kwargs):
        return self.addFmt(propTag, data, 'i', **kwargs)

    def addInt64(self, propTag, data=None, **kwargs):
        return self.addFmt(propTag, data, 'q', **kwargs)

    def addFloat(self, propTag, data=None, **kwargs):
        return self.addFmt(propTag, data, 'f', **kwargs)

    def addDouble(self, propTag, data=None, **kwargs):
        return self.addFmt(propTag, data, 'd', **kwargs)

    def addCurrency(self, propTag, currencyId=None, **kwargs):
        return self.addInt64(propTag, currencyId, **kwargs)

    def addAppTime(self, propTag, dtm=None, **kwargs):
        data = self.convertData(propTag, dtm, datetime.now(), self.oleTime)
        return self.addDouble(propTag, data, **kwargs)

    def addError(self, propTag, data=None, **kwargs):
        return self.addInt32(propTag, data, **kwargs)

    def addBool(self, propTag, data=None, **kwargs):
        if data is None or isinstance(data, bool):
            data = 1 if data else 0
        return self.addInt16(propTag, data, **kwargs)

    def addObject(self, propTag, data=None, **kwargs):
        data = self.convertData(propTag, data, '', MapiProps.convertBinary)
        return self.addRaw(propTag, data if self.isArr(data) else [data], **kwargs)

    def addString(self, propTag, data=None, **kwargs):
        data = self.convertData(propTag, data, '', MapiProps.convertString)
        return self.addRaw(propTag, data if self.isArr(data) else [data], **kwargs)

    def addUnicode(self, propTag, data=None, **kwargs):
        data = self.convertData(propTag, data, '', MapiProps.convertUnicode)
        return self.addRaw(propTag, data if self.isArr(data) else [data], **kwargs)

    def addSysTime(self, propTag, dtm=None, **kwargs):
        data = self.convertData(propTag, dtm, datetime.now(), self.sysTime)
        return self.addInt64(propTag, data, **kwargs)

    def addGuid(self, propTag, data=None, **kwargs):
        data = self.convertData(propTag, data, uuid.uuid1(), MapiProps.convertGuid)
        return self.addRaw(propTag, data, **kwargs)

    def addBinary(self, propTag, data=None, **kwargs):
        data = self.convertData(propTag, data, '', MapiProps.convertBinary)
        return self.addRaw(propTag, data if self.isArr(data) else [data], **kwargs)

    def addBinStream(self, propTag, data=None, **kwargs):
        if not isinstance(data, MapiProps.BinStream):
            data = MapiProps.BinStream(data, **kwargs)
        return self.addBinary(propTag, data.dump(), **kwargs)

    def rtf(self, data=None, **kwargs):
        return self.addBinary(MapiEnum.PR_RTF_COMPRESSED, data, **kwargs)

    def add(self, propTag, data=None, **kwargs):
        tp = propTag & 0xFFFF
        if tp & 0x1000 != 0 and not self.isArr(data):
            raise MapiProps.ArrayMismatchError()
        if tp & 0x1000 == 0 and self.isArr(data, False):
            raise MapiProps.ArrayMismatchError()
        if tp in [MapiEnum.PT_NONE, MapiEnum.PT_NULL]:
            return self.addRaw(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_I2, MapiEnum.PT_MV_I2]:
            return self.addInt16(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_LONG, MapiEnum.PT_MV_LONG]:
            return self.addInt32(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_LONG, MapiEnum.PT_MV_LONG]:
            return self.addInt32(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_R4, MapiEnum.PT_MV_R4]:
            return self.addFlt32(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_DOUBLE, MapiEnum.PT_MV_DOUBLE]:
            return self.addFlt64(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_CURRENCY, MapiEnum.PT_MV_CURRENCY]:
            return self.addCurrency(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_APPTIME, MapiEnum.PT_MV_APPTIME]:
            return self.addAppTime(propTag, data, **kwargs)
        elif tp == MapiEnum.PT_ERROR:
            return self.addError(propTag, data, **kwargs)
        elif tp == MapiEnum.PT_BOOLEAN:
            return self.addBool(propTag, data, **kwargs)
        elif tp == MapiEnum.PT_OBJECT:
            return self.addObject(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_I8, MapiEnum.PT_MV_I8]:
            return self.addInt64(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_STRING8, MapiEnum.PT_MV_STRING8]:
            return self.addString(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_UNICODE, MapiEnum.PT_MV_UNICODE]:
            return self.addUnicode(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_SYSTIME, MapiEnum.PT_MV_SYSTIME]:
            return self.addSysTime(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_CLSID, MapiEnum.PT_MV_CLSID]:
            return self.addGuid(propTag, data, **kwargs)
        elif tp in [MapiEnum.PT_BINARY, MapiEnum.PT_MV_BINARY]:
            return self.addBinary(propTag, data, **kwargs)
        else:
            raise MapiProps.WrongTypeError()
