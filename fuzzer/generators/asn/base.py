import hexdump
import re
import copy
from pyout.util.oids import Oids
from datetime import datetime
import time

ctx = None


class Error(Exception):
    """ ASN Error """


class ASNBase:
    tag = 0x00
    value = None
    infinite = False

    def __init__(self, value=None, **kwargs):
        self.name = kwargs.get('name') or self.__class__.__name__
        self.value = copy.deepcopy(self.__class__.value) if value is None else self.convertValue(value)
        self.checkValue = kwargs.get('check') or False
        self.tag = kwargs.get('tag') or self.__class__.tag
        self.infinite = kwargs.get('infinite') or self.__class__.infinite

    def __getitem__(self, idx):
        return self.value[idx]

    def __setitem__(self, idx, value):
        self.value[idx] = value

    def readTagLength(self, bytes):
        tag = ord(bytes[0])
        if tag != self.tag:
            raise Error("Wrong tag: 0x{:02X} expected: 0x{:02X}".format(tag, self.tag))
        ln = ord(bytes[1])
        idx = 2
        if ln == 0:
            return (None, idx)
        if ln & 0x80 != 0:
            ln = ln & 0x7F
            if ln > 0:
                sz = ln
                ln = 0
                for i in range(sz):
                    ln <<= 8
                    ln |= ord(bytes[idx])
                    idx += 1
        return (ln, idx)

    def convertValue(self, value):
        return value

    def setValue(self, value):
        val = self.convertValue(value)
        if self.checkValue and val != self.value:
            raise Error("ASN value not match: {} vs {}", value, self.value)
        self.value = val

    def readValue(self, bytes, sz):
        self.setValue(bytes)
        return len(bytes)

    def read(self, bytes):
        sz, idx = self.readTagLength(bytes)
        if sz is None:
            return idx
        data = bytes[idx:idx + sz] if sz != 0 else bytes[idx:]
        return idx + self.readValue(data, sz)

    def bytes2s(self, arr, reverse=True):
        ret = ''
        if reverse:
            arr.reverse()
        for x in arr:
            ret += chr(x)
        return ret

    def dumpValue(self):
        return self.value

    def dump(self):
        val = self.dumpValue()
        ret = chr(self.tag)
        if val is None:
            ret += "\x00"
            return ret
        if self.infinite:
            ret += "\x80"
            ret += val
            ret += "\x00\x00"
        else:
            ln = len(val)
            vls = []
            while ln > 0:
                vls += [ln & 0xFF]
                ln >>= 8
            if len(vls) == 1 and vls[0] < 0x80:
                ret += chr(vls[0])
            else:
                ret += chr(0x80 + len(vls))
                ret += self.bytes2s(vls)
            ret += val
        return ret

    def pprint(self, pref=0):
        if pref == 0:
            print '----'
        if isinstance(self.value, (list, tuple)):
            print pref * 2 * ' ' + str(self) + "{"
            for x in self.value:
                x.pprint(pref + 1)
            print pref * 2 * ' ' + "}"
        else:
            print pref * 2 * ' ' + str(self)

    def __str__(self):
        return self.name + ': ' + str(self.value)

    def setup(self, data):
        self.value = data

    def replace(self, other):
        self.value = other.value


class Boolean(ASNBase):
    tag = 0x01

    def readValue(self, bytes, sz):
        if sz != 1:
            raise Error("ASN bool size error")
        self.setValue(bytes[0] != 0)
        return 1

    def dumpValue(self):
        return "\xFF" if self.value else "\x00"


class Integer(ASNBase):
    tag = 0x02

    def readValue(self, bytes, sz):
        values = [ord(b) for b in bytes[:sz]]
        # check if the integer is normalized
        if len(values) > 1 and (values[0] == 0xff and values[1] & 0x80 or values[0] == 0x00 and not (values[1] & 0x80)):
            raise Error('ASN1 syntax error')
        negative = values[0] & 0x80
        if negative:
            # make positive by taking two's complement
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        self.setValue(value)
        return sz

    def dumpValue(self):
        if isinstance(self.value, basestring):
            return self.value
        value = self.value
        if value < 0:
            value = -value
            negative = True
            limit = 0x80
        else:
            negative = False
            limit = 0x7f
        values = []
        while value > limit:
            values.append(value & 0xff)
            value >>= 8
        values.append(value & 0xff)
        if negative:
            # create two's complement
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values)):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i != len(values) - 1
                values[i] = 0x00
        return self.bytes2s(values)


class Bytes(ASNBase):

    def __str__(self):
        return self.name + ': ' + (hexdump.dump(self.value) if self.value else str(self.value))


class BitString(Bytes):
    tag = 0x03


class OctetString(Bytes):
    tag = 0x04


class Null(ASNBase):
    tag = 0x05

    def __str__(self):
        return self.name + ': NULL'


class ObjectId(ASNBase):
    tag = 0x06

    def convertValue(self, val):
        if not ctx.reOid.match(val):
            return ctx.oids.oidByName(val)
        return val

    def readValue(self, bytes, sz):
        result = []
        value = 0
        for i in range(sz):
            byte = ord(bytes[i])
            if value == 0 and byte == 0x80:
                raise Error('ASN1 syntax error')
            value = (value << 7) | (byte & 0x7f)
            if not byte & 0x80:
                result.append(value)
                value = 0
        if len(result) == 0 or result[0] > 1599:
            raise Error('ASN1 syntax error')
        result = [result[0] // 40, result[0] % 40] + result[1:]
        result = list(map(str, result))
        self.setValue(str('.'.join(result)))
        return sz

    def dumpValue(self):
        oid = self.value
        if not ctx.reOid.match(oid):
            return self.value
#           raise Error('Illegal object identifier')
        cmps = list(map(int, oid.split('.')))
        if cmps[0] > 39 or cmps[1] > 39:
            raise Error('Illegal object identifier')
        cmps = [40 * cmps[0] + cmps[1]] + cmps[2:]
        cmps.reverse()
        result = []
        for cmp_data in cmps:
            result.append(cmp_data & 0x7f)
            while cmp_data > 0x7f:
                cmp_data >>= 7
                result.append(0x80 | (cmp_data & 0x7f))
        return self.bytes2s(result)

    def __str__(self):
        if self.value is not None:
            val = self.value + " (" + ctx.oids.getOid(self.value) + ")"
        else:
            val = str(self.value)
        return self.name + ": " + val


class UTF8String(ASNBase):
    tag = 0x0C


class PrintableString(ASNBase):
    tag = 0x13


class IA5String(ASNBase):
    tag = 0x16


class UTCTime(ASNBase):
    tag = 0x17

    def setup(self, value):
        if isinstance(value, datetime):
            self.value = str(int(time.mktime(value.timetuple()))) + 'Z'
        else:
            self.value = value


class Container(ASNBase):
    tag = 0x20
    optional = []

    def __init__(self, value=None, **kwargs):
        ASNBase.__init__(self, value, **kwargs)
        self.optional = kwargs.get('optional') or self.__class__.optional

    def createSub(self, tag):
        if tag & 0xA0 != 0:
            return self.optional[tag - 0xA0](tag=tag)
        return ctx.factory(tag)

    def readValue(self, bytes, sz):
        pos = 0
        if self.value is None:
            self.value = []
        oid = 0
        while True:
            # print pos, len(bytes), sz
            obj = None
            tag = ord(bytes[pos])
            if sz == 0 and tag == 0 and ord(bytes[pos + 1]) == 0:
                return pos + 2
            if len(self.value) < oid + 1:
                obj = self.createSub(tag)
                self.value += [obj]
            else:
                obj = self.value[oid]
            oid += 1
            pos += obj.read(bytes[pos:])
            if sz != 0 and pos == len(bytes):
                return pos

    def dumpValue(self):
        ret = ''
        for x in self.value:
            ret += x.dump()
        return ret

    def __str__(self):
        return self.name


class ContainerOf(Container):

    def __init__(self, cls=None, value=None, **kwargs):
        Container.__init__(self, value, **kwargs)
        self.cls = cls

    def createSub(self, tag):
        if self.cls is None:
            return Container.createSub(self, tag)
        return self.cls()

    def __str__(self):
        return self.name + ": (array of " + (self.cls.__name__ if self.cls else 'unknown') + ")"


class Sequence(Container):
    tag = 0x30


class Set(Container):
    tag = 0x31


class SequenceOf(ContainerOf):
    tag = 0x30


class SetOf(ContainerOf):
    tag = 0x31


class Optional(ContainerOf):
    tag = 0xA0


class Context:
    tags = {
        0x01: Boolean,
        0x02: Integer,
        0x03: BitString,
        0x04: OctetString,
        0x05: Null,
        0x06: ObjectId,
        0x0C: UTF8String,
        0x13: PrintableString,
        0x16: IA5String,
        0x17: UTCTime,
        0x20: Container,
        0x30: Sequence,
        0x31: Set,
    }

    def __init__(self):
        self.oids = Oids()
        self.reOid = re.compile(r"^[012]\.\d+(\.\d+)+$")

    def factory(self, tag, optional):
        if tag not in Context.tags:
            raise Error("Unknown tag 0x{:02X}".format(tag))
        cls = Context.tags[tag]
        return cls(tag=tag)


ctx = Context()
