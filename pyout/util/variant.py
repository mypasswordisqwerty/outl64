import struct
import uuid
import datetime
import json
import hexdump


class VariantIntf:

    def __init__(self, data, clsid=None):
        self.clsid = clsid or self.CLSID
        if isinstance(self.clsid, basestring):
            self.clsid = uuid.UUID(self.clsid)
        self.data = data

    def dump(self):
        ret = self.clsid.bytes_le
        ret += self.build()
        return ret

    def build(self):
        return self.data


class VariantPolicy:

    def __init__(self, typeFormat, ctypeFormat=None, bits=64):
        self.typeFormat = typeFormat
        self.ctypeFormat = ctypeFormat or typeFormat
        self.bits = bits


class Variant:

    POL_DEFAULT = VariantPolicy("<H")
    POL_NOTYPE = VariantPolicy(None)
    POL_DWORDTYPE = VariantPolicy("<L")
    POL_COMPLEX = VariantPolicy(None, "<H")

    VT_EMPTY = 0
    VT_NULL = 1
    VT_I2 = 2
    VT_I4 = 3
    VT_R4 = 4
    VT_R8 = 5
    VT_CY = 6
    VT_DATE = 7
    VT_BSTR = 8
    VT_DISPATCH = 9
    VT_ERROR = 10
    VT_BOOL = 11
    VT_VARIANT = 12
    VT_UNKNOWN = 13
    VT_DECIMAL = 14
    VT_I1 = 16
    VT_UI1 = 17
    VT_UI2 = 18
    VT_UI4 = 19
    VT_I8 = 20
    VT_UI8 = 21
    VT_INT = 22
    VT_UINT = 23
    VT_VOID = 24
    VT_HRESULT = 25
    VT_PTR = 26
    VT_SAFEARRAY = 27
    VT_CARRAY = 28
    VT_USERDEFINED = 29
    VT_LPSTR = 30
    VT_LPWSTR = 31
    VT_RECORD = 36
    VT_INT_PTR = 37
    VT_UINT_PTR = 38
    VT_FILETIME = 64
    VT_BLOB = 65
    VT_STREAM = 66
    VT_STORAGE = 67
    VT_STREAMED_OBJECT = 68
    VT_STORED_OBJECT = 69
    VT_BLOB_OBJECT = 70
    VT_CF = 71
    VT_CLSID = 72
    VT_VERSIONED_STREAM = 73
    VT_BSTR_BLOB = 0xfff
    VT_VECTOR = 0x1000
    VT_ARRAY = 0x2000
    VT_BYREF = 0x4000

    MAP = {'null': VT_NULL, 'i2': VT_I2, 'i4': VT_I4, 'r4': VT_R4, 'r8': VT_R8, 'currency': VT_CY,
           'apptime': VT_DATE, 'error': VT_ERROR, 'bool': VT_BOOL, 'object': VT_DISPATCH, 'i8': VT_I8,
           'str': VT_BSTR, 'unicode': VT_LPWSTR, 'systime': VT_FILETIME, 'clsid': VT_CLSID, 'bin': VT_BLOB}
    CTYPES = [VT_BSTR, VT_BLOB, VT_LPSTR, VT_LPWSTR, VT_VARIANT, VT_UNKNOWN, VT_UNKNOWN, VT_DISPATCH]
    UNICODE = [VT_LPWSTR]

    @staticmethod
    def dumpValue(val, pt=None):
        return Variant(val, pt).dump()

    @staticmethod
    def str2type(tp):
        arr = 0
        if tp.endswith('s'):
            tp = tp[:-1]
            arr = VT_ARRAY
        return arr | self.MAP[tp]

    @staticmethod
    def guessType(val):
        if isinstance(val, bool):
            return Variant.VT_BOOL
        if isinstance(val, float):
            return Variant.VT_R8
        if isinstance(val, int):
            return Variant.VT_I4
        if isinstance(val, long):
            return Variant.VT_I8
        if isinstance(val, str):
            return Variant.VT_BSTR
        if isinstance(val, unicode):
            return Variant.VT_LPWSTR
        if isinstance(val, uuid.UUID):
            return Variant.VT_CLSID
        if isinstance(val, datetimself.datetime):
            return Variant.VT_DATE
        return Variant.VT_BLOB

    def __init__(self, val=None, pt=None, policy=None, name=None):
        self.policy = policy or self.POL_DEFAULT
        self.pt = pt
        self.val = val
        self.name = name

    def setType(self, pt):
        self.pt = pt

    def __repr__(self):
        return "<VAR:{}:{}:{}>".format(str(self.name), str(self.pt), str(self.val))

    def dump(self):
        if self.pt is None:
            self.pt = Variant.guessType(self.val)
        ret = ''

        if self.policy.typeFormat and self.pt not in self.CTYPES:
            ret = struct.pack(self.policy.typeFormat, self.pt)
        if self.policy.ctypeFormat and self.pt in self.CTYPES:
            ret = struct.pack(self.policy.ctypeFormat, self.pt)

        if self.pt < self.VT_I2:
            return ret
        if self.pt in [self.VT_I2, self.VT_BOOL, self.VT_UI2]:
            ret += struct.pack("H", self.val)
        elif self.pt in [self.VT_R4, self.VT_I4, self.VT_ERROR, self.VT_UI4]:
            ret += struct.pack("I", self.val)
        elif self.pt in [self.VT_I8, self.VT_R8, self.VT_UI8, self.VT_CY, self.VT_FILETIME, self.VT_DATE]:
            ret += struct.pack("Q", self.val)
        elif self.pt == self.VT_CLSID:
            ret += self.val.bytes_le
        elif self.pt in [self.VT_UNKNOWN, self.VT_DISPATCH]:
            ret += self.val.dump()
        elif self.pt in [self.VT_BSTR, self.VT_LPWSTR, self.VT_DISPATCH, self.VT_BLOB, self.VT_VARIANT]:
            if self.pt in self.UNICODE:
                self.val = self.val.encode('utf-16le')
            ret += struct.pack("<L", len(self.val) + 2)
            ret += self.val
            ret += "\x00\x00"
        else:
            raise Exception("Unknown ole type: " + str(self.pt))
        return ret


class VariantArray:

    @staticmethod
    def dumpJson(js, policy=Variant.POL_DEFAULT):
        return VariantArray.fromJson(js, policy).dump()

    @staticmethod
    def fromJson(js, policy=Variant.POL_DEFAULT):
        return VariantArray(policy).addJson(js)

    @staticmethod
    def dumpHashAndData(arr, json, policy=Variant.POL_DEFAULT):
        return VariantArray.fromHashAndData(arr, json, policy).dump()

    @staticmethod
    def fromHashAndData(arr, json, policy=Variant.POL_DEFAULT):
        return VariantArray(policy).addArray(arr).addJson(json)

    def __init__(self, policy=Variant.POL_DEFAULT):
        self.policy = policy
        self.vars = []

    def addArray(self, arr):
        for x in arr:
            self.addVar(x)
        return self

    def addHash(self, arr):
        for key in arr:
            x = arr[key]
            if isinstance(x, (list, tuple)):
                self.addVar(x[0], x[1], key)
            else:
                self.addVar(x, key=key)
        return self

    def addJson(self, js):
        v = js
        if isinstance(js, basestring):
            v = json.loads(js)
        if isinstance(v, dict):
            self.addHash(v)
        else:
            self.addArray(v)
        return self

    def addVar(self, val, tp=None, key=None):
        if isinstance(val, (list, tuple)):
            key = val[0]
            tp = val[2] if len(val) > 2 else None
            val = val[1]
        if key is None:
            key = len(self.vars)
        return self.putVar(key, val, tp)

    def putVar(self, key, val, tp=None):
        if isinstance(tp, basestring):
            tp = Variant.str2type(tp)
        if not isinstance(val, Variant):
            val = Variant(val, tp, self.policy, key)
        else:
            val.policy = self.policy
            val.key = val.key or key
        i = 0
        while i < len(self.vars):
            if self.vars[i].name == key:
                self.vars[i].val = val.val
                break
            i += 1
        if i == len(self.vars):
            self.vars += [val]
        return self

    def getVar(self, key):
        return self.vars[key]

    def dump(self):
        ret = ''
        for x in self.vars:
            ret += x.dump()
        return ret
