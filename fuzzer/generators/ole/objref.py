
import struct
import uuid
from moniker import ObjRefMoniker
from . import gendata
import os


class DoubleMarshal(ObjRefMoniker):
    IID2 = uuid.UUID("{00000000-0000-0000-c000-000000000046}")

    def dump(self, filename, **kwargs):
        ret = self.OBJREF_CLSID.bytes_le
        data2 = self._dumpInternal(self.build(), self.CLSID2, self.IID2)
        ret += self._dumpInternal(self.splitter() + data2)
        return ret + self.end()

    def end(self):
        return ""

    def splitter(self):
        return ""


class ShellLink(ObjRefMoniker):
    CLSID = uuid.UUID("{00021401-0000-0000-c000-000000000046}")

    class IdList:

        def __init__(self, path):
            self.path = path

        def dump(self):
            pth = self.path
            ret = ''
            while len(pth) > 0:
                s = os.path.split(pth)
                pth, w = s if len(s) == 2 else ('', "/C:\\")
                d = struct.pack("<H", len(w) + 1) + w + "\x00"
                ret = d + ret
            return struct.pack("<H", len(ret)) + ret

    class LinkInfo:

        def __init__(self, path):
            self.path = path

        def dump(self):
            ret = struct.pack("<LLLLLL", 0x1C, 1, 0x1C, 0x30, 0, 0)
            # drv
            ret += struct.pack("<LLLLL", 0x14, 0, 0, 0x10, 0)
            ret += self.path + "\0"
            return struct.pack("<L", len(ret) + 4) + ret

    def __init__(self, data=None, **kwargs):
        ObjRefMoniker.__init__(self, None)
        self.data = data
        self.unicode = False
        self.trgList = kwargs.get('trgList') or self.IdList(data)
        self.linkInfo = kwargs.get('linkInfo')  # or self.LinkInfo(data)
        self.name = kwargs.get('name')
        self.relPath = kwargs.get('relPath')
        self.workDir = kwargs.get('workDir')
        self.arguments = kwargs.get('arguments')
        self.iconLoc = kwargs.get('iconLoc')
        self.lflags = kwargs.get('flags') or 0
        self.lflags |= 1 if self.trgList else 0
        self.lflags |= 2 if self.linkInfo else 0
        self.lflags |= 4 if self.name else 0
        self.lflags |= 8 if self.relPath else 0
        self.lflags |= 0x10 if self.workDir else 0
        self.lflags |= 0x20 if self.arguments else 0
        self.lflags |= 0x40 if self.iconLoc else 0
        self.lflags |= 0x80 if self.unicode else 0
        self.fattr = kwargs.get('fattr') or 0
        self.ctime = kwargs.get('ctime') or 0
        self.atime = kwargs.get('atime') or 0
        self.wtime = kwargs.get('wtime') or 0
        self.fsize = kwargs.get('fsize') or 0
        self.iconIdx = kwargs.get('iconIdx') or 0
        self.showCmd = kwargs.get('showCmd') or 1
        self.hotkey = kwargs.get('hotkey') or 0

    def dumpString(self, string):
        ret = struct.pack("<H", len(string))
        if self.unicode:
            ret += string.encode("utf-16le")
        else:
            ret += string
        return ret

    def build(self):
        ret = struct.pack("<L", 0x4C)
        ret += self.CLSID.bytes_le
        ret += struct.pack("<LLQQQ", self.lflags, self.fattr, self.ctime, self.atime, self.wtime)
        ret += struct.pack("<LLLH", self.fsize, self.iconIdx, self.showCmd, self.hotkey)
        ret += struct.pack("<HLL", 0, 0, 0)
        if self.trgList:
            ret += self.trgList.dump()
        if self.linkInfo:
            ret += self.linkInfo.dump()
        if self.name:
            ret += self.dumpString(self.name)
        if self.relPath:
            ret += self.dumpString(self.relPath)
        return ret


class DocFile(ObjRefMoniker):
    CLSID = uuid.UUID("{0000030b-0000-0000-c000-000000000046}")
    IID_ISTREAM = uuid.UUID("{0000000c-0000-0000-c000-000000000046}")
    IID_ISTORAGE = uuid.UUID("{0000000b-0000-0000-c000-000000000046}")

    def build(self):
        ret = self.IID_ISTORAGE.bytes_le
        self.data = gendata()
        ret += struct.pack("<L", 0xFFFFFFFF)
        ret += struct.pack("<L", len(self.data))
        ret += self.data
        return ret


class MarkupWrapper(ObjRefMoniker):
    CLSID = uuid.UUID("{e50cfa77-9bad-47a3-a1e2-038c7ad0051a}")

    def build(self):
        return struct.pack("<Q", eval(self.data))


class ClassFactory(ObjRefMoniker):
    CLSID = uuid.UUID("{ecabafc0-7f19-11d2-978e-0000f8757e2a}")

    def build(self):
        ret = struct.pack("<HH", 4, 2)
        ret += self.CLSID.bytes_le
        ret += struct.pack("<LL", 0, 0)
        ret += self.CLSID.bytes_le
        ret += struct.pack("<LL", 10, 13)
        return ret + self.data


class Dtc(ObjRefMoniker):
    CLSID = uuid.UUID("{193b4137-0480-11d1-97da-00c04fb9618a}")

    def build(self):
        ret = "A" * 0x4C
        return struct.pack("<L", len(ret)) + ret


class ContextStream(ObjRefMoniker):
    CLSID = uuid.UUID("{30510483-98b5-11cf-bb82-00aa00bdce0b}")

    def build(self):
        ret = struct.pack("<LLQ", 4, 3, eval(self.data))
        return ret


class ComCall(ObjRefMoniker):
    CLSID = uuid.UUID("{3f281000-e95a-11d2-886b-00c04f869f04}")

    def build(self):
        ret = struct.pack("<QL", eval(self.data), 1)
        return ret


class OLEDB(DoubleMarshal):
    CLSID = uuid.UUID("{58ecee30-e715-11cf-b0e3-00aa003f000f}")
    CLSID2 = uuid.UUID("{62547d24-2aca-4a33-8f15-ae95ce1a45bd}")
    IID2 = uuid.UUID("{6d5140c1-7436-11ce-8034-00aa006009fa}")

    def splitter(self):
        return struct.pack("<L", 0x20)

    def build(self):
        return gendata()


class UndoUnit(DoubleMarshal):
    CLSID = uuid.UUID("{078759d3-423b-48ad-ab6a-5638c2884dbe}")
    CLSID2 = uuid.UUID("{72c57034-02c4-4e9f-bf9c-ca711031757e}")
    IID2 = uuid.UUID("{6d5140c1-7436-11ce-8034-00aa006009fa}")

    def splitter(self):
        return struct.pack("<L", 1)

    def build(self):
        return gendata()


class WebAccount(ObjRefMoniker):
    CLSID = uuid.UUID("{db5286f5-c166-4032-95e2-70d62c8d26da}")
    IID = uuid.UUID("{2b9c347e-56fb-4947-ab47-6982bb2cf28d}")

    def build(self):
        ret = struct.pack("<L", 0x15F63A4D)
        ret += gendata()
        return ret


class WbemContext(DoubleMarshal):
    CLSID = uuid.UUID("{674b6698-ee92-11d0-ad71-00c04fd8fdff}")
    CLSID2 = uuid.UUID("{9a653086-174f-11d2-b5f9-00104b703efd}")

    def splitter(self):
        ret = struct.pack("<LL", 0, 1)
        ret += self.dumpStr("SomeString")
        ret += struct.pack("<LH", 0x66, 0x0D)
        return ret

    def build(self):
        data = gendata()
        ret = "\x00" * 0x20
        ret += struct.pack("<L", len(data))
        ret += data
        return ret


class DevInfo(ObjRefMoniker):
    CLSID = uuid.UUID("{79512918-11cd-4f7c-a294-de1ff011a194}")
    V1 = 0x8A885D04
    V2 = 0x71710533

    def build(self):
        ret = struct.pack("<LL", 0x99661002, 0xAABBCCDD)
        ret += "\x69" * 0x10
        ret += struct.pack("<L", self.V1)
        ret += gendata()
        return struct.pack("<L", len(ret)) + ret


class ILList:

    def __init__(self, val, isfile=True):
        self.val = val
        self.isfile = isfile

    def dumpStr(self, s):
        ret = struct.pack("<H", len(s) + 3) + s + "\x00"
        return ret

    def dumpDrive(self, drv):
        return self.dumpStr(drv)

    def dumpDir(self, dname):
        return self.dumpStr(dname)

    def dumpFile(self, fname):
        return self.dumpStr(fname)

    def dump(self):
        drv, path = os.path.splitdrive(self.val)
        ret = '' if len(drv) == 0 else self.dumpDrive(drv)
        pth = []
        while True:
            path, f = os.path.split(path)
            if len(f) == 0:
                if len(path) == 0:
                    break
                if path == "/" or path == "\\":
                    break
                pth += [path]
                break
            pth += [f]
        pth.reverse()
        for x in pth[:-1]:
            ret += self.dumpDir(x)
        ret += self.dumpFile(pth[-1]) if self.isfile else self.dumpDir(pth[-1])
        ret += struct.pack("<H", 0)
        return ret


class ShellArray(DoubleMarshal):
    CLSID = uuid.UUID("{f6166dad-d3be-4ebd-8419-9b5ead8d0ec7}")
    CLSID2 = uuid.UUID("{19352205-42b0-4690-9aa4-d7db9ae5f259}")
    CLSID_SVC = uuid.UUID("{3abeafc4-f48f-4517-a9b0-8ad6a94a99a1}")

    def getFileData(self, data):
        return data

    def splitter(self):
        data = ILList(self.data).dump()
        ret = struct.pack("<H", len(data)) + data
        return ret

    def build(self):
        ret = struct.pack("<L", 1)
        ret += self.CLSID_SVC.bytes_le
        ret += struct.pack("<LLLL", 0, 0, 0, 0)
        data = gendata(val="BB")
        ret += struct.pack("<L", len(data))
        ret += data
        return ret


class OTest(ObjRefMoniker):
    CLSID = uuid.UUID("{ecabb0c7-7f19-11d2-978e-0000f8757e2a}")

    def build(self):
        ret = struct.pack("<L", len(self.data))
        ret += self.data
        return ret
