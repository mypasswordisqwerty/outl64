import struct
import uuid
from moniker import ObjRefMoniker
from . import gendata
import os
from pyout.util.variant import *


class PersistStream(ObjRefMoniker):
    INTERCEPTOR_CLSID = uuid.UUID("{ecabafcb-7f19-11d2-978e-0000f8757e2a}")
    CLSID = None

    def dump(self, filename, **kwargs):
        ret = self.OBJREF_CLSID.bytes_le
        data = struct.pack("<QL", 0, 0x10)
        data += self.clsid.bytes_le
        data2 = self.build()
        data += struct.pack("<L", len(data2)) + data2
        ret += self._dumpInternal(data, self.INTERCEPTOR_CLSID)
        return ret

    def build(self):
        data = gendata()
        return struct.pack("<L", len(data)) + data


class InternetLink(PersistStream):
    CLSID = uuid.UUID("{fbf23b40-e3f0-101b-8488-00aa003e56f8}")

    def build(self):
        ret = """[{000214A0-0000-0000-C000-000000000046}]
Prop3=19,2
[InternetShortcut]
IDList=
URL="""
        ret += self.data + "\n"
        return ret


class Favourites(InternetLink):
    CLSID = uuid.UUID("{7ee0a24e-a8c6-46ae-a875-8e7c3d18aeaf}")


class WebBrowser(PersistStream):
    CLSID = uuid.UUID("{8856f961-340a-11d0-a96b-00c04fd705a2}")

    def build(self):
        lnk = InternetLink(self.data)
        ret = lnk.build()
        #ret += struct.pack("<L", len(self.data))
        #ret += self.data
        return ret


class BrowserBand(PersistStream):
    CLSID = uuid.UUID("{07c45bb1-4a8c-4642-a1f5-237e7215ff66}")

    def build(self):
        ret = struct.pack("<L", 1)
        ret += self.data
        return ret


class QuickLinks(PersistStream):
    CLSID = uuid.UUID("{f2cf5485-4e02-4f68-819c-b92de9277049}")

    def build(self):
        ret = struct.pack("<L", 8)
        ret += self.data
        ret += self.data
        return ret


class BandSite(PersistStream):
    CLSID = uuid.UUID("{bfad62ee-9d54-4b2a-bf3b-76f90697bd2a}")

    def build(self):
        ret = struct.pack("<LLQL", 1, 1, 1, 0)
        ret += self.data
        return ret


class DeskBarApp(PersistStream):
    CLSID = uuid.UUID("{3ccf8a41-5c85-11d0-9796-00aa00b90adf}")
    IEID = uuid.UUID("{15d633e2-ad00-465b-9ec7-f56b7cdf8e27}")

    def build(self):
        ret = struct.pack("<LLLL", 8, 1, 0x4C, 8)
        ret += "\x00" * 0x44
        ret += struct.pack("<LLLL", 0x0C, 8, 1, 0)
        ret += self.IEID.bytes_le
        ret += struct.pack("<L", len(self.data))
        ret += self.data
        return ret


class HLink(PersistStream):
    CLSID = uuid.UUID("{79eac9d0-baf9-11ce-8c82-00aa004ba90b}")

    def build(self):
        ret = struct.pack("<LLL", 0, 0, 0)


class WordpadFilter(PersistStream):
    CLSID = uuid.UUID("{6047f837-d527-467e-9dc1-6d51f92d9e45}")

    def build(self):
        return self.data


class ShellGroup(PersistStream):
    CLSID = uuid.UUID("{4f58f63f-244b-4c07-b29f-210be59be9b4}")

    def build(self):
        ret = """
        <?c:Version="1"?>
        <xml>
        </xml>
        """
        return ret


class Azrole(PersistStream):
    CLSID = uuid.UUID("{1f5eec01-1214-4d94-80c5-4bdcd2014ddd}")

    def getFileData(self, data):
        return data

    def build(self):
        ret = struct.pack("<LLLLL", 7, 0x66, 0, 1, 0x3)
        ret += self.dumpStr("AdminCheck")
        ret += self.dumpStr(self.data)
        return ret


class MimeMessage(PersistStream):
    CLSID = uuid.UUID("{fd853ce3-7f86-11d0-8252-00c04fd85ab4}")

    def build(self):
        ret = "\r\n"
        ret += "MIME-Version: 1.0\r\n"
        ret += "Content-Type: Multipart/Mixed; boundary=tiger-lily\r\n\r\n"
        ret += "--tiger-lily\r\n"
        ret += "Content-Type: text/html\r\n\r\n"
        ret += "<html><head><script>alert('working');</script></head><body></body></html>"
        ret += "--tiger-lily--\r\n"
        return ret


class PDF(PersistStream):
    CLSID = uuid.UUID("{6c337b26-3e38-4f98-813b-fba18bab64f5}")

    def build(self):
        return self.data[17:]


class FilterGraph(PersistStream):
    CLSID = uuid.UUID("{e436ebb3-524f-11ce-9f53-0020af0ba770}")
    CLSID_URLSOURCE = "{e436ebb6-524f-11ce-9f53-0020af0ba770}"

    def build(self):
        s = '2 FILTERS 66 "VALUE1" '
        s += self.CLSID_URLSOURCE
        s += ' SOURCE "' + self.data + '"'
        ret = s.encode("utf-16le")
        return ret


class Shortcut(PersistStream):
    CLSID = uuid.UUID("{00021401-0000-0000-c000-000000000046}")

    def build(self):
        ret = struct.pack("<L", 0x4C)
        ret += self.CLSID.bytes_le
        ret += gendata(0x3C, "BB")
        ret += gendata()
        return ret
