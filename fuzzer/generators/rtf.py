#!/usr/bin/env python
from PyRTF.Elements import *
from PyRTF.document.section import Section
import struct
import binascii
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO


class RTFCompressor:

    COMPRESSED = 0x75465A4C
    UNCOMPRESSED = 0x414C454D

    def __init__(self):
        pass

    def compressRtf(self, data):
        ret = struct.pack("III", len(data), self.UNCOMPRESSED, 0)
        ret += data
        return struct.pack("I", len(ret)) + ret

    def decompressRtf(self, data):
        return data

    @staticmethod
    def compress(data):
        return RTFCompressor().compressRtf(data)

    @staticmethod
    def decompress(data):
        return RTFCompressor().decompressRtf(data)


class RTF(Section):
    """ RTF Generator """

    class RtfObject:
        OBJ_EMBED = "objemb"
        OBJ_LINK = "objlink"
        OBJ_AUTOLINK = "objautlink"
        LINK = 1
        EMBED = 2

        def __init__(self, cls, data, objType=OBJ_EMBED, width=100, height=100, version=0x501, embedType=None,
                     name=None, topic=None, item=None, networkName=None, linkUpdate=0):
            self.cls = cls
            self.data = data
            self.otype = objType
            self.w = width
            self.h = height
            self.version = version
            self.etype = embedType or (2 if objType == EMBED else 1)
            self.name = name or cls
            self.topic = topic
            self.item = item
            self.nname = networkName
            self.lupdate = linkUpdate

        def hex(self, val, fmt="<L", split=39):
            split *= 2
            buf = struct.pack(fmt, val) if fmt else val
            data = binascii.hexlify(buf)
            ret = ''
            while len(data) > split:
                ret += data[:split] + "\n"
                data = data[split:]
            ret += data + "\n"
            return ret

        def buf(self, buf):
            ln = len(buf) if buf else 0
            ret = self.hex(ln)
            if ln:
                ret += self.hex(buf, None)
            return ret

        def string(self, s):
            return self.buf(s + "\x00" if s else None)

        def build(self):
            ret = "{\\object\\%s\\objupdate\\objw%d\\objh%d{\\*\\objclass %s}{\\*\\objdata\n" % (
                self.otype, self.w, self.h, self.cls)
            # ole 1.0 header
            ret += self.hex(self.version) + self.hex(self.etype)
            ret += self.string(self.name) + self.string(self.topic) + self.string(self.item)
            # link object fields
            if self.etype == self.LINK:
                ret += self.string(self.nname) + self.hex(0) + self.hex(self.lupdate)
            # native data
            ret += self.buf(self.data)
            # presentation object
            ret += self.hex(self.version) + self.hex(0)
            ret += "}}\n"
            return ret

    def __init__(self, doc=None, *args, **kwargs):
        Section.__init__(self, *args, **kwargs)
        self.doc = doc or Document(self.defaultStyle())
        self.doc.Sections.append(self)

    def defaultStyle(self):
        cols = Colours()
        cols.append(Colour('Black', 0, 0, 0))
        fonts = Fonts()
        fonts.append(Font('Arial', 'swiss', 0, 2, '020b0604020202020204'))
        ret = StyleSheet(cols, fonts)
        ps = ParagraphStyle('Normal', TextStyle(TextPropertySet(ret.Fonts.Arial, 22)))
        ret.ParagraphStyles.append(ps)
        return ret

    def customWrite(self, render, elem):
        render._write(elem.build())

    def addObject(self, cls, buf, **kwargs):
        obj = RTF.RtfObject(cls, buf, **kwargs)
        self.append(obj)
        return obj

    def addObjectFile(self, cls, fp, **kwargs):
        if isinstance(fp, basestring):
            fp = open(fp, mode="rb")
        return self.addObject(cls, fp.read(), **kwargs)

    def dump(self):
        buf = StringIO()
        rnd = Renderer(self.customWrite)
        rnd.Write(self.doc, buf)
        return buf.getvalue()

    def pprint(self):
        print self.dump()

if __name__ == "__main__":
    from officefile import OfficeFile
    import ole
    from ole import moniker, oleobject, utils
    import sys
    import os

    if len(sys.argv) < 2:
        print "Usage: rtf.py monikerClass stringOrFile\nExamples:\n"
        print "rtf.py ole.monikers.UrlMoniker http://www.local/file.html"
        print "rtf.py XmlMoniker ./xmlmonstream.bin"
        sys.exit(1)
    if os.path.isfile(sys.argv[1]):
        data = open(sys.argv[1], "rb").read()
    else:
        Cls = ole.getOleObject(sys.argv[1])
        obj = Cls(sys.argv[2])
        data = OfficeFile.OLEObject(obj)
    rtf = RTF()
    rtf.addObject("OfficeDOC", data, objType=RTF.RtfObject.OBJ_AUTOLINK, embedType=RTF.RtfObject.EMBED)
    print rtf.dump()
