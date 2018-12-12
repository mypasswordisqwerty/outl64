#!/usr/bin/env python
import zipfile
from utils import Utils
try:
    import cStringIO as StringIO
except ImportError:
    import StringIO
from xml.dom import minidom


class XFile:
    """ Zipeed xml office file """

    ROOT_FILE = "[Content_Types].xml"

    def __init__(self, fp=None, **kwargs):
        self.files = {}
        if fp:
            self.memfile = StringIO.StringIO(Utils.readFP(fp))
        else:
            self.memfile = StringIO.StringIO()
        if not fp:
            self.setXml(self.ROOT_FILE, self._typesXml())

    def _typesXml(self):
        _TYPEXML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
</Types>
"""
        return minidom.parseString(_TYPEXML)

    def getFile(self, path):
        if path in self.files:
            return self.files[path]
        z = zipfile.ZipFile(self.memfile)
        return z.read(path)

    def getXml(self, path):
        return minidom.parseString(self.getFile(path))

    def removeFile(self, path):
        self.setFile(path, None)

    def setFile(self, path, data):
        self.files[path] = data

    def setXml(self, path, xml):
        self.setFile(path, xml.toxml())

    def writeZip(self):
        if len(self.files) == 0:
            return
        mem = self.memfile
        self.memfile = StringIO.StringIO()
        i = zipfile.ZipFile(mem)
        o = zipfile.ZipFile(self.memfile, "w", zipfile.ZIP_DEFLATED)
        for f in i.infolist():
            if f.filename in self.files:
                data = self.files[f.filename]
                del self.files[f.filename]
                if data is None:
                    continue
                o.writestr(f, data)
            else:
                o.writestr(f, i.read(f))
        mem.close()
        for x in self.files:
            o.writestr(f, self.files[x])
        self.files = {}

    def dump(self):
        self.writeZip()
        return self.memfile.getvalue()

    def save(self, fname):
        with open(fname, "wb") as f:
            f.write(self.dump())


if __name__ == "__main__":
    import sys
    x = XFile(sys.argv[1])
    nm = 'ppt/slides/_rels/slide1.xml.rels'
    f = x.getXml(nm)
    print "xml", f.toxml()
    x.setFile(nm, 'hui')
    print "nu", x.getFile(nm)
    x.save("tmp.zip")
