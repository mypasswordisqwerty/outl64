#!/usr/bin/env python
import zlib
import os
import struct
from ole import utils, olefile
from StringIO import StringIO


class OleData:

    def __init__(self, fp=None):
        self.files = {}
        if fp:
            data = utils.Utils.readFP(fp)
            fp = StringIO(zlib.decompress(data[4:]))
            f = olefile.OleFile(fp)
            for x in f.root.subnodes:
                buf = f.getFile(x)
                self.files[x] = zlib.decompress(buf[4:])

    def addFile(self, name, file):
        if isinstance(file, olefile.OleFile):
            fdata = file.dump()
        else:
            fdata = utils.Utils.readFP(file)
        self.files[name] = fdata

    def pprint(self):
        for x in self.files:
            print "---FILE " + x + "---"
            fp = StringIO(self.files[x])
            olefile.OleFile(fp).pprint()

    def dump(self):
        o = olefile.OleFile()
        for x in self.files:
            buf = self.files[x]
            p = struct.pack("<L", len(buf)) + zlib.compress(buf)
            o.setFile(x, p)
        buf = o.dump()
        return struct.pack("<L", len(buf)) + zlib.compress(buf)


if __name__ == "__main__":
    import sys
    if os.path.isfile(sys.argv[1]):
        OleData(sys.argv[1]).pprint()
        exit()
    od = OleData()
    od.addFile(sys.argv[1], sys.argv[2])
    od.pprint()
    if len(sys.argv) > 3:
        with open(sys.argv[3], "wb") as f:
            f.write(od.dump())
