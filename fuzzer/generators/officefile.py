#!/usr/bin/env python
import ole
import uuid


class OfficeFile:

    def __init__(self, mode=ole.MODE_OLE, pig=None):
        self.mode = mode
        self.file = ole.createOleFile(mode, pig)

    def insertOLE(self, oleObj):
        oleObj.save(self.file)

    def pprint(self):
        self.file.pprint()

    def dump(self):
        return self.file.dump()

    @staticmethod
    def OLEObject(object):
        file = OfficeFile(ole.MODE_OLE)
        file.insertOLE(object)
        return file.dump()

    @staticmethod
    def PPSX(relstring):
        file = OfficeFile(ole.MODE_PPSX)
        return file.dump()


if __name__ == "__main__":
    import sys
    Cls = ole.getOleObject(sys.argv[1])
    obj = Cls(sys.argv[2])
    of = OfficeFile()
    of.insertOLE(obj)
    of.pprint()
    if len(sys.argv) > 3:
        with open(sys.argv[3], "wb") as f:
            f.write(of.dump())
