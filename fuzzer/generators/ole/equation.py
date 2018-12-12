import oleobject
import olestream
import struct


class Equation(oleobject.OleObject):
    CLSID = "{0002ce02-0000-0000-c000-000000000046}"
    FILES = [
        # olestream.OleStream.NAME,
        #olestream.CompObj.NAME, olestream.ObjInfo.NAME,
        "Equation Native"]

    def __init__(self, data):
        oleobject.OleObject.__init__(self, data)
        self.minsize = 0xA9
        self.h1 = 0xc49e0002
        self.h2 = 0x5ca7c8
        self.h3 = 0x5beec4
        self.end = "\x12\x0c\x43"

    def createStream(self, name):
        if name == olestream.OleStream.NAME:
            return olestream.OleStream(None, flags=olestream.OleStream.FLAG_HINT, linkUpdate=0)
        if name == olestream.CompObj.NAME:
            return olestream.CompObj(self, fmt="DS Equation",
                                     displayName="Microsoft Equation 3.0", reserved="Equation.3")
        return olestream.StreamFactory(name, self)

    def dump(self, fname, **kwargs):
        zeros = max(0, self.minsize - len(self.data) - 10 - len(self.end))
        ln = len(self.data) + 10 + len(self.end) + zeros
        ret = struct.pack("<LLLLLLL", 0x1C, self.h1, ln, 0, self.h2, self.h3, 0)
        ret += struct.pack("<LL", 0x03010103, 0x08010A0A)
        ret += "ZZ"
        ret += self.data
        ret += self.end
        ret += "\x00" * zeros
        return ret
