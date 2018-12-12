import uuid
import os
import olestream
from utils import Utils


class OleObject:
    """ OleObject stream base """

    def __init__(self, data=None, clsid=None, files=None):
        self.files = files or self.FILES
        clsid = clsid or self.CLSID
        data = self.getFileData(data)
        if isinstance(clsid, basestring):
            clsid = uuid.UUID(clsid)
        self.clsid = clsid
        self.data = data

    def getFileData(self, data):
        if data and os.path.isfile(data):
            data = open(data, "rb").read()
        return data

    def createStream(self, name):
        return olestream.StreamFactory(name, self)

    def save(self, olefile):
        olefile.root.clsid = self.clsid
        for x in self.files:
            wr = self.createStream(x)
            olefile.setFile(x, wr.dump(x) if wr else self.dump(x))

    def dump(self, fname, **kwargs):
        return self.data


class StdOleLinkNonMoniker(OleObject):
    """ NonMoniker link stream base """
    FILES = [olestream.OleStream.NAME, olestream.OlePresentation.NAME, olestream.CompObj.NAME, "CONTENTS"]
    STDOLE_CLSID = uuid.UUID("{00000300-0000-0000-C000-000000000046}")
    APPID = uuid.UUID("{00000300-0000-0000-C000-000000000046}")
    FORMAT = "Embedded Object"
    # Link Source; Data Object; Embedded Object

    def createStream(self, name):
        if name == olestream.OleStream.NAME:
            return olestream.OleStream(None,
                                       relative=True,
                                       appid=self.APPID)
        if name == olestream.OlePresentation.NAME:
            return olestream.OlePresentation(self, fmt=self.FORMAT)
        if name == olestream.CompObj.NAME:
            return olestream.CompObj(self, fmt=self.FORMAT)
        return olestream.StreamFactory(name, self)

    def save(self, olefile):
        OleObject.save(self, olefile)
        olefile.root.clsid = self.STDOLE_CLSID

    def dump(self, filename, **kwargs):
        if filename == olestream.OleStream.NAME:
            return self.clsid.bytes_le
        return self.data


class MSWebBrowser1(StdOleLinkNonMoniker):
    CLSID = uuid.UUID("{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}")
    FORMAT = "text/html"


class OutlookFileAttachment(OleObject):
    FILES = [olestream.OleStream.NAME, olestream.OlePresentation.NAME, "CONTENTS"]
    CLSID = uuid.UUID("{0006F031-0000-0000-C000-000000000046}")

    def createStream(self, name):
        if name == olestream.OlePresentation.NAME:
            return olestream.OlePresentation(self, fmt="text/html")
        return OleObject.createStream(self, name)


class OutlookMessageAttachment(OleObject):
    FILES = [olestream.OleStream.NAME, olestream.OlePresentation.NAME, "CONTENTS"]
    CLSID = uuid.UUID("{0006F032-0000-0000-C000-000000000046}")

    def createStream(self, name):
        if name == olestream.OlePresentation.NAME:
            return olestream.OlePresentation(self, fmt="UniformResourceLocator")
        return OleObject.createStream(self, name)


class PictureMetafile(OleObject):
    """ combase.dll """
    FILES = [olestream.OleStream.NAME, olestream.OlePresentation.NAME, "CONTENTS"]
    CLSID = uuid.UUID("{00000319-0000-0000-C000-000000000046}")

    def createStream(self, name):
        if name == olestream.OlePresentation.NAME:
            return olestream.OlePresentation(self, fmt=14)
        return OleObject.createStream(self, name)
