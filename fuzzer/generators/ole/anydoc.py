from utils import OleError
import olefile
import xfile


class AnyDoc:
    """ Proxy for CFB olefile or zipped xml office files """

    def __init__(self, fp, isBin=None, **kwargs):
        if fp is None and isBin is None:
            raise OleError("Need file or isBin parameter")
        if isBin is None:
            isBin = olefile.OleFile.detect(fp)
        self.isBin = isBin
        if isBin:
            self.file = olefile.OleFile(fp, **kwargs)
        else:
            self.file = xfile.XFile(fp, **kwargs)

    def getObject(self, name):
        if self.isBin:
            return self.file.getFile(name)
        else:
            return self.file.getXml(name)

    def setObject(self, name, obj):
        if self.isBin:
            self.file.setFile(name, obj)
        else:
            self.file.setXml(name, obj)

    def dump(self):
        return self.file.dump()

    def save(self, fname):
        self.file.save(fname)
