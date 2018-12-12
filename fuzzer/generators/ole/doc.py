import anydoc
import olefile
import xfile


class DocFile(anydoc.AnyDoc):
    """ word document """

    def __init__(self, fp, isBin=None, **kwargs):
        anydoc.AnyDoc.__init__(self, fp, isBin, **kwargs)
