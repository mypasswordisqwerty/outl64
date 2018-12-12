import anydoc


class PptFile(anydoc.AnyDoc):
    """ power point document """

    def __init__(self, isPPS, fp, isBin=None, **kwargs):
        anydoc.AnyDoc.__init__(self, fp, isBin, **kwargs)
        self.pps = isPPS
