import idaapi
import idc


class DictChooser(idaapi.Choose2):

    def __init__(self, title, data, cols=None, jumpProc=None):
        self.jumpProc = jumpProc
        if isinstance(data, dict):
            self.data = []
            for x in sorted(data.keys()):
                self.data += [data[x]]
        else:
            self.data = data
        self._cols = cols
        if not self._cols:
            self._cols = []
            for x in self.data[0].keys():
                self._cols += [[x]]
        sc2 = self._cols
        self._cols = []
        for x in sc2:
            if not isinstance(x, list):
                x = [x]
            if len(x) < 2:
                x += [10]
            self._cols += [x]
        idaapi.Choose2.__init__(self, title, self._cols)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        dt = self.data[n]
        ret = []
        for x in self._cols:
            v = dt.get(x[0])
            v = "{:X}h".format(v) if x[
                1] & idaapi.Choose2.CHCOL_HEX != 0 and v else str(v)
            ret += [v]
        return ret

    def OnGetSize(self):
        return len(self.data)

    def OnSelectLine(self, n):
        dt = self.data[n]
        if self.jumpProc:
            self.jumpProc(dt)
            return
        for x in self._cols:
            if x[0].lower() != 'address':
                continue
            v = dt.get(x[0])
            if v:
                idc.Jump(v)
