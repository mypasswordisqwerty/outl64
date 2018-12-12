# -*- coding: utf-8 -*-
import idautils
import idc
import idaapi
from pyout.classes.logger import Logger
from pyout.enums.tnef import TnefEnum
from pyout.enums.mapi import MapiEnum
from pyout.pyoutida import HexraysPlugin, MODS
util = MODS.util


class Test:
    """ Test reloadable class. Feel free to change run method and call IDA().test() """

    def __init__(self):
        pass

    def show(self, txt):
        util.showText(txt, "TEST")

    def run(self, **kwargs):
        Logger.debug("Test run with params: " + str(kwargs))
        return self.showTnefTbl()

    def showTnefTbl(self):
        s = MODS.struct.Struct('TnefPropDescr')
        res = "Tnef Prop -> Mapi PropTag\n{0:40s}\ttypeId\tMapiPropTag\n".format("TnefValue")
        mp = MapiEnum()
        tn = TnefEnum()
        for y, x in s.instances().iteritems():
            print str(x)
            tvl = tn.name(x['tnefId'])
            ptvl = mp.name(x['propTag']) if x['propTag'] != 0 else "None"
            res += "{0:40s}\t{1:5d}\t{2}\n".format(tvl, x['typeId'], ptvl)
        self.show(res)
