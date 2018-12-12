#!/usr/bin/env python
import sys
from fuzzer import Fuzzer
from generators.tnef import TNEF
from generators.mapiprop import MapiProps
from pyout.enums.tnef import TnefEnum
from pyout.enums.mapi import MapiEnum
import random
import uuid


class TnefFuzzer(Fuzzer):
    PROB_RANDKEY = 0.1
    PROB_STD = 0.5
    PROB_HASVERSION = 0.7
    PROB_HASCODEPAGE = 0.3
    PROB_RANDVERSION = 0.1
    PROB_RANDCODEPAGE = 0.1
    PROB_RANDLEVEL = 0.2
    PROB_RANDTYPE = 0.2
    PROB_RANDMAPIPROPS = 0.3
    PROB_RANDMAPITYPE = 0.8
    PROB_RANDMAPIGUID = 0.3

    def __init__(self):
        Fuzzer.__init__(self, self.parseTnef)
        self.props = {}
        self.pmapi = {}
        self.types = []
        self.tmapi = []
        for x, y in TnefEnum().allValues().iteritems():
            if x.startswith('TYPE_'):
                self.types += [y]
            elif x.startswith('ID_'):
                self.props[x] = y
        for x, y in MapiEnum().allValues().iteritems():
            if x.startswith('PT_'):
                self.tmapi += [y]
            if x.startswith('PR_'):
                self.pmapi[x] = y

    def randOpts(self):
        ret = {}
        if self.prob(TnefFuzzer.PROB_RANDLEVEL):
            ret['level'] = TNEF.LVL_MESSAGE if self.prob(0.5) else TNEF.LVL_ATTACHMENT
        if self.prob(TnefFuzzer.PROB_RANDTYPE):
            ret['type'] = random.choice(self.types)
        return ret

    def version(self, tnef):
        if self.prob(TnefFuzzer.PROB_HASVERSION):
            vdata = self.randData() if self.prob(TnefFuzzer.PROB_RANDVERSION) else TNEF.DATA_VERSION
            tnef.version(vdata, **self.randOpts())
        if self.prob(TnefFuzzer.PROB_HASCODEPAGE):
            vdata = self.randData() if self.prob(TnefFuzzer.PROB_RANDCODEPAGE) else TNEF.DATA_CODEPAGE
            tnef.codePage(vdata, **self.randOpts())

    def randMapiOpts(self):
        ret = {}
        if self.prob(TnefFuzzer.PROB_RANDMAPITYPE):
            ret['type'] = random.choice(self.tmapi)
        if self.prob(TnefFuzzer.PROB_RANDMAPIGUID):
            ret['guid'] = uuid.uuid4()
            if self.prob(0.5):
                ret['map'] = random.randrange(0xFFFFFFFF)
            else:
                ret['map'] = self.randString()
        return ret

    def genMapiProps(self, isArr=False):
        ret = []
        cnt = random.randrange(10) if isArr else 1
        for i in range(cnt):
            p = MapiProps()
            prop = random.choice(self.pmapi.values())
            for j in range(random.randrange(20)):
                p.addRaw(prop, self.randData(), **self.randMapiOpts())
            ret += [p]
        return ret if isArr else ret[0]

    def addProp(self, tnef):
        prop = random.choice(self.props.keys())
        self.debug("tnef prop " + prop)
        pid = self.props[prop]
        if pid in [TnefEnum.ID_MAPIPROPS, TnefEnum.ID_ATTACHMENT,
                   TnefEnum.ID_RECIPTABLE] and not self.prob(TnefFuzzer.PROB_RANDMAPIPROPS):
            if pid == TnefEnum.ID_RECIPTABLE:
                tnef.recipTable(self.genMapiProps(True), **self.randOpts())
            else:
                tnef.addMapiProps(pid, self.genMapiProps(), **self.randOpts())
        else:
            tnef.add(pid, self.randData(), **self.randOpts())

    def generate(self, step):
        tnef = TNEF(self.randByte() if self.prob(TnefFuzzer.PROB_RANDKEY) else 0x01)
        if self.prob(TnefFuzzer.PROB_STD):
            tnef.std()
        else:
            self.version(tnef)
        cnt = 1 if self.mode == 0 else random.randrange(10)
        for i in range(cnt):
            self.addProp(tnef)
        return self.variant(tnef.dump())


if __name__ == "__main__":
    sys.exit(TnefFuzzer().run())
