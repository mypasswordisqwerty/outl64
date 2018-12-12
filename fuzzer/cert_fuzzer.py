#!/usr/bin/env python
import sys
from fuzzer import Fuzzer
from generators.cert import Cert
import random


class CertFuzzer(Fuzzer):
    PROB_RANDVALUE = 0.5
    MAX_CERTS = 10
    MAX_INFO = 3

    def __init__(self):
        Fuzzer.__init__(self, self.parseCert)

    def randomize(self, value):
        if isinstance(value.value, (tuple, list)):
            for x in value.value:
                self.randomize(x)
        elif self.prob(CertFuzzer.PROB_RANDVALUE):
            value.value = self.randData()

    def generate(self, step):
        cert = Cert()
        for i in range(random.randrange(CertFuzzer.MAX_CERTS)):
            c = cert.createCertificate(self.randData(), self.randData())
            cert.addCertificate(c)
        for i in range(random.randrange(CertFuzzer.MAX_INFO)):
            s = cert.createSignerInfo(self.randData(), self.randData())
            cert.addSignerInfo(s)
        if self.mode & 2 == 0:
            self.randomize(cert.obj)
        return self.variant(cert.dump())


if __name__ == "__main__":
    sys.exit(CertFuzzer().run())
