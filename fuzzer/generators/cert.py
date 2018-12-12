#!/usr/bin/env python
from asn import p7s, x509
import sys
from datetime import datetime


class Cert:

    def __init__(self, fname=None):
        self.certStrings = x509.CertStrings()
        self.obj = p7s.P7S()
        self.signedData = self.obj.signedData
        self.certificates = self.signedData.certificates
        self.certificates.value = []
        self.signerInfos = self.signedData.signerInfos
        self.signerInfos.value = []
        if fname:
            self.fname = fname
            with open(fname, "rb") as f:
                data = f.read()
            try:
                self.obj.read(data)
            except Exception:
                self.obj.pprint()
                raise

    def setStrings(self, commonName, org, unit, state, country, locality, email):
        self.certStrings.setup(commonName, org, unit, state, country, locality, email)

    def addCertificate(self, x509cert=None):
        if x509cert is None:
            x509cert = self.createCertificate()
        self.certificates.value += [x509cert]

    def createCertificate(self, pubkey=None, signature=None, validFrom=None, validTo=None, certStrings=None):
        cert = x509.Certificate()
        if pubkey is not None:
            cert.cert.pubkey.setup(pubkey)
        if signature is not None:
            cert.signature.setup(signature)
        if certStrings is None:
            certStrings = self.certStrings
        if validFrom is None:
            validFrom = datetime(2000, 1, 1)
        if validTo is None:
            validTo = datetime(2070, 1, 1)
        cert.cert.validity.setup(validFrom, validTo)
        cert.cert.issuer.replace(certStrings)
        cert.cert.subject.replace(certStrings)
        return cert

    def addSignerInfo(self, sinfo=None):
        if sinfo is None:
            sinfo = self.createSignerInfo()
        self.signerInfos.value += [sinfo]

    def createSignerInfo(self, msgDigest=None, digest=None, signTime=None, certStrings=None):
        si = p7s.SignerInfo()
        if certStrings is None:
            certStrings = self.certStrings
        iss = p7s.IssuerAndSerial()
        iss[0] = certStrings
        si.issuerAndSerial.replace(iss)
        si.attributes.msEncryptionCert.setup(iss)
        si.attributes.keyPref.setup(iss)
        si.attributes.signingTime.setup(datetime.now() if signTime is None else signTime)
        if msgDigest is not None:
            si.attributes.messageDigest.setup(msgDigest)
        if digest is not None:
            si.digest.setup(digest)
        return si

    def dump(self):
        return self.obj.dump()

    def pprint(self):
        self.obj.pprint()


if __name__ == "__main__":
    Cert(sys.argv[1] if len(sys.argv) > 1 else None).pprint()
