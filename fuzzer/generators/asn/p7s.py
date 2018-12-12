import base
import x509


class DigestAlgorithms(base.Set):
    value = [x509.Algorithm('hashAlgorithmIdentifier')]


class ContentInfo(base.Sequence):
    optional = [base.OctetString]
    infinite = True
    value = [base.ObjectId('data', name='data')]


class IssuerAndSerial(base.Sequence):
    value = [x509.CertStrings(name='issuer'), base.Integer(1, name='serial')]


class Attribute(base.Sequence):
    value = [base.ObjectId(), base.Set()]

    def setup(self, value):
        self.value[1].value[0].setup(value)


class AttContentType(Attribute):
    value = [base.ObjectId('contentType'), base.Set([base.ObjectId('data')])]


class AttSigningTime(Attribute):
    value = [base.ObjectId('signing-time'), base.Set([base.UTCTime()])]


class AttMessageDigest(Attribute):
    value = [base.ObjectId('messageDigest'), base.Set([base.OctetString()])]


class AttMSEncryptionCert(Attribute):
    value = [base.ObjectId('Microsoft_Encryption_Cert'), base.Set([IssuerAndSerial()])]

    def setup(self, value):
        self.value[1].value[0].setup(value.value)


class Cap(base.Sequence):

    def __init__(self, algo, val=None):
        value = [base.ObjectId(algo)]
        if val is not None:
            value += [base.Integer(val)]
        base.Sequence.__init__(self, value)

    def pprint(self, pref):
        s = str(self.value[0])
        if len(self.value) > 1:
            s += ' ' + str(self.value[1].value)
        print pref * 2 * ' ' + s


class SMIMECaps(base.Sequence):
    value = [Cap('aes256-CBC'), Cap('aes192-CBC'), Cap('des-ede3-cbc'), Cap('aes128-CBC'), Cap('rc2-cbc', 128),
             Cap('rc2-cbc', 64), Cap('hashAlgorithmIdentifier'), Cap('sha512'), Cap('sha384'), Cap('sha256')]


class AttSMIMECaps(Attribute):
    value = [base.ObjectId('smimeCapabilities'), base.Set([SMIMECaps()])]


class AttKeyPref(Attribute):
    value = [base.ObjectId('id-aa-encrypKeyPref'), base.Set([IssuerAndSerial(tag=0xA0)])]

    def setup(self, value):
        self.value[1].value[0].setup(value.value)


class Attributes(base.Optional):

    def __init__(self):
        self.contentType = AttContentType()
        self.signingTime = AttSigningTime()
        self.messageDigest = AttMessageDigest()
        self.msEncryptionCert = AttMSEncryptionCert()
        self.smimeCaps = AttSMIMECaps()
        self.keyPref = AttKeyPref()
        base.Optional.__init__(self,
                               Attribute,
                               [self.contentType,
                                self.signingTime,
                                self.messageDigest,
                                self.msEncryptionCert,
                                self.smimeCaps,
                                self.keyPref])


class SignerInfo(base.Sequence):

    def __init__(self):
        self.version = base.Integer(1, name='version', check=True)
        self.issuerAndSerial = IssuerAndSerial()
        self.digestAlgorithm = x509.Algorithm('hashAlgorithmIdentifier', name='digestAlgorithm')
        self.attributes = Attributes()
        self.encryptionAlgorithm = x509.Algorithm('rsaEncryption', name="encryptionAlgorithm")
        self.digest = base.OctetString(name='digest')
        base.Sequence.__init__(self,
                               [self.version,
                                self.issuerAndSerial,
                                self.digestAlgorithm,
                                self.attributes,
                                self.encryptionAlgorithm,
                                self.digest])


class SignedData(base.Sequence):
    optional = [x509.Certificate]
    infinite = True

    def __init__(self):
        self.version = base.Integer(1, name='version', check=True)
        self.digestAlgorithms = DigestAlgorithms()
        self.contentInfo = ContentInfo()
        self.certificates = base.Optional(x509.Certificate, [x509.Certificate()], name='certificates')
        self.signerInfos = base.Set([SignerInfo()], name="signerInfos")
        base.Sequence.__init__(self, [self.version, self.digestAlgorithms,
                                      self.contentInfo, self.certificates, self.signerInfos])


class P7S(base.Sequence):
    infinite = True
    optional = [SignedData]

    def __init__(self):
        self.contentType = base.ObjectId('signedData', name='contentType', check=True)
        self.signedData = SignedData()
        self.content = base.Optional(SignedData, [self.signedData], name='data', infinite=True)
        base.Sequence.__init__(self, [self.contentType, self.content])
