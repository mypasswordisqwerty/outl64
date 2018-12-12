import base


class Algorithm(base.Sequence):

    def __init__(self, algo='sha256WithRSAEncryption', **kwargs):
        base.Sequence.__init__(self, [base.ObjectId(algo, name="id"), base.Null()], **kwargs)


class OIDParam(base.Set):

    def __init__(self, objId, stringClass, default):
        self.holder = base.Sequence([base.ObjectId(objId), stringClass(default)])
        base.Set.__init__(self, [self.holder], name=objId)

    def pprint(self, pref):
        print pref * 2 * ' ' + str(self.value[0].value[0]) + " = " + self.value[0].value[1].value

    def setup(self, value):
        self.value[0].value[1].setup(value)
        return self


class CertStrings(base.Sequence):

    def __init__(self, **kwargs):
        self.commonName = OIDParam('commonName', base.UTF8String, 'sample')
        self.organizationName = OIDParam('organizationName', base.UTF8String, 'example.com')
        self.organizationalUnitName = OIDParam('organizationalUnitName', base.UTF8String, '')
        self.stateOrProvinceName = OIDParam('stateOrProvinceName', base.UTF8String, '')
        self.countryName = OIDParam('countryName', base.PrintableString, 'US')
        self.localityName = OIDParam('localityName', base.UTF8String, '')
        self.emailAddress = OIDParam('emailAddress', base.IA5String, 'sample@example.com')
        base.Sequence.__init__(self, [self.commonName, self.organizationName, self.organizationalUnitName,
                                      self.stateOrProvinceName, self.countryName, self.localityName, self.emailAddress],
                               **kwargs)

    def setup(self, commonName, org, unit, state, country, locality, email):
        self.commonName.setup(commonName)
        self.organizationName.setup(org)
        self.organizationalUnitName.setup(unit)
        self.stateOrProvinceName.setup(state)
        self.countryName.setup(country)
        self.localityName.setup(locality)
        self.emailAddress.setup(email)
        return self


class Validity(base.Sequence):
    value = [base.UTCTime(name="notBefore"), base.UTCTime(name="notAfter")]

    def setup(self, notBefore, notAfter):
        self.value[0].setup(notBefore)
        self.value[1].setup(notAfter)
        return self


class PubKey(base.Sequence):
    value = [Algorithm('rsaEncryption'), base.BitString(name="pubkey")]

    def setup(self, data):
        self.value[1].setup(data)
        return self


class Extention(base.Sequence):
    value = [base.ObjectId(name='extId'), base.Boolean(name='critical'), base.OctetString(name='value')]


class KeyUsage(Extention):
    value = [base.ObjectId('keyUsage'), base.Boolean(True), base.OctetString("\x03\x02\x01\xFE")]


class ExtKeyUsage(Extention):
    value = [base.ObjectId('extKeyUsage'), base.Boolean(True), base.OctetString(
        "\x30\x10\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x04\x06\x04\x55\x1D\x25\x00")]


class Extentions(base.Optional):
    tag = 0xA3

    def __init__(self):
        self.extentions = base.SequenceOf(Extention, [KeyUsage(), ExtKeyUsage()])
        base.Optional.__init__(self, base.Sequence, [self.extentions])


class Cert(base.Sequence):
    optional = [base.Integer, base.Null, base.Null, Extentions]

    def __init__(self):
        self.version = base.Optional(base.Integer, [base.Integer(2)], name='version')
        self.serial = base.Integer(1, name='serial')
        self.signatureAlgorithm = Algorithm(name='signatureAlgorithm')
        self.issuer = CertStrings(name='issuer')
        self.validity = Validity()
        self.subject = CertStrings(name='subject')
        self.pubkey = PubKey(name="subjectPubkey")
        self.extentions = Extentions()
        base.Sequence.__init__(self, [self.version, self.serial, self.signatureAlgorithm,
                                      self.issuer, self.validity, self.subject, self.pubkey, self.extentions])


class Certificate(base.Sequence):

    def __init__(self):
        self.cert = Cert()
        self.algorithm = Algorithm()
        self.signature = base.BitString(name='signature')
        base.Sequence.__init__(self, [self.cert, self.algorithm, self.signature])
