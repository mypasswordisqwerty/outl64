#!/usr/bin/env python
import struct
from generators.tnef import TNEF
from pyout.enums.tnef import TnefEnum
from pyout.enums.mapi import MapiEnum
import hexdump
from datetime import datetime
from generators.mapiprop import MapiProps
from generators.asn import p7s, x509
from fuzzer import Fuzzer


def checksum(data):
    return sum([ord(x) for x in data]) & 0xFFFF


def checkBuffers(b1, b2, printDiffs=False):
    if len(b1) != len(b2):
        if printDiffs:
            print "length differs: {} {}".format(len(b1), len(b2))
        else:
            return False
    if not printDiffs:
        return b1 == b2
    for i in range(min(len(b1), len(b2))):
        if b1[i] == b2[i]:
            continue
        print "value differs at {:08X}".format(i)
        data = b1[i:min(i + 16, len(b1))]
        hexdump.hexdump(data)
        data = b2[i:min(i + 16, len(b2))]
        hexdump.hexdump(data)
        return False
    return True


# TEST 1
# check simple tnef
result = {
    0: struct.pack('I', TNEF.SIGNATURE) + struct.pack('H', 0x01),
    # version
    4 + 2: struct.pack('B', TNEF.LVL_MESSAGE) + struct.pack('I', TnefEnum.ID_TNEFVERSION) + struct.pack('i', 4) +
    struct.pack('I', TNEF.DATA_VERSION),
    17 + 4: struct.pack('B', TNEF.LVL_ATTACHMENT) + struct.pack('I', TnefEnum.ID_TNEFVERSION) +
    struct.pack('i', len("someversion")) + "someversion",
    37 + 6: struct.pack('B', TNEF.LVL_MESSAGE) + struct.pack('I', TnefEnum.ID_TNEFVERSION) +
    struct.pack('i', len("otherversion")) + "otherversion" + struct.pack('H', checksum("otherversion")),
    58 + 8: struct.pack('B', TNEF.LVL_MESSAGE) + struct.pack('I', TnefEnum.ID_OEMCODEPAGE) + struct.pack('i', 8) +
    struct.pack('Q', TNEF.DATA_CODEPAGE),
    75 + 10: struct.pack('B', TNEF.LVL_ATTACHMENT) + struct.pack('I', 0x666666) + struct.pack('i', len("somedata")) +
    "somedata" + struct.pack('H', checksum("somedata")),
}

obj = TNEF()
data = (obj
        .version()
        .version("someversion", level=TNEF.LVL_ATTACHMENT)
        .add(TnefEnum.ID_TNEFVERSION, "otherversion")
        .codePage()
        .add(0x666666, "somedata", level=TNEF.LVL_ATTACHMENT)
        .dump())
stat = "OK"
for x in result:
    res = result[x]
    rlen = len(res)
    if data[x:x + rlen] != res:
        print "Data differs at offset", x
        # print data[x:x + rlen]
        # print result[x]
        stat = "FAILED"

print "test1:", stat
# hexdump.hexdump(data)

# TEST 2
# check tnef example + mapiprops

pref = """78 9f 3e 22 01 00 01 06 90 08 00 04 00 00 00 00 00 01 00 01 00 01 07 90 06 00 08 00 00 00 e4 04 00 00 00 00 00 00
e8 00 01 08 80 07 00 20 00 00 00 49 50 4d 2e 4d 69 63 72 6f 73 6f 66 74 20 53 63 68 65 64 75 6c 65 2e 4d 74 67 52 65 73
70 4e 00 55 0b 01 0d 80 04 00 02 00 00 00 02 00 02 00 01 05 80 03 00 0e 00 00 00 d8 07 01 00 10 00 17 00 1c 00 08 00 03
00 2e 01 01 20 80 03 00 0e 00 00 00 d8 07 01 00 10 00 17 00 1c 00 08 00 03 00 2e 01 01 03 90 06 00 88 00 00 00 02 00 00
00 02 01 7f 00 01 00 00 00 0c 00 00 00"""
ckey = "38 71 6b 6a 30 30 73 67 6d 34 66 00"
mid = "02 01 09 10 01 00 00 00 5d 00 00 00"
rtf = """59 00 00 00 b3 00 00 00 4c 5a 46 75 a9 be bb ed 87 00 0a 01 0d 03 43 74 65 78 74 01 f7 ff 02 a4 03 e4 05 eb 02
83 00 50 02 f3 06 b4 02 83 26 32 03 c5 02 00 63 68 0a c0 73 65 d8 74 30 20 07 13 02 80 7d 0a 80 08 cf 3f 09 d9 02 80
0a 84 0b 37 12 c2 01 d0 20 46 10 59 49 00 7d 18 20"""
postf = "00 00 00 f7 21"

dt = datetime(2008, 1, 16, 23, 28, 8)
prop = MapiProps()
prop.add(MapiEnum.PR_TNEF_CORRELATION_KEY, hexdump.dehex(ckey))
prop.add(MapiEnum.PR_RTF_COMPRESSED, hexdump.dehex(rtf))
obj = TNEF()
data = obj.std().messageClass(TNEF.CLASS_MRESPN).priority().dateSent(dt).dateModified(dt).msgProps(prop).dump()

res = hexdump.dehex(pref + ' ' + ckey + ' ' + mid + ' ' + rtf + ' ' + postf)

print "test2:", "OK" if checkBuffers(res, data, True) else "FAILED"

# TEST3
# test p7s builder

pubkey = """00 30 82 01 0A 02 82 01 01 00 BE 93 B1 7E E5 7E 12 AE 4A C8 3F 56 AA 2D F1 EE F8 99 50 61 8A F2 3B 43 3A
11 31 57 D7 B9 FE 71 56 CB C0 A3 57 10 FC 79 1A 34 26 0D A4 67 3C 53 64 18 8B 70 AA A9 12 52 13 16 98 5E 65 2D 98 B5
66 8E 70 07 55 D4 C3 56 B1 8D 1A 87 94 9A 96 33 57 16 3E BF DC A2 D1 EB 96 6D CD 46 13 40 2C 1C 1D AF 54 B5 55 49 47
27 9D 76 5A BF 2A 78 25 A4 67 F5 2B 60 85 BF 2B 2A C4 E2 41 CF B6 4D BA 69 92 25 66 4D 1D 1C 4D 47 B5 F3 FB 39 F0 B8
BE 63 E3 B2 91 DD 17 B9 AD D0 8A 8E E6 4C 77 B4 86 9C 3E 32 AA A1 08 DA 65 E0 38 0E 8A 04 2C 17 CE 3C 71 BC 90 C8 62
1C 6E 4F 27 C8 81 34 AA FB 17 68 A7 3E E7 80 08 0C AB 87 38 40 96 85 17 38 68 03 A6 04 44 F1 05 14 83 C7 D7 DC 18 BA
5E 7B 88 96 83 47 C7 98 DF 04 F1 6D E7 01 A8 C3 FB 49 4B 6C F5 7C 6D 2D E5 20 60 5B 51 74 60 87 77 1E F7 9F 02 03 01
00 01"""
signature = """00 8C 63 B7 8D 24 55 3C 1C B0 B7 1F A9 1B 0E 67 91 E4 1F 86 8C 0A 8B C2 5A C7 3C 77 76 55 DF 86 73 01
D8 85 02 F0 F7 BE BD D2 8A 2B 13 C0 63 7E BD 00 6B 03 F9 E8 AD 9B B1 BE 78 F7 72 23 71 01 B2 ED 9F 3D 4B 73 98 75 83
AA 9C 9A 92 8F 35 14 9F A8 1F A9 7A 1E A0 04 2A A3 8B 05 65 94 F2 9D 1C A9 98 6E 6C 3C 33 44 4F 36 69 5B 4F E1 7B 9D
05 08 CC 50 E6 9C 21 63 40 52 E1 32 A4 35 E7 5D 7E 9A 22 B7 AC DE BF 25 73 9D B6 8F 19 EC E7 6D F6 8C 41 EC 0C C3 31
84 AC FE 6E 10 81 23 D7 BE 45 40 16 BE E5 AC 2C C6 11 83 F9 38 34 32 81 58 80 80 93 0F F1 8D 8F BE EB 81 84 19 1D 62
84 F4 92 43 19 0D 2C 9E BD 79 B3 D3 0F C2 26 5C CD 5B 17 F6 D8 5D 37 40 B4 D1 96 41 84 16 5F 65 FD 1D C3 7F A9 FE 6B
41 39 E6 3A D4 A4 8F 86 0B 8F 64 A4 46 7E B6 51 78 4F 0D D9 F6 CA FB FA 72 1B 6D CB"""
msgDigest = "14 8E 20 FB 1F 41 BB 6F 4A 27 36 26 1E 75 C5 EA 87 12 48 D0"
digest = """3C A5 BA A4 11 96 98 5B E0 15 32 A8 B6 ED 9A B1 E8 09 50 33 E0 5C 01 C6 E0 4C 8A 15 72 A1 43 51 40 73 94 60
8E 58 83 BF F2 E4 1F E4 7A FD 72 B6 87 CA 7B 9C EB 4D 69 16 BE B4 20 A8 61 F2 02 7C 69 D7 B3 DD C9 E7 5D 34 E4 3E D9
EC 71 44 70 1D CD 4A 62 D4 AB 8A D1 FF E8 C9 45 4C 80 0D 2D 2B CE A1 A4 62 5B 0F 57 D9 88 A2 55 A0 0C A5 79 E3 73 C6
00 18 D4 3C 5A 76 C2 AE 3F 0B 77 13 5E 5E FC F6 58 FC D1 A6 82 2C FB 6F 11 B8 9F AE 84 15 2E AE 1D A4 D3 BC 2E A8 97
31 8E 8B BF 9D F5 7C 13 B4 6B 53 9E 0B 76 B3 21 EF D8 69 59 AF EF 74 B4 F5 36 DA 95 5C A9 37 24 DB F5 A3 07 C0 6E E6
14 DE 49 30 CC 81 BB 9B B8 B8 51 B4 6B 4D C5 7A C5 69 63 74 9E 41 FC 9B 71 5B 93 D9 09 51 EC AB D5 AA 52 55 6D 0B E5
1E 02 67 EE CB 06 47 C7 73 C1 CF 7A 6A 77 A0 0E 95 90 AE 9D D8 86 23 B6 F3"""

obj = p7s.P7S()

st = x509.CertStrings()
st.setup("john", "none", "none", "none", "RU", "none", "user1@192.168.56.13")

cert = x509.Certificate()
cert.cert.issuer.replace(st)
cert.cert.subject.replace(st)
cert.cert.validity.setup('170420132219Z', '180420132219Z')
cert.cert.pubkey.setup(hexdump.dehex(pubkey))
cert.signature.setup(hexdump.dehex(signature))

iss = p7s.IssuerAndSerial()
iss[0] = st

obj.signedData.certificates[0].replace(cert)
si = obj.signedData.signerInfos[0]
si.issuerAndSerial.replace(iss)
si.attributes.signingTime.setup('170502094738Z')
si.attributes.messageDigest.setup(hexdump.dehex(msgDigest))
si.attributes.msEncryptionCert.setup(iss)
si.attributes.keyPref.setup(iss)
si.digest.setup(hexdump.dehex(digest))

data = obj.dump()

with open("../mails/cert.p7s", "rb") as f:
    res = f.read()

print "test3:", "OK" if checkBuffers(res, data, True) else "FAILED"

# obj.pprint()

fuzz = Fuzzer()
fuzz.parseArgs(None, ['-v'])
with open("crashdata0.log", "rb") as f:
    data = f.read()
print fuzz.parseTnef(fuzz.variant(data))
