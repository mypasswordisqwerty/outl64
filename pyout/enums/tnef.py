from pyout.classes.nenum import NEnum


class TnefEnum(NEnum):

    TYPE_TRIPLES = 0x00000000
    TYPE_STRING = 0x00010000
    TYPE_TEXT = 0x00020000
    TYPE_DATE = 0x00030000
    TYPE_SHORT = 0x00040000
    TYPE_LONG = 0x00050000
    TYPE_BYTE = 0x00060000
    TYPE_WORD = 0x00070000
    TYPE_DWORD = 0x00080000

    ATT_TNEFVERSION = 0x9006
    ATT_OEMCODEPAGE = 0x9007
    ATT_OWNER = 0x0000
    ATT_SENTFOR = 0x0001
    ATT_DELEGATE = 0x0002
    ATT_DATESTART = 0x0006
    ATT_DATEEND = 0x0007
    ATT_AIDOWNER = 0x0008
    ATT_REQUESTRES = 0x0009
    ATT_FROM = 0x8000
    ATT_SUBJECT = 0x8004
    ATT_DATESENT = 0x8005
    ATT_DATERECD = 0x8006
    ATT_MESSAGESTATUS = 0x8007
    ATT_MESSAGECLASS = 0x8008
    ATT_MESSAGEID = 0x8009
    ATT_PARENTID = 0x800A
    ATT_CONVERSATIONID = 0x800B
    ATT_BODY = 0x800C
    ATT_PRIORITY = 0x800D
    ATT_ATTACHDATA = 0x800F
    ATT_ATTACHTITLE = 0x8010
    ATT_ATTACHMETAFILE = 0x8011
    ATT_ATTACHCREATEDATE = 0x8012
    ATT_ATTACHMODIFYDATE = 0x8013
    ATT_DATEMODIFIED = 0x8020
    ATT_ATTACHTRANSPORTFILENAME = 0x9001
    ATT_ATTACHRENDDATA = 0x9002
    ATT_MAPIPROPS = 0x9003
    ATT_RECIPTABLE = 0x9004
    ATT_ATTACHMENT = 0x9005
    ATT_ORIGINALMESSAGECLASS = 0x0006

    ID_NULL = 0
    ID_TNEFVERSION = TYPE_DWORD | ATT_TNEFVERSION
    ID_OEMCODEPAGE = TYPE_BYTE | ATT_OEMCODEPAGE
    ID_OWNER = TYPE_BYTE | ATT_OWNER
#   PR_RCVD_REPRESENTING_xxx  or PR_SENT_REPRESENTING_xxx */
    ID_SENTFOR = TYPE_BYTE | ATT_SENTFOR
#   PR_SENT_REPRESENTING_xxx */
    ID_DELEGATE = TYPE_BYTE | ATT_DELEGATE
#   PR_RCVD_REPRESENTING_xxx */
    ID_DATESTART = TYPE_DATE | ATT_DATESTART
#   PR_DATE_START */
    ID_DATEEND = TYPE_DATE | ATT_DATEEND
#   PR_DATE_END */
    ID_AIDOWNER = TYPE_LONG | ATT_AIDOWNER
#   PR_OWNER_APPT_ID */
    ID_REQUESTRES = TYPE_SHORT | ATT_REQUESTRES
#   PR_RESPONSE_REQUESTED */
    ID_FROM = TYPE_TRIPLES | ATT_FROM
#   PR_ORIGINATOR_RETURN_ADDRESS */
    ID_SUBJECT = TYPE_STRING | ATT_SUBJECT
#   PR_SUBJECT */
    ID_DATESENT = TYPE_DATE | ATT_DATESENT
#   PR_CLIENT_SUBMIT_TIME */
    ID_DATERECD = TYPE_DATE | ATT_DATERECD
#   PR_MESSAGE_DELIVERY_TIME */
    ID_MESSAGESTATUS = TYPE_BYTE | ATT_MESSAGESTATUS
#   PR_MESSAGE_FLAGS */
    ID_MESSAGECLASS = TYPE_WORD | ATT_MESSAGECLASS
#   PR_MESSAGE_CLASS */
    ID_MESSAGEID = TYPE_STRING | ATT_MESSAGEID
#   PR_MESSAGE_ID */
    ID_PARENTID = TYPE_STRING | ATT_PARENTID
#   PR_PARENT_ID */
    ID_CONVERSATIONID = TYPE_STRING | ATT_CONVERSATIONID
#   PR_CONVERSATION_ID */
    ID_BODY = TYPE_TEXT | ATT_BODY
#   PR_BODY */
    ID_PRIORITY = TYPE_SHORT | ATT_PRIORITY
#   PR_IMPORTANCE */
    ID_ATTACHDATA = TYPE_BYTE | ATT_ATTACHDATA
#   PR_ATTACH_DATA_xxx */
    ID_ATTACHTITLE = TYPE_STRING | ATT_ATTACHTITLE
#   PR_ATTACH_FILENAME */
    ID_ATTACHMETAFILE = TYPE_BYTE | ATT_ATTACHMETAFILE
#   PR_ATTACH_RENDERING */
    ID_ATTACHCREATEDATE = TYPE_DATE | ATT_ATTACHCREATEDATE
#   PR_CREATION_TIME */
    ID_ATTACHMODIFYDATE = TYPE_DATE | ATT_ATTACHMODIFYDATE
#   PR_LAST_MODIFICATION_TIME */
    ID_DATEMODIFIED = TYPE_DATE | ATT_DATEMODIFIED
#   PR_LAST_MODIFICATION_TIME */
    ID_ATTACHTRANSPORTFILENAME = TYPE_BYTE | ATT_ATTACHTRANSPORTFILENAME
#   PR_ATTACH_TRANSPORT_NAME */
    ID_ATTACHRENDDATA = TYPE_BYTE | ATT_ATTACHRENDDATA
    ID_MAPIPROPS = TYPE_BYTE | ATT_MAPIPROPS
    ID_RECIPTABLE = TYPE_BYTE | ATT_RECIPTABLE
#   PR_MESSAGE_RECIPIENTS */
    ID_ATTACHMENT = TYPE_BYTE | ATT_ATTACHMENT
    ID_ORIGINALMESSAGECLASS = TYPE_WORD | ATT_ORIGINALMESSAGECLASS
#   PR_ORIG_MESSAGE_CLASS */

    def name(self, vid):
        nm = self.getName(vid)
        if not nm:
            tid = self.getName(vid & 0xFFFF)
            tp = self.getName(vid & 0xFFFF0000)
            nm = tid if tid else "UNKNOWN"
            nm += ("(" + tp + ")") if tp else ""
        return nm
