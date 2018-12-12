#include "stdafx.h"
#include "MailBuilder.h"
#include "Util.h"
int MailPart::partId = 0;


MailPart::MailPart(bool multipart, CString contentType):multipart(multipart) {
	this->multipart = multipart;
	boundary.Format(_T("bound_%d"), partId++);
	if (contentType.IsEmpty()) {
		if (multipart) {
			contentType = _T("multipart/mixed; boundary=\"");
			contentType.Append(boundary);
			contentType.Append(_T("\""));
		}
		else {
			contentType = _T("text/plain");
		}
	}
	if (multipart) {
		data = _T("This is a multipart message in MIME format.");
	}
	header(HDR_CONTENT_TYPE, contentType);
}

MailPart::MailPart(map<CString, CString> headers, CString data):multipart(false)
{
	this->headers = headers;
	this->data = data;
}

CString MailPart::build() {
	CString res;
	for (auto h : headers) {
		res.Append(h.first);
		res.Append(_T(": "));
		res.Append(h.second);
		res.Append(_T("\r\n"));
	}
	res.Append(_T("\r\n"));
	res.Append(data);
	res.Append(_T("\r\n\r\n"));
	if (!multipart) {
		return res;
	}
	for (auto p : parts) {
		res.Append(_T("--"));
		res.Append(boundary);
		res.Append(_T("\r\n"));
		res.Append(p.build());
	}

	if (multipart) {
		res.Append(_T("--"));
		res.Append(boundary);
		res.Append(_T("--\r\n"));
	}
	return res;
}


MailBuilder::MailBuilder(bool multipart,CString contentType):MailPart(multipart, contentType), log(nullptr)
{
	header(_T("From"), FROM_DEFAULT);
	header(_T("To"), TO_DEFAULT);
	header(_T("Subject"), SUBJECT_DEFAULT);
	header(_T("MIME-Version"), _T("1.0"));
}


MailBuilder::~MailBuilder()
{
}

CString MailBuilder::base64(void *data, size_t sz)
{
	DWORD len;
	CryptBinaryToString((const BYTE*)data, (DWORD)sz,CRYPT_STRING_BASE64,NULL, &len);
	CString res;
	CryptBinaryToString((const BYTE*)data, (DWORD)sz, CRYPT_STRING_BASE64, res.GetBufferSetLength(len), &len);
	res.ReleaseBufferSetLength(len);
	return res;
}

CString MailBuilder::stream2base64(IStream * stream)
{
	ULONG sz=Util::get().rewindStream(stream);
	char* data = new char[sz];
	stream->Read(data, sz, &sz);
	CString res = base64(data, sz);
	delete[] data;
	return res;
}

IStream* MailBuilder::buildStream(bool unicode) {
	CString data = build();
	DBG(_T("Mail is:\r\n%ls"), data.GetString());
	IStream* res;
	CreateStreamOnHGlobal(NULL, true, &res);
	if (res) {
		ULONG written;
		if (unicode) {
			CStringW sw(data);
			res->Write(sw.GetBuffer(), sw.GetLength(), &written);
		}
		else {
			CStringA sa(data);
			res->Write(sa.GetBuffer(), sa.GetLength(), &written);
		}
	}
	return res;
}

IStream * MailBuilder::mailForCert(IStream * cert, bool unicode)
{
	CString ct = _T("multipart/signed;\r\n\t");
	ct.Append(_T("protocol=\"application/x-pkcs7-signature\";\r\n\t"));
	ct.Append(_T("micalg=SHA1;\r\n\t"));
	ct.Append(_T("boundary=\""));
	ct.Append(boundary);
	ct.Append(_T("\""));
	header(HDR_CONTENT_TYPE, ct);
	map<CString, CString> p2h;
	p2h[HDR_CONTENT_TYPE] = _T("text/plain; charset = \"us-ascii\"");
	p2h[_T("Content-Transfer-Encoding")] = _T("7bit");
	addPart(MailPart(p2h, _T("SimpleMail")));
	p2h[HDR_CONTENT_TYPE] = _T("application/pkcs7-signature; name = \"smime.p7s\"");
	p2h[_T("Content-Transfer-Encoding")] = _T("base64");
	p2h[_T("Content-Disposition")] = _T("attachment; filename = \"smime.p7s\"");
	addPart(MailPart(p2h, stream2base64(cert)));
	return buildStream(unicode);
}

