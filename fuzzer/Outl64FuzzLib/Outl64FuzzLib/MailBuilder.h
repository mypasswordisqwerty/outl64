#pragma once

#include <map>
#include <vector>
#include "ILog.h"

using namespace std;

#define FROM_DEFAULT	_T("user1@example.com")
#define TO_DEFAULT		_T("user2@example.com")
#define SUBJECT_DEFAULT	_T("SomeSubject")
#define HDR_CONTENT_TYPE	_T("Content-Type")


#define DBG(...)	if(log) log->debug(__VA_ARGS__)

struct MailPart {
	map<CString, CString> headers;
	CString data;
	vector<MailPart> parts;
	bool multipart;
	CString boundary;
	static int partId;

	MailPart(bool multipart, CString contentType);
	MailPart(map<CString, CString> headers, CString data);
	void header(CString name, CString value) { headers[name] = value; }
	void setData(CString data) { this->data = data; }
	void addPart(MailPart part) { parts.push_back(part); }
	CString build();
};

class MailBuilder:public MailPart
{
public:
	MailBuilder(bool multipart=true, CString contentType=_T(""));
	~MailBuilder();

	CString base64(void* data, size_t sz);
	CString stream2base64(IStream* stream);

	IStream* buildStream(bool unicode=false);
	IStream* mailForCert(IStream* cert, bool unicode=false);

	void setLog(ILog* log) { this->log = log; }
private:
	ILog* log;
};

