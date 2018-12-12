#pragma once
#include "ILog.h"
#include <string>
#include <map>
#include "mimeole.h"

using namespace std;

#define MIMELIB	_T("outlmime.dll")
//mime func types
typedef HRESULT (WINAPI *MimeOleCreateSecurityFunc)(IMimeSecurity **ppSecurity);
typedef HRESULT (WINAPI *MimeOleCreateMessageFunc)(IUnknown *pUnkOuter,IMimeMessage **ppMessage);


class Util
{
public:
	static Util& get();
	HRESULT initialize(ILog* log);
	void finalize();
	IMessage* createMessage();
	FARPROC getProc(CString libName, CString procName);
	CString& getOfficePath();
	MimeOleCreateSecurityFunc getMimeOleCreateSecurity() { return (MimeOleCreateSecurityFunc)getProc(MIMELIB, _T("MimeOleCreateSecurity")); }
	MimeOleCreateMessageFunc getMimeOleCreateMessage() { return (MimeOleCreateMessageFunc)getProc(MIMELIB, _T("MimeOleCreateMessage")); }
	//rewinds stream, returns stream size
	ULONG rewindStream(IStream* stream);

	IMAPISession* sess;
	IAddrBook* abook;
	IMsgStore* store;
	IMAPIFolder* inbox;
	HRESULT openInbox();
private:
	int refcnt;
	ILog* log=NULL;
	map<CString, HMODULE> libs;
	CString officePath;

	Util();
	~Util();
	Util(Util const&) = delete;
	Util& operator= (Util const&) = delete;
	HMODULE getLibrary(CString& libname);
};

