#include "stdafx.h"
#include "Util.h"


#define _RELEASE(x) if (x) {x->Release(); x=nullptr;}

Util & Util::get()
{
	static Util _inst;
	return _inst;
}

HRESULT Util::initialize(ILog* log)
{
	if (log) {
		this->log = log;
	}
	if (sess) {
		refcnt++;
		return S_OK;
	}
	MAPIINIT_0 mi = { MAPI_INIT_VERSION, MAPI_MULTITHREAD_NOTIFICATIONS | 8 };
	HRESULT hr = MAPIInitialize(&mi);
	if (!SUCCEEDED(hr)) {
		return hr;
	}
	ULONG flgs = MAPI_USE_DEFAULT | MAPI_NEW_SESSION;
	hr = MAPILogonEx(NULL, NULL, NULL, flgs, &sess);
	if (!SUCCEEDED(hr)) {
		finalize();
		return hr;
	}
	hr = sess->OpenAddressBook(NULL, NULL, NULL, &abook);
	if (!SUCCEEDED(hr)) {
		finalize();
		return hr;
	}
	hr = openInbox();
	if (!SUCCEEDED(hr)) {
		finalize();
		return hr;
	}
	refcnt = 1;
	return S_OK;
}

ULONG Util::rewindStream(IStream * stream)
{
	ULARGE_INTEGER pos;
	LARGE_INTEGER p;
	memset(&p, 0, sizeof(p));
	stream->Seek(p, SEEK_END, &pos);
	LONG res = pos.LowPart;
	stream->Seek(p, SEEK_SET, &pos);
	return res;
}

HRESULT Util::openInbox() {
	if (inbox) {
		return S_OK;
	}
	LPMAPITABLE tbl = nullptr;
	LPSRowSet row = nullptr;
	HRESULT hr = sess->GetMsgStoresTable(0, &tbl);
	if (!SUCCEEDED(hr)) {
		return hr;
	}
	SPropTagArray propTag = { 1, PR_ENTRYID };
	SPropValue val; 
	val.ulPropTag = PR_DEFAULT_STORE; 
	val.Value.b = true;
	SRestriction sres; 
	sres.rt = RES_PROPERTY;
	sres.res.resProperty.relop = RELOP_EQ;
	sres.res.resProperty.ulPropTag = PR_DEFAULT_STORE;
	sres.res.resProperty.lpProp = &val;
	hr = HrQueryAllRows(tbl, &propTag, &sres, NULL, 0, &row);
	if (SUCCEEDED(hr) && row->cRows) {
		SBinary& bin = row->aRow[0].lpProps[0].Value.bin;
		hr = sess->OpenMsgStore(NULL, bin.cb, (LPENTRYID)bin.lpb, NULL, MDB_WRITE | MAPI_BEST_ACCESS | MDB_NO_DIALOG, &store);
	}
	if (store) {
		ULONG eid = 0;
		LPENTRYID pid = nullptr;
		hr = store->GetReceiveFolder(NULL, MAPI_UNICODE, &eid, &pid, NULL);
		if (SUCCEEDED(hr)) {
			hr = store->OpenEntry(eid, pid, NULL, MAPI_MODIFY, &eid, (LPUNKNOWN*)&inbox);
			MAPIFreeBuffer(pid);
		}
	}
	if (row) FreeProws(row);
	tbl->Release();
	return hr;
}

void Util::finalize()
{
	refcnt--;
	if (refcnt > 0)
		return;
	refcnt = 0;
	_RELEASE(inbox);
	_RELEASE(store);
	_RELEASE(abook);
	if (sess) {
		sess->Release();
		sess = nullptr;
		MAPIUninitialize();
	}
}

IMessage * Util::createMessage()
{
	if (!inbox) {
		return nullptr;
	}
	IMessage* msg = nullptr;
	HRESULT hr = inbox->CreateMessage(NULL, 0, &msg);
	if (!SUCCEEDED(hr)) {
		log->error(_T("Message not created: 0x%8.8X"), hr);
	}
	return msg;
}

FARPROC Util::getProc(CString libName, CString procName)
{
	HMODULE lib = getLibrary(libName);
	if (!lib) {
		return NULL;
	}
	CStringA procA(procName);
	FARPROC res=GetProcAddress(lib, procA.GetString());
	if (!res) {
		log->error(_T("Proc not found: %ls %ls"), libName.GetString(), procName.GetString());
	}
	return res;
}

CString& Util::getOfficePath()
{
	if (officePath.GetLength() > 0) {
		return officePath;
	}
	HKEY key = NULL;
	LSTATUS stat=RegOpenKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Office"), &key);
	if (stat != ERROR_SUCCESS) {
		return officePath;
	}
	wchar_t* nm[1024];
	int i = 0;
	while (RegEnumKey(key, i++, (LPWSTR)nm, 1024)==ERROR_SUCCESS) {
		wstring pth((wchar_t*)nm);
		pth += _T("\\Common\\InstallRoot");
		HKEY sub = NULL;
		stat = RegOpenKey(key, pth.c_str(), &sub);
		if (stat != ERROR_SUCCESS) {
			continue;
		}
		DWORD sz = 1024;
		stat=RegQueryValueEx(sub, _T("Path"), NULL, NULL, (LPBYTE)nm, &sz);
		if (stat == ERROR_SUCCESS) {
			officePath = (wchar_t*)nm;
			break;
		}
	}
	RegCloseKey(key);
	return officePath;
}

Util::Util(): refcnt(0), sess(nullptr), abook(nullptr), store(nullptr), inbox(nullptr)
{
}


Util::~Util()
{
	for (auto it : libs) {
		if (it.second) {
			FreeLibrary(it.second);
		}
	}
	libs.clear();
}

HMODULE Util::getLibrary(CString& libname)
{
	if (libs.count(libname)) {
		return libs[libname];
	}
	HMODULE lib=LoadLibrary(libname.GetString());
	if (!lib) {
		CString lpath = getOfficePath();
		lpath.Append(libname);
		lib = LoadLibrary(lpath.GetString());
		if (!lib) {
			log->error(_T("Library not found: %ls"), libname.GetString());
		}
	}
	libs[libname] = lib;
	return libs[libname];
}
