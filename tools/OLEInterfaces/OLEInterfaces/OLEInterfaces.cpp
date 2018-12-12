// OLEInterfaces.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <string>
#include <map>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <set>

using namespace std;

#define NAME_SIZE 256
#define LOG_FILE  "current_clsid.log"

const set<string> skip = {
	"{1b7cd997-e5ff-4932-a7a6-2a9e636da385}", // failed with mmc not loaded 
#ifdef _WIN64

//"{0E94CA61-50B3-4ACD-8276-1A281F3357F3}", // Device Element Source View C:\Windows\System32\DeviceElementSource.dll call to some eip on CreateInstance
//"{208DD6A3-E12B-4755-9607-2E39EF84CFC5}", //	MSB1GEEN.DLL!00007ff8a6ca2744()	Reads 0xFFFFFFFFF on release
"{22AF56E3-F2E0-4A7E-AA0C-6B226EF5ABF8}", //hangs on release
"{50FDBB99-5C92-495E-9E81-E2C2F48CDDAE}", //Unhandled exception at 0x00007FF8C647BB2D (twinui.pcshell.dll) in OLEInterfaces64.exe: 0x80270233 (parameters: 0xFFFFFFFF80004005).
"{f580a09b-ea6e-4d83-9a03-add6cb756ab3}", //
"{CAFEEFAC-",
"{E19F9331-3110-11D4-991C-005004D3B3DB}",
"{8AD9C840-044E-11D1-B3E9-00805F499D93}",
#else //32bit excludes

#endif
};

#ifdef _WIN64
static string bits = "64";
#else
static string bits = "32";
#endif

static string cont = "";// "{e5b35059-a1be-4977-9bee-5c44226340f7}";

struct IFace {
	char name[NAME_SIZE];
	IID iid;
};

void s2iid(const char* s, IID* iid){
	auto unhex = [s](int ofs)->uint8_t {
		uint8_t res = 0;
		for (int i = 0; i < 2; i++) {
			char c = s[ofs+i];
			if (c >= 'a') c -= 'a' - 'A';
			uint8_t p = c >= 'A' ? (c - 'A' + 0x0A) : (c - '0');
			res <<= 4;
			res |= p & 0x0F;
		}
		return res;
	};
	int key[] = { 7,5,3,1, 12,10, 17,15, 20,22, 25,27,29,31,33,35 };
	uint8_t* p = (uint8_t*)iid;
	for (int i = 0; i < 16; i++) {
		*p++ = unhex(key[i]);
	}
}

int interfacesFromList(IFace** ifaces, map<string, bool> *search)
{
	int count = (int)search->size();
	IFace* arr = new IFace[count]();
	int i = 0;
	for (auto it : *search)
	{
		strcpy_s(arr[i].name, NAME_SIZE, it.first.c_str());
		s2iid(arr[i].name, &arr[i].iid);
		i++;
	}
	*ifaces = arr;
	return count;
}

int loadInterfaces(IFace** ifaces, bool ids) {
	HKEY k;
	DWORD count = 0, maxlen = 0;
	RegOpenKeyEx(HKEY_CLASSES_ROOT, _T("Interface"), 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &k);
	RegQueryInfoKey(k, NULL, NULL, NULL, &count, &maxlen, NULL, NULL, NULL, NULL, NULL, NULL);
	cerr << "Found " << count << " interfaces." << endl;
	IFace* arr = new IFace[count]();
	char buf[NAME_SIZE];
	LONG len;
	LONG res;
	for (DWORD i = 0; i < count; ++i) {
		if ((res = RegEnumKey(k, i, arr[i].name, NAME_SIZE)) != ERROR_SUCCESS) {
			cout << "Error: " << res << endl;
			continue;
		}
		s2iid(arr[i].name, &arr[i].iid);
		len = NAME_SIZE;
		if (!ids) {
			RegQueryValue(k, arr[i].name, buf, &len);
			if (len > 1) {
				strcpy_s(arr[i].name, NAME_SIZE, buf);
			}
		}
	}
	RegCloseKey(k);
	*ifaces = arr;
	return (int)count;
}

void checkInterfaces(string clsid, IFace* ifaces, int count) {
	if (skip.count(clsid) || skip.count(clsid.substr(0,10))) {
		cout << "\"EXCEPTION_"<< bits << "\"";
		cerr << "Skipped " << clsid << endl;
		return;
	}
	IUnknown* unk=nullptr;
	IClassFactory* fac=nullptr;
	CLSID cid;
	USES_CONVERSION;
	if (CLSIDFromString(A2COLE(clsid.c_str()), &cid) != S_OK) {
		cerr << "Can't convert clsid " << clsid << endl;
		return;
	}
	bool first = true;
	set<int> done;
	for (int i = 0; i < 2; i++) {
		string mode = i == 0 ? "A" : "M";
		CoInitializeEx(NULL, i==0 ? COINIT_APARTMENTTHREADED : COINIT_MULTITHREADED);
		try {
			if (!SUCCEEDED(CoGetClassObject(cid, CLSCTX_ALL, NULL, IID_IClassFactory, (LPVOID*)&fac)) || !fac) {
				cerr << "Factory not created: " << clsid << endl;
				CoUninitialize();
				continue;
			}
			if (!SUCCEEDED(fac->CreateInstance(NULL, IID_IUnknown, (LPVOID*)&unk)) || !unk) {
				cerr << "Instance not created " << clsid << endl;
				fac->Release();
				CoUninitialize();
				continue;
			}

			IUnknown* i2;
			for (int i = 0; i < count; i++) {
				if (done.count(i)) {
					continue;
				}
				if (unk->QueryInterface(ifaces[i].iid, (LPVOID*)&i2) == S_OK) {
					i2->Release();
					if (!first) {
						cout << ",";
					}
					else {
						first = false;
					}
					cout << "\"" << ifaces[i].name << "\"";
					done.insert(i);
				}
			}
			unk->Release();
			unk = NULL;
			fac->Release();
			fac = NULL;
		}
		catch (...) {
			if (!first) {
				cout << ",";
			}
			else {
				first = false;
			}
			cout << "\"EXCEPTION" << bits << mode << "\"";
			first = false;
			cerr << "Exception while processing " << clsid  << endl;
		}
		CoUninitialize();
	}

}

void marshalInterface(string fname, const IID &intf, IUnknown* obj, bool inproc = true, DWORD flags = MSHLFLAGS_NORMAL)
{
	HRESULT hr;
	CComBSTR s(fname.c_str());
	IStream* stm = nullptr;
	hr = SHCreateStreamOnFileEx(s, STGM_CREATE | STGM_WRITE | STGM_SHARE_DENY_NONE, 0, FALSE, NULL, &stm);
	if (!SUCCEEDED(hr))
	{
		cerr << "can't create file" << fname << endl;
		return;
	}
	hr = CoMarshalInterface(stm, intf, obj, inproc ? MSHCTX_INPROC : MSHCTX_LOCAL, NULL, flags);
	if (!SUCCEEDED(hr)) {
		cerr << "Error marshaling interface: " << hr << endl;
	}
	stm->Release();
}

void releaseInterface(string clsid, bool marshal){
	IUnknown* unk=nullptr;
	CLSID cid;
	USES_CONVERSION;
	if (CLSIDFromString(A2COLE(clsid.c_str()), &cid) != S_OK) {
		cerr << "Can't convert clsid " << clsid << endl;
		return;
	}
	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED(CoCreateInstance(cid, NULL, CLSCTX_ALL, IID_IUnknown, (LPVOID*)&unk)) && unk){
		if (marshal)
		{
			marshalInterface(clsid + ".bin", IID_IUnknown, unk);
		}
		unk->Release();
	}
	else {
		cerr << "Instance not created: " << clsid << endl;
	}
	CoUninitialize();
}


int main(int argc, char* argv[])
{
	HKEY k;
	map<string, bool> search;
	bool ids = false;
	bool release=false;
	bool marshal = false;
	bool icust = false;
	for (int i = 1; i < argc; i++) {
		string v = argv[i];
		std::transform(v.begin(), v.end(), v.begin(), ::tolower);
		if (v == "ids") {
			ids = true;
		}
		else if (v=="release")
		{
			release=true;
		}
		else if (v == "marshal")
		{
			marshal = true;
		}
		else if (v == "intf")
		{
			icust = true;
		}
		else {
			search[v] = false;
		}
	}
	int i = 0;
	char buf[1024];
	LONG len = 0;
	int printed = 0;
	IFace* ifaces = NULL;

	if (!release){
		ifstream f(LOG_FILE);
		if (f.is_open()) {
			f >> cont;
			f.close();
		}
	}

	int count=0;
	if (!release){
		if (icust)
		{
			count = interfacesFromList(&ifaces, &search);
			search.clear();
		}else {
			count = loadInterfaces(&ifaces, ids);
		}
	}
	cout << "{";
	RegOpenKey(HKEY_CLASSES_ROOT, _T("CLSID"), &k);
	while (RegEnumKey(k, i++, buf, 1024) == ERROR_SUCCESS) {
		string clsid = buf;
		if (!cont.empty() && cont != clsid) {
			continue;
		}
		cont="";
		if (clsid[0] != '{') {
			continue;
		}
		bool proc = true;
		if (search.size() > 0) {
			proc = false;
			string v = clsid;
			std::transform(v.begin(), v.end(), v.begin(), ::tolower);
			if (search.count(v)) {
				search[v] = true;
				proc = true;
			}
			if (!proc && RegQueryValue(k, clsid.c_str(), buf, &len) == ERROR_SUCCESS) {
				v = buf;
				std::transform(v.begin(), v.end(), v.begin(), ::tolower);
				if (search.count(v)) {
					search[v] = true;
					proc = true;
				}
			}
		}
		if (proc) {
			if (!release){
				ofstream f(LOG_FILE);
				f << clsid;
				f.flush();
				f.close();
			}
			if (printed) {
				cout << ",";
			}
			cout << endl;
			cout << "\"" << clsid << "\": [";
			if (release)
			{
				releaseInterface(clsid, marshal);
			}else{
				checkInterfaces(clsid, ifaces, count);
			}
			cout << "]";
			printed++;

		}
	}
	RegCloseKey(k);
	cout << endl << "}" << endl;
	if (ifaces){
		delete[] ifaces;
	}

	_unlink(LOG_FILE);

	for (auto it : search) {
		if (!it.second) {
			cerr << "CLSID not found: " << it.first << endl;
		}
	}
	return 0;
}

