// mapidbg.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "mapidbg.h"
#include "Outl64FuzzLib_i.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

#define CHECKHR(err) (!SUCCEEDED(hr)) { wprintf(L"Error "##err##": %X\n",hr); return hr;} else

CWinApp theApp;

struct SPropValueArray {
	ULONG cValues;
	SPropValue values[1];
};
typedef int(*proc)(vector<wstring>&);
IMapiFuzz* mapi = NULL;



int parseTnef(vector<wstring> &params) {
	_variant_t fname(params[2].c_str());
	ULONG mock = 0;
	if (params.size() > 3 && params[3] == L"mock") {
		mock = 1;
	}
	HRESULT hr = mapi->parseTnef(fname, mock, NULL);
	if CHECKHR("parsing tnef") {
		wprintf(L"OK");
		return 0;
	}
}

int messageProp(vector<wstring> &params) {
	_variant_t fname(params[2].c_str());
	HRESULT hr = mapi->createMessage(fname, NULL);
	if CHECKHR("setting message props") {
		wprintf(L"OK");
		return 0;
	}
}

int buildPropVal(vector<wstring> &params) {
	SPropValueArray arr;
	memset(&arr, 0, sizeof(SPropValueArray));
	arr.cValues = 1;
	arr.values[0].ulPropTag = PR_TRANSPORT_STATUS;
	arr.values[0].Value.l = 0x666;
	FILE* f = NULL;
	_wfopen_s(&f, params[2].c_str(), L"wb");
	if (!f) {
		wprintf(L"Cannot create file %ls\n", params[2].c_str());
		return 1;
	}
	fwrite(&arr, sizeof(SPropValueArray), 1, f);
	fclose(f);
	return 0;
}

int parseCert(vector<wstring> &params) {
	_variant_t fname(params[2].c_str());
	HRESULT hr = mapi->parseCert(fname,NULL);
	if CHECKHR("parsing cert") {
		wprintf(L"OK");
		return 0;
	}
}

int crash(vector<wstring> &params) {
	mapi->crash(0);
	return 0;
}

int test(vector<wstring> &params) {
	int i = 0;
	_variant_t fname(params[2].c_str());
	while (i < 0x80FF) {
		i++;
		if (i % 1000 == 0) {
			wprintf(L"Step %d\n", i);
		}
		mapi->parseTnef(fname, 0, NULL);
	}
	return 0;
}

map<wstring, proc> commands = {
	{ L"parseTnef", &parseTnef },
	{ L"msgProp", &messageProp },
	{ L"buildPropVal", &buildPropVal },
	{ L"parseCert", &parseCert },
	{ L"crash", &crash },
	{ L"test", &test },
};


int wmain(int argc, wchar_t** argv)
{
    int nRetCode = 0;
	if (argc < 2) {
		wprintf(L"Usage: mapidbg file.tnef");
		return 0;
	}

	_set_se_translator([](unsigned int u, EXCEPTION_POINTERS *pExp) {
		std::string error = "SE Exception: ";
		switch (u) {
		case 0xC0000005:
			error += "Access Violation";
			break;
		default:
			char result[11];
			sprintf_s(result, 11, "0x%08X", u);
			error += result;
		};
		throw std::exception(error.c_str());
	});

    HMODULE hModule = ::GetModuleHandle(nullptr);

    if (hModule != nullptr)
    {
        // initialize MFC and print and error on failure
        if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
        {
            wprintf(L"Fatal Error: MFC initialization failed\n");
            nRetCode = 1;
        }
        else
        {
			CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
			HRESULT hr = CoCreateInstance(CLSID_MapiFuzz, NULL, CLSCTX_INPROC_SERVER, IID_IMapiFuzz, (void**)&mapi);
			mapi->config(0);
			if CHECKHR("creating instance") {
				vector<wstring> params;
				for (int i = 0; i < argc; i++) {
					params.push_back(argv[i]);
				}
				if (!commands.count(params[1])) {
					nRetCode = -1;
					wprintf(L"Unknown command %ls\n", params[1].c_str());
				}else {
					try {
						nRetCode = commands[params[1]](params);
					}
					catch (exception &e) {
						wprintf(L"Exception caught: %hs\n", e.what());
					}
					catch (...) {
						wprintf(L"Unhandled exception caught\n");
					}
				}
				mapi->Release();
			}
			CoUninitialize();
        }
    }
    else
    {
        // TODO: change error code to suit your needs
        wprintf(L"Fatal Error: GetModuleHandle failed\n");
        nRetCode = 1;
    }

    return nRetCode;
}
