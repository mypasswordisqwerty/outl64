// dllmain.cpp: реализация DllMain.

#include "stdafx.h"
#include "resource.h"
#include "Outl64FuzzLib_i.h"
#include "dllmain.h"
#include "compreg.h"


COutl64FuzzLibModule _AtlModule;

class COutl64FuzzLibApp : public CWinApp
{
public:

// Переопределение
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	DECLARE_MESSAGE_MAP()
};

BEGIN_MESSAGE_MAP(COutl64FuzzLibApp, CWinApp)
END_MESSAGE_MAP()

COutl64FuzzLibApp theApp;

BOOL COutl64FuzzLibApp::InitInstance()
{
	return CWinApp::InitInstance();
}

int COutl64FuzzLibApp::ExitInstance()
{
	return CWinApp::ExitInstance();
}
