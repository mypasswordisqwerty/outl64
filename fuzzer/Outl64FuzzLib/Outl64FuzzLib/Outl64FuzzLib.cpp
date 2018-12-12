// Outl64FuzzLib.cpp: реализация экспорта DLL.

//
// Примечание. Информация COM+ 1.0:
//      Для установки компонентов не забудьте запустить Microsoft Transaction Explorer.
//      Регистрация не выполняется по умолчанию. 

#include "stdafx.h"
#include "resource.h"
#include "Outl64FuzzLib_i.h"
#include "dllmain.h"
#include "compreg.h"


using namespace ATL;

// Используется, чтобы определить, можно ли выгрузить DLL средствами OLE.
STDAPI DllCanUnloadNow(void)
{
			AFX_MANAGE_STATE(AfxGetStaticModuleState());
	return (AfxDllCanUnloadNow()==S_OK && _AtlModule.GetLockCount()==0) ? S_OK : S_FALSE;
	}

// Возвращает фабрику класса для создания объекта требуемого типа.
_Check_return_
STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID* ppv)
{
		return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}

// DllRegisterServer - добавляет записи в системный реестр.
STDAPI DllRegisterServer(void)
{
	// регистрирует объект, библиотеку типов и все интерфейсы в библиотеке типов
	HRESULT hr = _AtlModule.DllRegisterServer();
		return hr;
}

// DllUnregisterServer - удаляет записи из системного реестра.
STDAPI DllUnregisterServer(void)
{
	HRESULT hr = _AtlModule.DllUnregisterServer();
		return hr;
}

// DllInstall - добавляет и удаляет записи системного реестра для конкретного пользователя и компьютера.
STDAPI DllInstall(BOOL bInstall, _In_opt_  LPCWSTR pszCmdLine)
{
	HRESULT hr = E_FAIL;
	static const wchar_t szUserSwitch[] = L"user";

	if (pszCmdLine != NULL)
	{
		if (_wcsnicmp(pszCmdLine, szUserSwitch, _countof(szUserSwitch)) == 0)
		{
			ATL::AtlSetPerUserRegistration(true);
		}
	}

	if (bInstall)
	{	
		hr = DllRegisterServer();
		if (FAILED(hr))
		{
			DllUnregisterServer();
		}
	}
	else
	{
		hr = DllUnregisterServer();
	}

	return hr;
}


